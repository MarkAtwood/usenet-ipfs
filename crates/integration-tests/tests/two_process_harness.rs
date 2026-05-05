//! Two-process integration harness: transit + reader sharing IPFS and MsgIdMap.
//!
//! Scenario:
//! 1. POST an article through the reader.
//! 2. Verify it appears via GROUP, OVER, and ARTICLE on the reader.
//! 3. Send IHAVE to the transit with the same Message-ID.
//! 4. Verify transit returns 435 Duplicate — proving shared MsgIdMap.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use stoa_auth::CredentialStore;
use stoa_core::{hlc::HlcClock, msgid_map::MsgIdMap};
use stoa_reader::{
    auth_limiter::{AuthFailureTracker, DEFAULT_MAX_ENTRIES},
    post::ipfs_write::{IpfsBlockStore, IpfsWriteError},
    session::lifecycle::{run_session, ListenerKind},
    store::{
        article_numbers::ArticleNumberStore, overview::OverviewStore, server_stores::ServerStores,
    },
};
use stoa_transit::peering::{
    blacklist::BlacklistConfig,
    ingestion_queue::ingestion_queue,
    pipeline::{run_pipeline, IpfsError, IpfsStore, PipelineCtx},
    rate_limit::{ExhaustionAction, PeerRateLimiter},
    session::{run_peering_session, PeeringShared},
};

// ── Shared IPFS adapter ───────────────────────────────────────────────────────

/// In-memory IPFS store shared between transit and reader.
///
/// Stores blocks keyed by CID bytes. Implements both the transit `IpfsStore`
/// and the reader `IpfsBlockStore` traits, backed by the same HashMap.
struct SharedIpfs {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl SharedIpfs {
    fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl IpfsStore for SharedIpfs {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        Ok(self.blocks.read().await.get(&cid.to_bytes()).cloned())
    }
}

#[async_trait]
impl IpfsBlockStore for SharedIpfs {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.blocks.write().await.insert(cid.to_bytes(), data);
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.blocks
            .read()
            .await
            .get(&cid.to_bytes())
            .cloned()
            .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
    }
}

// ── Pool helpers ──────────────────────────────────────────────────────────────
//
// Tests use on-disk SQLite backed by a tempdir so they exercise the same
// code path as production deployments (disk + WAL mode).

async fn make_core_pool(dir: &tempfile::TempDir) -> sqlx::AnyPool {
    let path = dir.path().join("core.db");
    let url = format!("sqlite://{}", path.display());
    stoa_core::migrations::run_migrations(&url)
        .await
        .expect("core migrations");
    stoa_core::db_pool::try_open_any_pool(&url, 4)
        .await
        .expect("core pool")
}

async fn make_reader_pool(dir: &tempfile::TempDir) -> sqlx::AnyPool {
    let path = dir.path().join("reader.db");
    let url = format!("sqlite://{}", path.display());
    stoa_reader::migrations::run_migrations(&url)
        .await
        .expect("reader migrations");
    stoa_core::db_pool::try_open_any_pool(&url, 4)
        .await
        .expect("reader pool")
}

async fn make_verify_pool(dir: &tempfile::TempDir) -> sqlx::AnyPool {
    let path = dir.path().join("verify.db");
    let url = format!("sqlite://{}", path.display());
    stoa_verify::run_migrations(&url)
        .await
        .expect("verify migrations");
    stoa_core::db_pool::try_open_any_pool(&url, 4)
        .await
        .expect("verify pool")
}

/// Core-schema pool for transit's MsgIdMap and SqliteLogStorage.
///
/// Transit uses a separate core pool because sqlx validates that every
/// previously-applied migration version is still present in the migrator;
/// mixing core and transit migrations in one pool would cause VersionMissing.
async fn make_transit_core_pool(dir: &tempfile::TempDir) -> sqlx::AnyPool {
    let path = dir.path().join("transit_core.db");
    let url = format!("sqlite://{}", path.display());
    stoa_core::migrations::run_migrations(&url)
        .await
        .expect("transit core migrations");
    stoa_core::db_pool::try_open_any_pool(&url, 4)
        .await
        .expect("transit core pool")
}

async fn make_transit_db_pool(dir: &tempfile::TempDir) -> sqlx::AnyPool {
    let path = dir.path().join("transit.db");
    let url = format!("sqlite://{}", path.display());
    stoa_transit::migrations::run_migrations(&url)
        .await
        .expect("transit db migrations");
    stoa_core::db_pool::try_open_any_pool(&url, 4)
        .await
        .expect("transit db pool")
}

// ── Test config ───────────────────────────────────────────────────────────────

fn reader_test_config(addr: &str) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("minimal reader config must parse")
}

// ── Helpers for sending NNTP commands ────────────────────────────────────────

async fn read_line(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line.trim_end_matches(['\r', '\n']).to_string()
}

async fn send_cmd(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    command: &str,
) -> String {
    writer
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .unwrap();
    read_line(reader).await
}

async fn read_dot_body(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            break;
        }
        lines.push(trimmed.to_string());
    }
    lines
}

// ── Article fixture ───────────────────────────────────────────────────────────

fn test_article(newsgroup: &str, subject: &str, msgid: &str) -> String {
    let date = common::now_rfc2822();
    format!(
        "Newsgroups: {newsgroup}\r\n\
         From: integ@test.example\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         Message-ID: {msgid}\r\n\
         \r\n\
         Integration test body.\r\n"
    )
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn transit_reader_shared_store() {
    // ── Shared storage layer ──────────────────────────────────────────────────

    let shared_ipfs = Arc::new(SharedIpfs::new());
    let db_dir = tempfile::TempDir::new().expect("tempdir");
    let core_pool = make_core_pool(&db_dir).await;
    let log_pool = core_pool.clone();
    let msgid_map = Arc::new(MsgIdMap::new(core_pool));

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // ── Reader stores ─────────────────────────────────────────────────────────

    let reader_pool = make_reader_pool(&db_dir).await;
    let stores = Arc::new(ServerStores {
        ipfs_store: Arc::clone(&shared_ipfs) as Arc<dyn IpfsBlockStore>,
        msgid_map: Arc::clone(&msgid_map),
        log_storage: Arc::new(stoa_core::group_log::SqliteLogStorage::new(log_pool)),
        article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
        overview_store: Arc::new(OverviewStore::new(reader_pool)),
        credential_store: Arc::new(CredentialStore::empty()),
        client_cert_store: Arc::new(stoa_auth::ClientCertStore::empty()),
        trusted_issuer_store: Arc::new(stoa_auth::TrustedIssuerStore::empty()),
        clock: Arc::new(Mutex::new(HlcClock::new([0x01u8; 8], now_ms))),
        signing_key: Arc::new(stoa_core::signing::SigningKey::from_bytes(&[0x42u8; 32])),
        search_index: None,
        smtp_relay_queue: None,
        verification_store: Arc::new(stoa_verify::VerificationStore::new(
            make_verify_pool(&db_dir).await,
        )),
        dkim_authenticator: Arc::new(
            mail_auth::MessageAuthenticator::new_cloudflare_tls().unwrap(),
        ),
        path_hostname: "localhost".to_string(),
        audit_logger: None,
        auth_failure_tracker: Arc::new(tokio::sync::Mutex::new(AuthFailureTracker::new(
            10,
            std::time::Duration::from_secs(60),
            DEFAULT_MAX_ENTRIES,
        ))),
        oidc_store: None,
        mail_complaints_to: None,
        max_clock_skew_secs: None,
        staging_pool: None,
    });

    // ── Transit stores ────────────────────────────────────────────────────────

    let transit_core_pool = make_transit_core_pool(&db_dir).await;
    let transit_log_storage = Arc::new(stoa_core::group_log::SqliteLogStorage::new(
        transit_core_pool,
    ));
    let transit_signing_key = Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32]));
    let transit_hlc = Arc::new(Mutex::new(HlcClock::new([0x02u8; 8], now_ms)));

    let (ingestion_sender, mut ingestion_receiver) = ingestion_queue(64, u64::MAX);
    let ingestion_sender = Arc::new(ingestion_sender);

    let transit_db_pool = Arc::new(make_transit_db_pool(&db_dir).await);

    let transit_shared = Arc::new(PeeringShared {
        ipfs: Arc::clone(&shared_ipfs) as Arc<dyn IpfsStore>,
        msgid_map: Arc::clone(&msgid_map),
        signing_key: Arc::clone(&transit_signing_key),
        hlc: Arc::clone(&transit_hlc),
        ingestion_sender: Arc::clone(&ingestion_sender),
        local_hostname: "integ-test.local".to_string(),
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            100.0,
            200,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::clone(&transit_db_pool),
        blacklist_config: BlacklistConfig::default(),
        trusted_keys: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        tls_acceptor: None,
        staging: None,
        verification_store: None,
        dkim_authenticator: None,
    });

    // ── Pipeline drain task ───────────────────────────────────────────────────

    {
        let ipfs = Arc::clone(&shared_ipfs) as Arc<dyn IpfsStore>;
        let msgid_drain = Arc::clone(&msgid_map);
        let log_drain = Arc::clone(&transit_log_storage);
        let key_drain: Arc<ed25519_dalek::SigningKey> = Arc::clone(&transit_signing_key);
        let hlc_drain = Arc::clone(&transit_hlc);
        let transit_db_pool = Arc::clone(&transit_db_pool);

        tokio::spawn(async move {
            while let Some(article) = ingestion_receiver.recv().await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let ts = hlc_drain.lock().await.send(now);
                let ctx = PipelineCtx {
                    timestamp: ts,
                    operator_signing_key: Arc::clone(&key_drain),
                    local_hostname: "integ-test.local",
                    verify_store: None,
                    trusted_keys: std::sync::Arc::from(vec![]),
                    dkim_auth: None,
                    group_filter: None,
                };
                let _ = run_pipeline(
                    &article.bytes,
                    &*ipfs,
                    &msgid_drain,
                    &*log_drain,
                    &transit_db_pool,
                    ctx,
                )
                .await;
            }
        });
    }

    // ── Start reader listener ─────────────────────────────────────────────────

    let reader_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reader_addr = reader_listener.local_addr().unwrap();
    let reader_config = Arc::new(reader_test_config(&reader_addr.to_string()));

    {
        let stores = Arc::clone(&stores);
        let config = Arc::clone(&reader_config);
        tokio::spawn(async move {
            loop {
                let (stream, _) = reader_listener.accept().await.unwrap();
                let s = Arc::clone(&stores);
                let c = Arc::clone(&config);
                tokio::spawn(
                    async move { run_session(stream, ListenerKind::Plain, &c, s, None).await },
                );
            }
        });
    }

    // ── Start transit listener ────────────────────────────────────────────────

    let transit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transit_addr = transit_listener.local_addr().unwrap();

    {
        let shared = Arc::clone(&transit_shared);
        tokio::spawn(async move {
            loop {
                let (stream, addr) = transit_listener.accept().await.unwrap();
                let s = Arc::clone(&shared);
                tokio::spawn(async move {
                    run_peering_session(stream, addr.to_string(), addr.ip(), s).await;
                });
            }
        });
    }

    // ── Part 1: POST via reader, verify GROUP/OVER/ARTICLE ───────────────────

    let msgid = "<integ@test.example>";
    let stream = TcpStream::connect(reader_addr).await.unwrap();
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await;
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );

    let post_start = send_cmd(&mut write_half, &mut reader, "POST").await;
    assert!(
        post_start.starts_with("340"),
        "expected 340 after POST, got: {post_start}"
    );

    let body = test_article("comp.test", "Integ Subject", msgid);
    write_half.write_all(body.as_bytes()).await.unwrap();
    write_half.write_all(b".\r\n").await.unwrap();

    let mut post_result = String::new();
    reader.read_line(&mut post_result).await.unwrap();
    assert!(
        post_result.starts_with("240"),
        "expected 240 after article body, got: {post_result}"
    );

    let group_resp = send_cmd(&mut write_half, &mut reader, "GROUP comp.test").await;
    assert!(
        group_resp.starts_with("211"),
        "expected 211, got: {group_resp}"
    );
    let parts: Vec<&str> = group_resp.split_whitespace().collect();
    assert_eq!(parts[1], "1", "GROUP count must be 1");

    let over_resp = send_cmd(&mut write_half, &mut reader, "OVER 1").await;
    assert!(
        over_resp.starts_with("224"),
        "expected 224, got: {over_resp}"
    );
    let over_lines = read_dot_body(&mut reader).await;
    assert_eq!(over_lines.len(), 1, "OVER must return exactly one record");
    assert!(
        over_lines[0].contains("Integ Subject"),
        "OVER must include subject; got: {}",
        over_lines[0]
    );

    let article_resp = send_cmd(&mut write_half, &mut reader, &format!("ARTICLE {msgid}")).await;
    assert!(
        article_resp.starts_with("220"),
        "expected 220, got: {article_resp}"
    );
    let article_lines = read_dot_body(&mut reader).await;
    assert!(
        article_lines.iter().any(|l| l.contains("Integ Subject")),
        "ARTICLE must include Subject header"
    );
    assert!(
        article_lines
            .iter()
            .any(|l| l.contains("Integration test body")),
        "ARTICLE must include body text"
    );

    let quit = send_cmd(&mut write_half, &mut reader, "QUIT").await;
    assert!(quit.starts_with("205"), "expected 205, got: {quit}");

    // ── Part 2: IHAVE to transit with same msgid → must be rejected as duplicate ─

    let t_stream = TcpStream::connect(transit_addr).await.unwrap();
    let (t_read_half, mut t_write) = tokio::io::split(t_stream);
    let mut t_reader = BufReader::new(t_read_half);

    let t_greeting = read_line(&mut t_reader).await;
    assert!(
        t_greeting.starts_with("200"),
        "transit: expected 200 greeting, got: {t_greeting}"
    );

    let ihave_resp = send_cmd(&mut t_write, &mut t_reader, &format!("IHAVE {msgid}")).await;
    assert!(
        ihave_resp.starts_with("435"),
        "transit IHAVE must return 435 Duplicate (proves shared msgid_map); got: {ihave_resp}"
    );

    let t_quit = send_cmd(&mut t_write, &mut t_reader, "QUIT").await;
    assert!(
        t_quit.starts_with("205"),
        "transit: expected 205, got: {t_quit}"
    );
}
