//! E2E integration tests for SMTP Sieve routing with the native Sieve engine.
//! Bead: stoa-n3vt.7
//!
//! External oracles:
//!   - RFC 5228 §2.10.2: implicit keep when no action is taken.
//!   - RFC 5228 §4.1: fileinto action delivers to named folder.
//!   - RFC 5228 §4.2: reject action causes 550 response.
//!   - RFC 5228 §2.2: discard action silently drops the message.
//!   - RFC 5229 §3: variables extension; set + expansion via ${name}.
//!
//! Each test stores a known Sieve script in an in-memory SQLite database,
//! drives an SMTP session through `run_session`, and inspects either the
//! NNTP queue directory (for newsgroup routing) or the mailbox_messages
//! table (for INBOX/folder delivery) to verify the outcome.
//!
//! THESE TESTS MUST NOT BE MODIFIED TO MAKE THEM PASS. Fix the
//! implementation.

use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use stoa_auth::{AuthConfig, CredentialStore};
use stoa_smtp::{
    config::{
        Config, DatabaseConfig, DnsResolver, LimitsConfig, ListenConfig, LogConfig, LogFormat,
        ReaderConfig, SieveAdminConfig, TlsConfig,
    },
    queue::NntpQueue,
    session::run_session,
    store,
};

// ─── Test infrastructure ──────────────────────────────────────────────────────

/// Build a `Config` with one local user: alice / alice@example.com.
fn test_config() -> Arc<Config> {
    Arc::new(Config {
        hostname: "test.example.com".to_string(),
        listen: ListenConfig {
            port_25: "127.0.0.1:0".to_string(),
            port_587: "127.0.0.1:0".to_string(),
            smtps_addr: None,
        },
        tls: TlsConfig {
            cert_path: None,
            key_path: None,
        },
        limits: LimitsConfig {
            max_message_bytes: 1_048_576,
            max_recipients: 10,
            command_timeout_secs: 300,
            max_connections: 10,
            sieve_eval_timeout_ms: 5_000,
        },
        log: LogConfig {
            level: "error".to_string(),
            format: LogFormat::Text,
        },
        reader: ReaderConfig::default(),
        delivery: stoa_smtp::config::DeliveryConfig::default(),
        database: DatabaseConfig::default(),
        sieve_admin: SieveAdminConfig::default(),
        dns_resolver: DnsResolver::System,
        auth: AuthConfig::default(),
        peer_whitelist: vec![],
        mta_sts: Default::default(),
    })
}

/// Open an in-memory SQLite database with the smtp schema applied.
async fn open_test_db() -> SqlitePool {
    store::open(":memory:").await.expect("open in-memory DB")
}

/// Count `.msg` files in a queue directory.
fn count_queued(dir: &tempfile::TempDir) -> usize {
    std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
        .count()
}

/// Count mailbox messages using a direct sqlx query.
///
/// Integration tests cannot call the `#[cfg(test)]`-gated helpers in
/// `store.rs` (those are compiled only into the lib's own unit test binary),
/// so we query the pool directly here.
async fn count_mailbox(pool: &SqlitePool, username: &str, mailbox: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mailbox_messages WHERE username = ? AND mailbox = ?",
    )
    .bind(username)
    .bind(mailbox)
    .fetch_one(pool)
    .await
    .expect("count_mailbox query")
}

/// The full SMTP exchange that delivers a message to alice@example.com.
/// Subject is set to "Test" — used as-is for most tests.
const FULL_MSG: &[u8] = b"EHLO client.example.com\r\n\
    MAIL FROM:<sender@example.com>\r\n\
    RCPT TO:<alice@example.com>\r\n\
    DATA\r\n\
    From: sender@example.com\r\n\
    To: alice@example.com\r\n\
    Subject: Test\r\n\
    \r\n\
    Body text.\r\n\
    .\r\n\
    QUIT\r\n";

/// SMTP exchange with Subject: "rust" — used for the conditional routing test.
const RUST_MSG: &[u8] = b"EHLO client.example.com\r\n\
    MAIL FROM:<sender@example.com>\r\n\
    RCPT TO:<alice@example.com>\r\n\
    DATA\r\n\
    From: sender@example.com\r\n\
    To: alice@example.com\r\n\
    Subject: rust\r\n\
    \r\n\
    Body text.\r\n\
    .\r\n\
    QUIT\r\n";

/// Drive one SMTP session with the given `config`, optional database `pool`,
/// and `client_script` bytes.
///
/// Returns `(server_response, nntp_queue_dir)`.  The `TempDir` must stay
/// alive until the caller has finished inspecting queue files.
async fn drive(
    config: Arc<Config>,
    pool: Option<SqlitePool>,
    client_script: &[u8],
) -> (String, tempfile::TempDir) {
    let queue_dir = tempfile::tempdir().expect("tempdir");
    let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
    let cred_store = Arc::new(CredentialStore::empty());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let config2 = Arc::clone(&config);
    let queue2 = Arc::clone(&nntp_queue);
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session(
            stream,
            false,
            false,
            peer.to_string(),
            config2,
            cred_store,
            queue2,
            None,
            std::sync::Arc::new(stoa_smtp::dns_cache::DnsCache::new()),
            pool,
            None,
            None,
            None,
        )
        .await;
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    client.write_all(client_script).await.expect("write");
    client.shutdown().await.expect("shutdown");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    server_task.await.expect("server task");

    (response, queue_dir)
}

// ─── Test 1: fileinto "newsgroup:comp.test" → article enqueued ───────────────

/// RFC 5228 §4.1: fileinto with the `newsgroup:` prefix routes the message
/// to the NNTP injection queue rather than a mailbox folder.
///
/// Oracle: queue directory gains exactly one `.msg` file; the file contains
/// a `Newsgroups: comp.test` header; nothing is stored in alice's INBOX.
#[tokio::test]
async fn fileinto_newsgroup() {
    let pool = open_test_db().await;
    store::save_script(
        &pool,
        "_global",
        "default",
        br#"require ["fileinto"]; fileinto "newsgroup:comp.test";"#,
        true,
    )
    .await
    .expect("save script");

    let (response, queue_dir) = drive(test_config(), Some(pool.clone()), FULL_MSG).await;

    assert!(
        response.contains("250 OK"),
        "expected 250 OK after DATA, got:\n{response}"
    );
    assert_eq!(
        count_queued(&queue_dir),
        1,
        "expected exactly 1 article in NNTP queue"
    );

    let msg_files: Vec<_> = std::fs::read_dir(queue_dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
        .collect();
    let bytes = std::fs::read(msg_files[0].path()).expect("read queue file");
    let text = std::str::from_utf8(&bytes).expect("valid UTF-8");
    assert!(
        text.contains("Newsgroups: comp.test"),
        "queued article must contain 'Newsgroups: comp.test'; got:\n{text}"
    );

    let inbox_count = count_mailbox(&pool, "_global", "INBOX").await;
    assert_eq!(inbox_count, 0, "newsgroup fileinto must not store in INBOX");
}

// ─── Test 2: reject "policy" → 550 response ──────────────────────────────────

/// RFC 5228 §4.2: reject causes the SMTP DATA response to be 550.
///
/// Oracle: server response contains "550"; nothing is stored in INBOX;
/// nothing is queued.
#[tokio::test]
async fn reject_returns_550() {
    let pool = open_test_db().await;
    store::save_script(
        &pool,
        "_global",
        "default",
        br#"require ["reject"]; reject "policy";"#,
        true,
    )
    .await
    .expect("save script");

    let (response, queue_dir) = drive(test_config(), Some(pool.clone()), FULL_MSG).await;

    assert!(
        response.contains("550"),
        "reject action must produce 550 response; got:\n{response}"
    );
    assert_eq!(
        count_queued(&queue_dir),
        0,
        "rejected message must not appear in NNTP queue"
    );
    let inbox_count = count_mailbox(&pool, "_global", "INBOX").await;
    assert_eq!(inbox_count, 0, "rejected message must not appear in INBOX");
}

// ─── Test 3: discard → 250 OK; nothing stored ────────────────────────────────

/// RFC 5228 §2.2: discard silently drops the message.  The SMTP layer still
/// returns 250 OK (the message was accepted at the protocol level), but
/// nothing is stored anywhere.
///
/// Oracle: response contains "250 OK"; 0 in queue; 0 in INBOX.
#[tokio::test]
async fn discard_returns_250_nothing_stored() {
    let pool = open_test_db().await;
    store::save_script(&pool, "_global", "default", b"discard;", true)
        .await
        .expect("save script");

    let (response, queue_dir) = drive(test_config(), Some(pool.clone()), FULL_MSG).await;

    assert!(
        response.contains("250 OK"),
        "discard must still return 250 OK; got:\n{response}"
    );
    assert_eq!(
        count_queued(&queue_dir),
        0,
        "discarded message must not appear in NNTP queue"
    );
    let inbox_count = count_mailbox(&pool, "_global", "INBOX").await;
    assert_eq!(inbox_count, 0, "discarded message must not appear in INBOX");
}

// ─── Test 4: header conditional — subject "rust" → newsgroup ─────────────────

/// RFC 5228 §5.7.1 (header test): a script that tests the Subject header
/// routes matching messages to a newsgroup and non-matching ones to INBOX.
///
/// Two sessions are driven:
///   - Subject "rust" → fileinto "newsgroup:comp.lang.rust" → 1 .msg queued
///   - Subject "Test" → implicit keep (no condition matches) → 1 INBOX row
#[tokio::test]
async fn header_conditional_routing() {
    let script = br#"require ["fileinto"];
if header :contains "Subject" "rust" {
    fileinto "newsgroup:comp.lang.rust";
}"#;

    // Session 1: subject "rust" → should go to newsgroup queue.
    let pool1 = open_test_db().await;
    store::save_script(&pool1, "_global", "default", script, true)
        .await
        .expect("save script");

    let (resp1, queue_dir1) = drive(test_config(), Some(pool1.clone()), RUST_MSG).await;
    assert!(
        resp1.contains("250 OK"),
        "expected 250 OK for rust subject; got:\n{resp1}"
    );
    assert_eq!(
        count_queued(&queue_dir1),
        1,
        "subject 'rust' must route to newsgroup queue"
    );
    let inbox1 = count_mailbox(&pool1, "_global", "INBOX").await;
    assert_eq!(inbox1, 0, "rust-subject message must not land in INBOX");

    // Session 2: subject "Test" → no match → implicit keep → INBOX.
    let pool2 = open_test_db().await;
    store::save_script(&pool2, "_global", "default", script, true)
        .await
        .expect("save script");

    let (resp2, queue_dir2) = drive(test_config(), Some(pool2.clone()), FULL_MSG).await;
    assert!(
        resp2.contains("250 OK"),
        "expected 250 OK for non-matching subject; got:\n{resp2}"
    );
    assert_eq!(
        count_queued(&queue_dir2),
        0,
        "non-matching subject must not route to newsgroup queue"
    );
    let inbox2 = count_mailbox(&pool2, "_global", "INBOX").await;
    assert_eq!(inbox2, 1, "non-matching subject must land in INBOX");
}

// ─── Test 5: variables extension — set + fileinto with expansion ──────────────

/// RFC 5229 §3: the variables extension allows `set` to define a variable
/// and `${name}` to expand it inside string arguments.
///
/// Script sets "ng" to "newsgroup:comp.test" then calls fileinto "${ng}".
/// Oracle: 1 .msg in queue containing "Newsgroups: comp.test".
#[tokio::test]
async fn variables_set_fileinto() {
    let pool = open_test_db().await;
    store::save_script(
        &pool,
        "_global",
        "default",
        br#"require ["variables", "fileinto"];
set "ng" "newsgroup:comp.test";
fileinto "${ng}";"#,
        true,
    )
    .await
    .expect("save script");

    let (response, queue_dir) = drive(test_config(), Some(pool.clone()), FULL_MSG).await;

    assert!(
        response.contains("250 OK"),
        "expected 250 OK; got:\n{response}"
    );
    assert_eq!(
        count_queued(&queue_dir),
        1,
        "variables fileinto must route to newsgroup queue"
    );

    let msg_files: Vec<_> = std::fs::read_dir(queue_dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
        .collect();
    let bytes = std::fs::read(msg_files[0].path()).expect("read queue file");
    let text = std::str::from_utf8(&bytes).expect("valid UTF-8");
    assert!(
        text.contains("Newsgroups: comp.test"),
        "queued article must contain 'Newsgroups: comp.test'; got:\n{text}"
    );

    let inbox_count = count_mailbox(&pool, "_global", "INBOX").await;
    assert_eq!(inbox_count, 0, "variables fileinto must not store in INBOX");
}

// ─── Test 6: no script → implicit keep → INBOX ───────────────────────────────

/// RFC 5228 §2.10.2: when no active script exists for a user, the implicit
/// default action is Keep — the message is delivered to INBOX.
///
/// Oracle: no script stored for alice; message arrives in alice's INBOX;
/// nothing in queue.
#[tokio::test]
async fn implicit_keep_no_script() {
    let pool = open_test_db().await;
    // Deliberately do NOT save any script for alice.

    let (response, queue_dir) = drive(test_config(), Some(pool.clone()), FULL_MSG).await;

    assert!(
        response.contains("250 OK"),
        "expected 250 OK when no script; got:\n{response}"
    );
    assert_eq!(
        count_queued(&queue_dir),
        0,
        "implicit keep must not route to newsgroup queue"
    );
    let inbox_count = count_mailbox(&pool, "_global", "INBOX").await;
    assert_eq!(inbox_count, 1, "implicit keep must deliver to INBOX");
}
