//! RFC 8621 §2 cross-account authorization tests.
//!
//! The JMAP spec requires that every method call carrying an `accountId` that
//! does not belong to the authenticated principal returns an `accountNotFound`
//! method-level error — not data, not a server error.
//!
//! These tests use the in-process server pattern from `jmap_e2e.rs`.
//! The server runs in dev mode (no HTTP auth required); the canonical account
//! id issued by the session endpoint is `u_anonymous`.
//!
//! Independent oracle: RFC 8621 §2
//!   "If the `accountId` does not correspond to a valid account, the method
//!   MUST return an `accountNotFound` error."

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use stoa_mail::{
    server::{build_router, AppState, JmapStores},
    store::new_sqlx_mail_store,
    token_store::TokenStore,
};
use stoa_reader::{
    post::ipfs_write::{IpfsBlockStore, IpfsWriteError},
    store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
};
use tokio::net::TcpListener;

// ── Minimal in-memory IPFS store ──────────────────────────────────────────────

struct MemIpfs {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemIpfs {
    fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(Default::default()),
        }
    }
}

#[async_trait]
impl IpfsBlockStore for MemIpfs {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
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

// ── Pool helpers ───────────────────────────────────────────────────────────────

async fn make_reader_pool(_tag: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_reader::migrations::run_migrations(&url)
        .await
        .expect("reader migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("reader pool");
    (pool, tmp)
}

async fn make_mail_pool(_tag: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_mail::migrations::run_migrations(&url)
        .await
        .expect("mail migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("mail pool");
    (pool, tmp)
}

async fn make_core_pool(_tag: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url)
        .await
        .expect("core migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("core pool");
    (pool, tmp)
}

/// Spin up a dev-mode JMAP server and return its base URL and temp-file handles.
///
/// The caller MUST hold the returned handles alive for the duration of the test;
/// dropping them deletes the SQLite files backing the stores.
///
/// Dev mode: no HTTP authentication required, canonical accountId = `u_anonymous`.
async fn spawn_dev_server(tag: &str) -> (String, Vec<tempfile::TempPath>) {
    let (reader_pool, reader_tmp) = make_reader_pool(tag).await;
    let (mail_pool, mail_tmp) = make_mail_pool(tag).await;
    let mail_pool_arc = Arc::new(mail_pool);
    let (core_pool, core_tmp) = make_core_pool(tag).await;

    let ipfs = Arc::new(MemIpfs::new());
    let article_numbers = Arc::new(ArticleNumberStore::new(reader_pool.clone()));
    let overview_store = Arc::new(OverviewStore::new(reader_pool));
    let mail_store = new_sqlx_mail_store(Arc::clone(&mail_pool_arc));
    mail_store
        .provision_mailboxes()
        .await
        .expect("provision_mailboxes must succeed at startup");
    let special_mailboxes = Arc::new(
        mail_store
            .list_mailboxes()
            .await
            .expect("list_mailboxes must succeed after provision"),
    );
    let jmap_stores = Arc::new(JmapStores {
        ipfs: ipfs as Arc<dyn IpfsBlockStore>,
        msgid_map: Arc::new(stoa_core::msgid_map::MsgIdMap::new(core_pool)),
        article_numbers,
        overview_store,
        search_index: None,
        outbound_mailer: None,
        mail_store,
        special_mailboxes,
    });

    let state = Arc::new(AppState {
        start_time: std::time::Instant::now(),
        jmap: Some(jmap_stores),
        jmap_dispatcher: None,
        credential_store: Arc::new(stoa_auth::CredentialStore::empty()),
        auth_config: Arc::new(stoa_auth::AuthConfig::default()),
        token_store: Arc::new(TokenStore::new(Arc::clone(&mail_pool_arc))),
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (
        format!("http://127.0.0.1:{port}"),
        vec![reader_tmp, mail_tmp, core_tmp],
    )
}

// ── Helper: post a single JMAP method call, return methodResponses[0] ─────────

async fn jmap_call(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let req_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[method, args, "c1"]]
    });
    let resp = client
        .post(format!("{base}/jmap/api"))
        .json(&req_body)
        .send()
        .await
        .expect("request must succeed");
    assert_eq!(resp.status(), 200, "JMAP API must return HTTP 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["methodResponses"][0].clone()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Email/get with a foreign accountId must return accountNotFound, not data.
///
/// Oracle: RFC 8621 §2 — accountNotFound error when accountId does not match
/// the authenticated principal.
#[tokio::test]
async fn email_get_wrong_account_id_returns_account_not_found() {
    let (base, _handles) = spawn_dev_server("eg_wrong").await;
    let client = reqwest::Client::new();

    // Confirm the canonical accountId so we know what "wrong" means.
    let session: serde_json::Value = client
        .get(format!("{base}/jmap/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let canonical = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("primaryAccounts must contain urn:ietf:params:jmap:mail");
    assert_eq!(
        canonical, "u_anonymous",
        "dev-mode canonical accountId must be u_anonymous"
    );

    // Use a different, non-existent account id.
    let invocation = jmap_call(
        &client,
        &base,
        "Email/get",
        serde_json::json!({
            "accountId": "other-account",
            "ids": ["bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"]
        }),
    )
    .await;

    // The invocation name must be "error", not "Email/get".
    assert_eq!(
        invocation[0].as_str().unwrap(),
        "error",
        "wrong accountId must produce an error invocation, got: {invocation}"
    );
    // The error type must be accountNotFound (RFC 8621 §2).
    let error_type = invocation[1]["type"].as_str().unwrap_or("");
    assert_eq!(
        error_type, "accountNotFound",
        "error type must be accountNotFound, got: {invocation}"
    );
}

/// Mailbox/get with a foreign accountId must return accountNotFound, not data.
#[tokio::test]
async fn mailbox_get_wrong_account_id_returns_account_not_found() {
    let (base, _handles) = spawn_dev_server("mg_wrong").await;
    let client = reqwest::Client::new();

    let invocation = jmap_call(
        &client,
        &base,
        "Mailbox/get",
        serde_json::json!({
            "accountId": "other-account",
            "ids": null
        }),
    )
    .await;

    assert_eq!(
        invocation[0].as_str().unwrap(),
        "error",
        "wrong accountId must produce an error invocation, got: {invocation}"
    );
    let description = invocation[1]["type"].as_str().unwrap_or("");
    assert_eq!(
        description, "accountNotFound",
        "error type must be accountNotFound, got: {invocation}"
    );
}

/// Email/query with a foreign accountId must return accountNotFound.
#[tokio::test]
async fn email_query_wrong_account_id_returns_account_not_found() {
    let (base, _handles) = spawn_dev_server("eq_wrong").await;
    let client = reqwest::Client::new();

    let invocation = jmap_call(
        &client,
        &base,
        "Email/query",
        serde_json::json!({
            "accountId": "other-account",
            "filter": {}
        }),
    )
    .await;

    assert_eq!(
        invocation[0].as_str().unwrap(),
        "error",
        "wrong accountId must produce an error invocation, got: {invocation}"
    );
    let description = invocation[1]["type"].as_str().unwrap_or("");
    assert_eq!(
        description, "accountNotFound",
        "error type must be accountNotFound, got: {invocation}"
    );
}

/// Email/get with an empty accountId must return accountNotFound.
///
/// An empty string is not a valid accountId and does not match `u_anonymous`.
#[tokio::test]
async fn email_get_empty_account_id_returns_account_not_found() {
    let (base, _handles) = spawn_dev_server("eg_empty").await;
    let client = reqwest::Client::new();

    let invocation = jmap_call(
        &client,
        &base,
        "Email/get",
        serde_json::json!({
            "accountId": "",
            "ids": []
        }),
    )
    .await;

    assert_eq!(
        invocation[0].as_str().unwrap(),
        "error",
        "empty accountId must produce an error invocation, got: {invocation}"
    );
    let description = invocation[1]["type"].as_str().unwrap_or("");
    assert_eq!(
        description, "accountNotFound",
        "error type must be accountNotFound, got: {invocation}"
    );
}

/// Mailbox/get with the correct canonical accountId must succeed (regression guard).
///
/// This confirms the validation does not break the happy path.
#[tokio::test]
async fn mailbox_get_correct_account_id_succeeds() {
    let (base, _handles) = spawn_dev_server("mg_correct").await;
    let client = reqwest::Client::new();

    // Get the canonical accountId from the session.
    let session: serde_json::Value = client
        .get(format!("{base}/jmap/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let account_id = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("primaryAccounts must contain urn:ietf:params:jmap:mail")
        .to_string();

    let invocation = jmap_call(
        &client,
        &base,
        "Mailbox/get",
        serde_json::json!({
            "accountId": account_id,
            "ids": null
        }),
    )
    .await;

    assert_eq!(
        invocation[0].as_str().unwrap(),
        "Mailbox/get",
        "correct accountId must succeed with Mailbox/get response, got: {invocation}"
    );
    assert!(
        invocation[1]["list"].is_array(),
        "response must contain a list field"
    );
}
