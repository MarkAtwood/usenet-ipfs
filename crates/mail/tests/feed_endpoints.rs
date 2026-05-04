//! Integration tests for the feed endpoints.
//!
//! Oracles:
//!   RSS 2.0 spec (http://www.rssboard.org/rss-specification)
//!   Atom 1.0 RFC 4287
//!   RFC 3977 §3.1 — newsgroup name validation
//!   XML 1.0 §2.4 — character data must use named entity escapes for & < >
//!
//! Each test starts an in-process server against a unique in-memory SQLite pool.
//! Store seeding uses the same public `insert` / `assign_number` APIs as
//! production code; no implementation internals are reached.

use std::sync::Arc;
use std::time::Instant;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use stoa_auth::{AuthConfig, CredentialStore};
use stoa_mail::{
    server::{build_router, AppState, JmapStores},
    state::{flags::UserFlagsStore, version::StateStore},
    token_store::TokenStore,
};
use stoa_reader::{
    post::ipfs_write::MemIpfsStore,
    store::{
        article_numbers::ArticleNumberStore, overview::OverviewRecord, overview::OverviewStore,
    },
};
use tokio::net::TcpListener;

// ── Pool helpers ──────────────────────────────────────────────────────────────

async fn make_reader_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
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

async fn make_mail_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
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

async fn make_core_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
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

// ── AppState builders ─────────────────────────────────────────────────────────

/// Build an AppState with `jmap: None` (for tests that don't need store data).
async fn state_no_jmap() -> Arc<AppState> {
    let (mail_pool, _mail_tmp) = make_mail_pool().await;
    // _mail_tmp dropped here; pool holds open fd so SQLite file remains accessible.
    Arc::new(AppState {
        start_time: Instant::now(),
        jmap: None,
        jmap_dispatcher: None,
        credential_store: Arc::new(CredentialStore::empty()),
        auth_config: Arc::new(AuthConfig::default()),
        token_store: Arc::new(TokenStore::new(Arc::new(mail_pool))),
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    })
}

/// Build an AppState with real JMAP stores backed by tempfile SQLite.
///
/// Returns the state, the bare stores so the caller can seed test data
/// before spawning the server, and the temp-file handles that must remain
/// alive for the duration of the test (dropping them deletes the SQLite files).
async fn state_with_jmap() -> (
    Arc<AppState>,
    Arc<ArticleNumberStore>,
    Arc<OverviewStore>,
    Vec<tempfile::TempPath>,
) {
    let (reader_pool, reader_tmp) = make_reader_pool().await;
    let (mail_pool, mail_tmp) = make_mail_pool().await;
    let mail_pool_arc = Arc::new(mail_pool);
    let (core_pool, core_tmp) = make_core_pool().await;

    let article_numbers = Arc::new(ArticleNumberStore::new(reader_pool.clone()));
    let overview_store = Arc::new(OverviewStore::new(reader_pool));
    let ipfs = Arc::new(MemIpfsStore::new());

    stoa_mail::mailbox::provision::provision_mailboxes(&mail_pool_arc)
        .await
        .expect("provision_mailboxes must succeed at startup");
    let special_mailboxes = Arc::new(
        stoa_mail::mailbox::provision::list_mailboxes(&mail_pool_arc)
            .await
            .expect("list_mailboxes must succeed after provision"),
    );
    let jmap = Arc::new(JmapStores {
        ipfs,
        msgid_map: Arc::new(stoa_core::msgid_map::MsgIdMap::new(core_pool)),
        article_numbers: Arc::clone(&article_numbers),
        overview_store: Arc::clone(&overview_store),
        user_flags: Arc::new(UserFlagsStore::new((*mail_pool_arc).clone())),
        state_store: Arc::new(StateStore::new((*mail_pool_arc).clone())),
        change_log: Arc::new(stoa_mail::state::change_log::ChangeLogStore::new(
            (*mail_pool_arc).clone(),
        )),
        search_index: None,
        subscription_store: Arc::new(stoa_mail::state::subscriptions::SubscriptionStore::new(
            (*mail_pool_arc).clone(),
        )),
        smtp_relay_queue: None,
        mail_pool: Arc::clone(&mail_pool_arc),
        special_mailboxes,
    });

    let state = Arc::new(AppState {
        start_time: Instant::now(),
        jmap: Some(jmap),
        jmap_dispatcher: None,
        credential_store: Arc::new(CredentialStore::empty()),
        auth_config: Arc::new(AuthConfig::default()),
        token_store: Arc::new(TokenStore::new(Arc::clone(&mail_pool_arc))),
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    });

    (
        state,
        article_numbers,
        overview_store,
        vec![reader_tmp, mail_tmp, core_tmp],
    )
}

/// Spawn the server on an ephemeral port and return the bound address.
async fn spawn_server(state: Arc<AppState>) -> std::net::SocketAddr {
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    addr
}

/// Build a synthetic CID from arbitrary bytes (for seeding ArticleNumberStore).
fn dummy_cid(tag: &[u8]) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(tag))
}

/// A minimal valid OverviewRecord for seeding test data.
fn make_record(n: u64, subject: &str, message_id: &str) -> OverviewRecord {
    OverviewRecord {
        article_number: n,
        subject: subject.to_string(),
        from: "user@example.com".to_string(),
        date: "Mon, 22 Apr 2024 12:00:00 +0000".to_string(),
        message_id: message_id.to_string(),
        references: String::new(),
        byte_count: 100,
        line_count: 5,
        did_sig_valid: None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// GET /feed/comp.test.rss must return 200, Content-Type: application/rss+xml,
/// and a body that starts with an RSS envelope containing the group name.
#[tokio::test]
async fn feed_rss_returns_xml() {
    let (state, article_numbers, overview_store, _handles) = state_with_jmap().await;

    // Seed one article so the group exists and returns a non-empty feed.
    article_numbers
        .assign_number("comp.test", &dummy_cid(b"rss-art-1"))
        .await
        .expect("assign_number");
    overview_store
        .insert(
            "comp.test",
            &make_record(1, "Test subject", "<rss-art-1@test>"),
        )
        .await
        .expect("insert overview");

    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/comp.test.rss"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(resp.status(), 200, "RSS feed must return 200");

    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/rss+xml"),
        "Content-Type must be application/rss+xml, got: {ct}"
    );

    let body = resp.text().await.expect("body must be readable");
    assert!(body.contains("<rss"), "body must contain RSS root element");
    assert!(
        body.contains("comp.test"),
        "body must contain the group name"
    );
}

/// GET /feed/comp.test.atom must return 200, Content-Type: application/atom+xml,
/// and a body that starts with an Atom feed envelope.
#[tokio::test]
async fn feed_atom_returns_xml() {
    let (state, article_numbers, overview_store, _handles) = state_with_jmap().await;

    article_numbers
        .assign_number("comp.test", &dummy_cid(b"atom-art-1"))
        .await
        .expect("assign_number");
    overview_store
        .insert(
            "comp.test",
            &make_record(1, "Atom subject", "<atom-art-1@test>"),
        )
        .await
        .expect("insert overview");

    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/comp.test.atom"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(resp.status(), 200, "Atom feed must return 200");

    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/atom+xml"),
        "Content-Type must be application/atom+xml, got: {ct}"
    );

    let body = resp.text().await.expect("body must be readable");
    assert!(
        body.contains("<feed"),
        "body must contain Atom feed root element"
    );
    assert!(
        body.contains("comp.test"),
        "body must contain the group name"
    );
}

/// A group name containing characters that fail RFC 3977 validation must return 400.
///
/// `1comp.test` starts with a digit, which is rejected by `validate_group_name`.
/// The handler validates after parsing the suffix, so `1comp.test.rss` strips to
/// `1comp.test`, which fails validation → 400 Bad Request.
#[tokio::test]
async fn feed_invalid_group_name_returns_400() {
    // jmap: None is fine — validation happens before the jmap lookup.
    let addr = spawn_server(state_no_jmap().await).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/1invalid-group.rss"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        400,
        "group name starting with digit must return 400"
    );
}

/// GET /feed/<nonexistent-group>.atom with a valid group name and empty stores
/// must return 200 with an empty Atom feed (no <entry> element).
#[tokio::test]
async fn feed_nonexistent_group_returns_empty_feed() {
    // Need jmap: Some so the handler reaches the group_range check.
    // Stores are empty — group_range returns (1, 0) which signals empty group.
    let (state, _article_numbers, _overview_store, _handles) = state_with_jmap().await;
    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/no.such.group.atom"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        200,
        "nonexistent group must return 200 with an empty feed"
    );

    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/atom+xml"),
        "Content-Type must be application/atom+xml for empty Atom feed, got: {ct}"
    );

    let body = resp.text().await.expect("body must be readable");
    assert!(
        !body.contains("<entry>"),
        "empty feed must contain no <entry> elements"
    );
    assert!(
        body.contains("<feed"),
        "response must still be a valid Atom envelope"
    );
}

/// A feed path without a recognized .rss or .atom extension must return 404.
///
/// Oracle: `parse_feed_path` returns None for paths without a suffix;
/// the handler converts None → NOT_FOUND.
#[tokio::test]
async fn feed_path_without_extension_returns_404() {
    let addr = spawn_server(state_no_jmap().await).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/comp.test"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        404,
        "path without .rss or .atom extension must return 404"
    );
}

/// Subjects containing XML-special characters must be entity-escaped in the feed.
///
/// Oracle: XML 1.0 §2.4 — `<`, `>`, `&` must appear as `&lt;`, `&gt;`, `&amp;`
/// in XML character data. The literal bytes `<XSS>` must not appear in the output.
#[tokio::test]
async fn feed_xml_special_chars_escaped() {
    let (state, article_numbers, overview_store, _handles) = state_with_jmap().await;

    article_numbers
        .assign_number("comp.test", &dummy_cid(b"xss-art-1"))
        .await
        .expect("assign_number");
    // Subject deliberately contains XML-special characters.
    overview_store
        .insert(
            "comp.test",
            &make_record(1, "<XSS>&test", "<xss-art-1@test>"),
        )
        .await
        .expect("insert overview");

    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/feed/comp.test.rss"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("body must be readable");

    // The escaped forms must be present.
    assert!(
        body.contains("&lt;XSS&gt;"),
        "< and > must be entity-escaped; body:\n{body}"
    );
    assert!(
        body.contains("&amp;test"),
        "& must be entity-escaped; body:\n{body}"
    );

    // The raw unescaped bytes must not appear — an XML parser would reject them.
    assert!(
        !body.contains("<XSS>"),
        "literal <XSS> must not appear in output; body:\n{body}"
    );
}
