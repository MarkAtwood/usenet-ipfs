//! Integration tests: security response headers on the JMAP HTTP server.
//!
//! Oracle: SOC2 CC6.6 / OWASP HTTP Security Headers.
//!
//! Every response from the JMAP server must carry the six standard security
//! headers.  `Strict-Transport-Security` is only emitted when the configured
//! `base_url` starts with `https://`, indicating TLS is active.
//!
//! These tests use the in-process server pattern established in
//! `feed_endpoints.rs` and `jmap_basic_auth.rs`.

use std::sync::Arc;
use std::time::Instant;

use stoa_auth::{AuthConfig, CredentialStore};
use stoa_mail::{
    server::{build_router, AppState},
    token_store::TokenStore,
};
use tokio::net::TcpListener;

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// Build a dev-mode `AppState` with the given `base_url`.
/// Returns the state and the temp-file handle (must stay alive for the test).
async fn dev_state(base_url: &str) -> (Arc<AppState>, tempfile::TempPath) {
    let (pool, tmp) = make_mail_pool().await;
    let state = Arc::new(AppState {
        start_time: Instant::now(),
        jmap: None,
        jmap_dispatcher: None,
        credential_store: Arc::new(CredentialStore::empty()),
        auth_config: Arc::new(AuthConfig::default()),
        token_store: Arc::new(TokenStore::new(Arc::new(pool))),
        oidc_store: None,
        base_url: base_url.to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    });
    (state, tmp)
}

/// Spawn the JMAP server in-process on a random port; returns the base URL.
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

/// Assert the five unconditional security headers are present with exact values.
fn assert_security_headers(resp: &reqwest::Response, context: &str) {
    let headers = resp.headers();
    let expected: &[(&str, &str)] = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("content-security-policy", "default-src 'none'"),
        (
            "permissions-policy",
            "geolocation=(), microphone=(), camera=()",
        ),
    ];
    for (name, value) in expected {
        let got = headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            got, *value,
            "{context}: header {name} expected {value:?}, got {got:?}"
        );
    }
}

// ── Security header tests ─────────────────────────────────────────────────────

/// Non-TLS: five security headers present; HSTS absent.
#[tokio::test]
async fn jmap_security_headers_on_health_http() {
    let (state, _tmp) = dev_state("http://localhost").await;
    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("GET /health");

    assert_eq!(resp.status().as_u16(), 200);
    assert_security_headers(&resp, "GET /health (http base_url)");

    let hsts = resp.headers().get("strict-transport-security");
    assert!(
        hsts.is_none(),
        "HSTS must not be emitted when base_url is http://; got: {hsts:?}"
    );
}

/// Non-TLS: security headers on well-known JMAP discovery endpoint.
#[tokio::test]
async fn jmap_security_headers_on_well_known() {
    let (state, _tmp) = dev_state("http://localhost").await;
    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/.well-known/jmap"))
        .send()
        .await
        .expect("GET /.well-known/jmap");

    // /.well-known/jmap redirects; reqwest follows it. Just assert the last response.
    assert_security_headers(&resp, "GET /.well-known/jmap");
}

/// TLS active (base_url starts with https://): HSTS present with correct value.
#[tokio::test]
async fn jmap_hsts_present_when_tls_active() {
    let (state, _tmp) = dev_state("https://mail.example.com").await;
    let addr = spawn_server(state).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("GET /health with https base_url");

    assert_eq!(resp.status().as_u16(), 200);
    assert_security_headers(&resp, "GET /health (https base_url)");

    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        hsts, "max-age=63072000; includeSubDomains",
        "HSTS must be present and correct when base_url starts with https://"
    );
}

/// JMAP /jmap/session endpoint (protected route): security headers present in dev mode.
#[tokio::test]
async fn jmap_security_headers_on_jmap_session() {
    let (state, _tmp) = dev_state("http://localhost").await;
    let addr = spawn_server(state).await;

    // Dev mode bypasses auth; /jmap/session returns 200 without credentials.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/jmap/session"))
        .send()
        .await
        .expect("GET /jmap/session");

    assert_security_headers(&resp, "GET /jmap/session");
}
