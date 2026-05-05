//! HTTP Basic Auth middleware tests for JMAP endpoints.
//!
//! Oracle: RFC 7617 §2 (Basic scheme), RFC 8620 §2 (JMAP session auth),
//! RFC 9110 §11.7 (WWW-Authenticate).
//!
//! These tests verify observable HTTP behaviour derived from the RFCs alone,
//! exercising the auth middleware from the outside via real HTTP requests.

use std::sync::Arc;
use std::time::Instant;

use data_encoding::BASE64;
use stoa_auth::{AuthConfig, CredentialStore, UserCredential};
use stoa_mail::{
    server::{build_router, AppState},
    token_store::TokenStore,
};
use tokio::net::TcpListener;

async fn make_token_store() -> Arc<TokenStore> {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_mail::migrations::run_migrations(&url)
        .await
        .expect("migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("pool");
    // Keep the file alive via the open pool fd (POSIX: unlink after fd open
    // leaves the inode readable until the last fd closes).
    std::mem::forget(tmp);
    Arc::new(TokenStore::new(Arc::new(pool)))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Build an `AppState` with a single user: alice / correct-horse.
/// bcrypt cost 4 for fast tests (minimum valid bcrypt cost).
async fn auth_state_alice() -> Arc<AppState> {
    let hash = bcrypt::hash("correct-horse", 4).expect("bcrypt::hash must not fail");
    let users = vec![UserCredential {
        username: "alice".to_string(),
        password: hash,
    }];
    Arc::new(AppState {
        start_time: Instant::now(),
        jmap: None,
        jmap_dispatcher: None,
        credential_store: Arc::new(
            CredentialStore::from_credentials(&users).expect("test setup: valid bcrypt hashes"),
        ),
        auth_config: Arc::new(AuthConfig {
            required: true,
            users,
            ..Default::default()
        }),
        token_store: make_token_store().await,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
        db_pool: None,
    })
}

/// Build an `AppState` in dev mode: `required = false`, no users, no credential file.
/// Per `AuthConfig::is_dev_mode()`, all requests bypass auth.
async fn dev_state() -> Arc<AppState> {
    Arc::new(AppState {
        start_time: Instant::now(),
        jmap: None,
        jmap_dispatcher: None,
        credential_store: Arc::new(CredentialStore::empty()),
        auth_config: Arc::new(AuthConfig::default()),
        token_store: make_token_store().await,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
        db_pool: None,
    })
}

/// Encode `user:pass` as the value to use in an Authorization header.
/// Returns the full header value e.g. `"Basic dXNlcjpwYXNz"`.
fn basic_header(user: &str, pass: &str) -> String {
    format!(
        "Basic {}",
        BASE64.encode(format!("{user}:{pass}").as_bytes())
    )
}

/// Spawn the mail server in-process on a random port. Returns the base URL.
async fn spawn_server(state: Arc<AppState>) -> String {
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Brief yield so the server task starts.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    format!("http://127.0.0.1:{port}")
}

// ── Test 1: No Authorization header ───────────────────────────────────────────

/// RFC 7617 §2 + RFC 9110 §11.7:
/// A request with no Authorization header to a protected resource must receive
/// 401 Unauthorized with a WWW-Authenticate header advertising the Basic scheme.
#[tokio::test]
async fn no_auth_header_to_jmap_api_returns_401_with_www_authenticate() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(resp.status(), 401, "missing auth must return 401");

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("401 must include WWW-Authenticate header")
        .to_str()
        .expect("WWW-Authenticate must be ASCII");

    // RFC 7617 §2: challenge must be 'Basic realm="..."'
    assert!(
        www_auth.starts_with("Basic "),
        "WWW-Authenticate must use Basic scheme, got: {www_auth}"
    );
    assert!(
        www_auth.contains("realm="),
        "WWW-Authenticate must include realm parameter, got: {www_auth}"
    );
}

// ── Test 2: Valid credentials ──────────────────────────────────────────────────

/// RFC 7617 §2: valid credentials must be accepted — the server must not return 401.
///
/// The AppState here has `jmap: None` (no backing stores), so the handler returns
/// 503 "JMAP not configured". That is the correct downstream response when auth
/// passes. We assert the response is NOT 401, proving the middleware accepted
/// the credentials.
#[tokio::test]
async fn valid_credentials_to_jmap_api_pass_auth_middleware() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    let status = resp.status().as_u16();
    assert_ne!(
        status, 401,
        "valid credentials must not return 401; got {status}"
    );
    assert_ne!(
        status, 403,
        "valid credentials must not return 403; got {status}"
    );
}

// ── Test 3: Wrong password ─────────────────────────────────────────────────────

/// RFC 7617 §2: wrong password must return 401.
/// The 401 must also carry WWW-Authenticate (RFC 9110 §11.7).
#[tokio::test]
async fn wrong_password_to_jmap_api_returns_401() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .header("Authorization", basic_header("alice", "wrong-password"))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(resp.status(), 401, "wrong password must return 401");
    assert!(
        resp.headers().contains_key("www-authenticate"),
        "401 on wrong password must include WWW-Authenticate"
    );
}

// ── Test 4: Malformed Authorization header ─────────────────────────────────────

/// RFC 7617 §2: a malformed Authorization header (not valid base64) must return
/// 401. The server must not panic or return 500 on malformed input.
#[tokio::test]
async fn malformed_base64_in_authorization_returns_401() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .header("Authorization", "Basic !!!not-valid-base64!!!")
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "malformed base64 in Authorization must return 401, not {}",
        resp.status()
    );
}

/// RFC 7617 §2: valid base64 that decodes to a string without ':' is malformed
/// per the Basic scheme grammar and must return 401.
#[tokio::test]
async fn authorization_header_missing_colon_returns_401() {
    let base = spawn_server(auth_state_alice().await).await;

    let encoded = BASE64.encode(b"nocolonhere");
    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .header("Authorization", format!("Basic {encoded}"))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "Authorization with no ':' separator must return 401"
    );
}

// ── Test 5: /health bypasses auth ─────────────────────────────────────────────

/// RFC 9110 §11.7: /health must be reachable without credentials.
/// Monitoring endpoints must not require auth.
#[tokio::test]
async fn health_endpoint_bypasses_auth() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        200,
        "/health must return 200 without credentials"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

// ── Test 6: /.well-known/jmap bypasses auth ────────────────────────────────────

/// /.well-known/jmap is a discovery endpoint (RFC 8620 §2).
/// Clients need it to locate the session URL before they have credentials;
/// it must not require auth.
#[tokio::test]
async fn well_known_jmap_bypasses_auth() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!("{base}/.well-known/jmap"))
        .send()
        .await
        .expect("request must succeed");

    // Must be 301 redirect, not 401.
    assert_eq!(
        resp.status(),
        301,
        "/.well-known/jmap must redirect (301) without credentials, not {}",
        resp.status()
    );
}

// ── Test 7: /jmap/download with wrong account_id ──────────────────────────────

/// RFC 8620 §2: /jmap/download/{account_id}/{blob_id}/{name} — when alice is
/// authenticated but the account_id in the path belongs to bob, the server must
/// reject the request (403 Forbidden if authenticated but not authorised;
/// 401 Unauthorized is also acceptable if the account_id is treated as part of
/// the credential check). Either way, a 200 must never be returned.
#[tokio::test]
async fn download_wrong_account_id_is_rejected_when_authenticated() {
    let base = spawn_server(auth_state_alice().await).await;

    // A real DAG-CBOR CID used as the blob_id; account_id is "u_bob" but
    // the authenticated user is "alice" (maps to "u_alice").
    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/jmap/download/u_bob/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/file.txt"
        ))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .send()
        .await
        .expect("request must succeed");

    let status = resp.status().as_u16();
    assert!(
        status == 403 || status == 401,
        "download with wrong account_id must return 403 or 401, got {status}"
    );
}

/// If unauthenticated, /jmap/download with any account_id must return 401.
#[tokio::test]
async fn download_without_credentials_returns_401() {
    let base = spawn_server(auth_state_alice().await).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/jmap/download/u_alice/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/file.txt"
        ))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "unauthenticated download must return 401"
    );
}

// ── Test 8: Dev mode ──────────────────────────────────────────────────────────

/// Dev mode: `auth.required = false`, no users configured.
/// Per `AuthConfig::is_dev_mode()`, all requests must pass through without
/// presenting credentials.
#[tokio::test]
async fn dev_mode_jmap_api_accessible_without_auth() {
    let base = spawn_server(dev_state().await).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/api"))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:mail"],
            "methodCalls": []
        }))
        .send()
        .await
        .expect("request must succeed");

    // 200 (no stores wired) or 503 (no JMAP stores) — either is fine.
    // What is NOT acceptable is 401.
    let status = resp.status().as_u16();
    assert!(status != 401, "dev mode must not return 401; got {status}");
}

/// Dev mode: /jmap/session must be accessible without credentials.
#[tokio::test]
async fn dev_mode_session_endpoint_accessible_without_auth() {
    let base = spawn_server(dev_state().await).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        200,
        "dev mode: /jmap/session must be accessible without credentials"
    );
}

/// Dev mode: /jmap/download must also bypass auth.
#[tokio::test]
async fn dev_mode_download_endpoint_bypasses_auth() {
    let base = spawn_server(dev_state().await).await;

    // Any CID — in dev mode auth must not block the request.
    // The response may be 400 (invalid CID) or 503 (no stores), but not 401.
    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/jmap/download/u_anon/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/file.txt"
        ))
        .send()
        .await
        .expect("request must succeed");

    let status = resp.status().as_u16();
    assert!(
        status != 401,
        "dev mode download must not return 401; got {status}"
    );
}
