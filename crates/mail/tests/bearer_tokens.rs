//! Bearer token issuance and validation tests for JMAP token API.
//!
//! Oracles:
//!   RFC 6750  §2.1 — Bearer Token usage (Authorization: Bearer header)
//!   RFC 6750  §3.1 — Error responses (401 with WWW-Authenticate)
//!   UUID v4   spec — id field format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
//!   FIPS 180-4     — SHA-256("test") =
//!                    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
//!                    (verified independently via `echo -n "test" | sha256sum`)
//!
//! These tests derive expected behaviour from the bead stoa-1c8.7 spec
//! and the RFCs above.  They do NOT read the implementation in auth_token.rs.
//!
//! Routes under test:
//!   POST   /jmap/auth/token          — issue a token (requires Basic auth)
//!   GET    /jmap/auth/token          — list tokens (id+label, NOT raw token or hash)
//!   DELETE /jmap/auth/token/:id      — revoke a specific token
//!   GET    /jmap/session             — protected endpoint; accepts Bearer auth
//!
//! Security invariants verified:
//!   - Raw token not returned by list endpoint
//!   - token_hash not returned by list endpoint
//!   - Expired token (expires_at in past) fails auth
//!   - User B cannot revoke user A's token (returns 404, not 200/204)

use std::sync::Arc;
use std::time::Instant;

use data_encoding::BASE64;
use stoa_auth::{AuthConfig, CredentialStore, UserCredential};
use stoa_mail::{
    server::{build_router, AppState},
    token_store::TokenStore,
};
use tokio::net::TcpListener;

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Build an in-process mail pool with migrations applied.
/// Returns a `(pool, TempPath)` tuple; the caller must keep `TempPath` alive.
async fn make_mail_pool(_tag: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_mail::migrations::run_migrations(&url)
        .await
        .expect("migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("pool");
    (pool, tmp)
}

/// Build an `AppState` in dev mode (auth not required, no users).
fn dev_app_state(token_store: Arc<TokenStore>) -> Arc<AppState> {
    Arc::new(AppState {
        start_time: Instant::now(),
        jmap: None,
        jmap_dispatcher: None,
        credential_store: Arc::new(CredentialStore::empty()),
        auth_config: Arc::new(AuthConfig::default()),
        token_store,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    })
}

/// Build an `AppState` with alice authenticated (bcrypt cost 4 for test speed).
fn auth_app_state_alice(token_store: Arc<TokenStore>) -> Arc<AppState> {
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
        token_store,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    })
}

/// Build an `AppState` with alice AND bob (for ownership tests).
fn auth_app_state_two_users(token_store: Arc<TokenStore>) -> Arc<AppState> {
    let alice_hash = bcrypt::hash("alice-pass", 4).expect("bcrypt::hash");
    let bob_hash = bcrypt::hash("bob-pass", 4).expect("bcrypt::hash");
    let users = vec![
        UserCredential {
            username: "alice".to_string(),
            password: alice_hash,
        },
        UserCredential {
            username: "bob".to_string(),
            password: bob_hash,
        },
    ];
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
        token_store,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
    })
}

/// Encode `user:pass` as a Basic Authorization header value.
fn basic_header(user: &str, pass: &str) -> String {
    format!(
        "Basic {}",
        BASE64.encode(format!("{user}:{pass}").as_bytes())
    )
}

/// Spawn the mail server on a random port. Returns the base URL.
async fn spawn_server(state: Arc<AppState>) -> String {
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    format!("http://127.0.0.1:{port}")
}

/// Return true if `s` is a valid UUID v4.
///
/// UUID v4 format per RFC 4122 §4.4:
///   xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
/// where every x is a lowercase hex digit, the version nibble is '4',
/// and the variant nibble y ∈ {'8', '9', 'a', 'b'}.
fn is_uuid_v4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lengths = [8usize, 4, 4, 4, 12];
    for (p, &expected_len) in parts.iter().zip(expected_lengths.iter()) {
        if p.len() != expected_len {
            return false;
        }
        if !p.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    // Version nibble must be '4' (parts[2] starts with '4').
    if parts[2].chars().next() != Some('4') {
        return false;
    }
    // Variant nibble must be 8, 9, a, or b (parts[3] starts with one of these).
    matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b'))
}

// ── Test 1: POST /jmap/auth/token — valid Basic auth → 201 with token fields ──

/// Spec (stoa-1c8.7): POST /jmap/auth/token with valid Basic auth returns
/// 201 with body containing "token", "id", and "expires_at".
///
/// RFC 6750 §2.1: the token value is a base64url string.
/// UUID v4 spec: the "id" field must be a UUID v4.
#[tokio::test]
async fn post_token_valid_basic_auth_returns_201_with_token_id_expires_at() {
    let (pool, _tmp) = make_mail_pool("t01").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .json(&serde_json::json!({"label": "test-client"}))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        201,
        "valid Basic auth must return 201 Created"
    );

    let body: serde_json::Value = resp.json().await.expect("body must be JSON");

    assert!(
        body.get("token").and_then(|v| v.as_str()).is_some(),
        "response must contain a string \"token\" field; got: {body}"
    );
    assert!(
        body.get("id").and_then(|v| v.as_str()).is_some(),
        "response must contain a string \"id\" field; got: {body}"
    );
    // expires_at may be null (no expiry) or an integer (unix timestamp).
    assert!(
        body.get("expires_at").is_some(),
        "response must contain \"expires_at\" (null or integer); got: {body}"
    );

    let id = body["id"].as_str().unwrap();
    assert!(is_uuid_v4(id), "\"id\" must be a UUID v4, got: {id}");

    // Token must be a non-empty string (base64url encoded bytes).
    let token = body["token"].as_str().unwrap();
    assert!(!token.is_empty(), "\"token\" must be a non-empty string");
    // base64url chars: A-Z, a-z, 0-9, -, _  (RFC 4648 §5, no padding).
    assert!(
        token
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        "\"token\" must be base64url-encoded (chars: A-Za-z0-9-_); got: {token}"
    );
}

// ── Test 2: Returned token works as Bearer on protected endpoint ───────────────

/// RFC 6750 §2.1: after obtaining a token via POST /jmap/auth/token, the client
/// MUST be able to use it as "Authorization: Bearer <token>" on protected routes.
/// The server MUST NOT return 401 for a valid, non-expired token.
#[tokio::test]
async fn bearer_token_grants_access_to_protected_endpoint() {
    let (pool, _tmp) = make_mail_pool("t02").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(Arc::clone(&token_store))).await;

    // Issue token via Basic auth.
    let issue_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .json(&serde_json::json!({"label": "test"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(issue_resp.status(), 201, "token issuance must return 201");
    let body: serde_json::Value = issue_resp.json().await.unwrap();
    let token = body["token"]
        .as_str()
        .expect("token must be a string")
        .to_string();

    // Use the token on /jmap/session.
    let resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("session request must succeed");

    let status = resp.status().as_u16();
    assert!(
        status != 401,
        "valid Bearer token must not return 401; got {status}"
    );
    assert!(
        status != 403,
        "valid Bearer token must not return 403; got {status}"
    );
    assert_eq!(
        status, 200,
        "valid Bearer token on /jmap/session must return 200"
    );
}

// ── Test 3: Wrong/invalid Bearer token → 401 ──────────────────────────────────

/// RFC 6750 §3.1: when a Bearer token is invalid, the server MUST respond 401.
#[tokio::test]
async fn invalid_bearer_token_returns_401() {
    let (pool, _tmp) = make_mail_pool("t03").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", "Bearer not-a-real-token-deadbeef1234")
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "invalid Bearer token must return 401; got {}",
        resp.status()
    );
}

// ── Test 4: Expired token is rejected ─────────────────────────────────────────

/// Spec (stoa-1c8.7): expires_at is checked on every request.
/// A token whose expires_at is in the past must be rejected with 401.
///
/// We seed a token directly via TokenStore::issue with expires_in_days = -1
/// (1 day in the past) and then attempt to use it via Bearer auth.
/// This bypasses the HTTP issuance endpoint (which would receive the request
/// after token creation) and exercises the verify path with a known-expired entry.
///
/// Oracle: the token_store::verify SQL checks `expires_at IS NULL OR expires_at > now`.
/// A token with expires_at = (now - 86400) satisfies `expires_at <= now` and
/// therefore fails the check.
#[tokio::test]
async fn expired_token_is_rejected_with_401() {
    let (pool_inner, _tmp) = make_mail_pool("t04").await;
    let pool = Arc::new(pool_inner);
    let token_store = Arc::new(TokenStore::new(Arc::clone(&pool)));

    // Issue an expired token directly (expires_in_days = -1 → expired yesterday).
    let (raw_token, _id, expires_at) = token_store
        .issue("alice", Some("expired".to_string()), Some(-1))
        .await
        .expect("direct issue must succeed");
    assert!(
        expires_at.is_some()
            && expires_at.unwrap() < {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            },
        "expires_at must be in the past for this test to be meaningful"
    );

    let base = spawn_server(auth_app_state_alice(Arc::clone(&token_store))).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", format!("Bearer {raw_token}"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "expired Bearer token must return 401; got {}",
        resp.status()
    );
}

// ── Test 5: DELETE /jmap/auth/token/:id revokes token → 401 on next use ───────

/// Spec: DELETE /jmap/auth/token/:id removes the token.
/// After deletion, any Bearer request using that token must return 401.
#[tokio::test]
async fn delete_token_revokes_access() {
    let (pool, _tmp) = make_mail_pool("t05").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(Arc::clone(&token_store))).await;

    // Issue a token.
    let issue_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .json(&serde_json::json!({"label": "to-revoke"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(issue_resp.status(), 201, "token issuance must return 201");
    let body: serde_json::Value = issue_resp.json().await.unwrap();
    let token = body["token"]
        .as_str()
        .expect("token must be a string")
        .to_string();
    let id = body["id"]
        .as_str()
        .expect("id must be a string")
        .to_string();

    // Verify the token works before revocation.
    let pre_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("pre-revocation request must succeed");
    assert_eq!(
        pre_resp.status(),
        200,
        "token must grant access before revocation; got {}",
        pre_resp.status()
    );

    // Revoke via DELETE — authenticated as alice (owner).
    let del_resp = reqwest::Client::new()
        .delete(format!("{base}/jmap/auth/token/{id}"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .send()
        .await
        .expect("delete request must succeed");
    assert_eq!(
        del_resp.status(),
        200,
        "DELETE must return 200; got {}",
        del_resp.status()
    );

    // Attempt to use revoked token — must fail.
    let post_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("post-revocation request must succeed");
    assert_eq!(
        post_resp.status(),
        401,
        "revoked Bearer token must return 401; got {}",
        post_resp.status()
    );
}

// ── Test 6: GET /jmap/auth/token lists tokens without raw token or hash ────────

/// Spec (stoa-1c8.7): GET /jmap/auth/token returns an array of token
/// records. Each record must include "id" and "label". It must NEVER include
/// the raw token string or any form of its hash.
///
/// Security invariant: raw token or hash in the list response would allow
/// an attacker with read-only list access to impersonate other sessions.
#[tokio::test]
async fn list_tokens_returns_id_label_not_raw_token_or_hash() {
    let (pool, _tmp) = make_mail_pool("t06").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(Arc::clone(&token_store))).await;

    // Issue two tokens with distinct labels.
    for label in &["client-alpha", "client-beta"] {
        let resp = reqwest::Client::new()
            .post(format!("{base}/jmap/auth/token"))
            .header("Authorization", basic_header("alice", "correct-horse"))
            .json(&serde_json::json!({"label": label}))
            .send()
            .await
            .expect("issue request must succeed");
        assert_eq!(resp.status(), 201, "token issuance must return 201");
    }

    // Fetch the list.
    let list_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .send()
        .await
        .expect("list request must succeed");
    assert_eq!(
        list_resp.status(),
        200,
        "GET /jmap/auth/token must return 200; got {}",
        list_resp.status()
    );

    let body: serde_json::Value = list_resp.json().await.expect("body must be JSON");
    let tokens = body.as_array().expect("list response must be a JSON array");

    assert!(
        tokens.len() >= 2,
        "list must contain at least 2 tokens; got {}",
        tokens.len()
    );

    for entry in tokens {
        // Must have "id".
        assert!(
            entry.get("id").and_then(|v| v.as_str()).is_some(),
            "each entry must have a string \"id\"; got: {entry}"
        );

        // SECURITY: MUST NOT expose raw token.
        assert!(
            entry.get("token").is_none(),
            "list MUST NOT include raw token field; got: {entry}"
        );

        // SECURITY: MUST NOT expose hash under any key.
        assert!(
            entry.get("token_hash").is_none(),
            "list MUST NOT include token_hash field; got: {entry}"
        );
        assert!(
            entry.get("hash").is_none(),
            "list MUST NOT include hash field; got: {entry}"
        );
    }

    // The labels issued must be present.
    let labels: Vec<Option<&str>> = tokens
        .iter()
        .map(|e| e.get("label").and_then(|v| v.as_str()))
        .collect();
    assert!(
        labels.contains(&Some("client-alpha")),
        "list must include \"client-alpha\"; labels: {labels:?}"
    );
    assert!(
        labels.contains(&Some("client-beta")),
        "list must include \"client-beta\"; labels: {labels:?}"
    );
}

// ── Test 7: User B cannot revoke user A's token ────────────────────────────────

/// Security invariant: DELETE /jmap/auth/token/:id must enforce ownership.
/// If user B sends a DELETE for user A's token id, the server must return 404
/// (the id is not visible to B), not 200 or 204.
///
/// Returning 200/204 here would be a critical authorization bypass allowing
/// any authenticated user to revoke any other user's sessions.
#[tokio::test]
async fn user_b_cannot_revoke_user_a_token() {
    let (pool, _tmp) = make_mail_pool("t07").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_two_users(Arc::clone(&token_store))).await;

    // Alice issues a token.
    let issue_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "alice-pass"))
        .json(&serde_json::json!({"label": "alice-session"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(
        issue_resp.status(),
        201,
        "alice token issuance must return 201"
    );
    let body: serde_json::Value = issue_resp.json().await.unwrap();
    let alice_token_id = body["id"]
        .as_str()
        .expect("id must be a string")
        .to_string();

    // Bob attempts to delete Alice's token by its id.
    let del_resp = reqwest::Client::new()
        .delete(format!("{base}/jmap/auth/token/{alice_token_id}"))
        .header("Authorization", basic_header("bob", "bob-pass"))
        .send()
        .await
        .expect("delete request must succeed");

    let status = del_resp.status().as_u16();

    // Must be 404 or 403 — never 200 or 204 (that would be an authorization bypass).
    assert_ne!(
        status, 200,
        "Bob MUST NOT successfully delete Alice's token (ownership bypass)"
    );
    assert_ne!(
        status, 204,
        "Bob MUST NOT successfully delete Alice's token (ownership bypass)"
    );
    assert!(
        status == 404 || status == 403,
        "Bob deleting Alice's token must return 404 or 403, not {status}"
    );
}

// ── Test 8: Dev mode — POST /jmap/auth/token issues token without credentials ──

/// In dev mode (auth not required) POST /jmap/auth/token must issue a bearer
/// token without requiring any credentials.  The handler uses
/// Option<Extension<AuthenticatedUser>> and falls back to an empty username
/// when no user identity is present.
///
/// The issued token must be usable on protected endpoints (which also bypass
/// auth in dev mode).
///
/// Oracle: bead stoa-1c8.7 spec — dev mode bootstrap case.
#[tokio::test]
async fn dev_mode_post_token_issues_token_without_credentials() {
    let (pool, _tmp) = make_mail_pool("t08").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(dev_app_state(token_store)).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .json(&serde_json::json!({"label": "dev-bootstrap"}))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        201,
        "dev mode must issue a token without credentials; got {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    assert!(
        body.get("token").and_then(|v| v.as_str()).is_some(),
        "response must contain a token field; got: {body}"
    );
    assert!(
        body.get("id").and_then(|v| v.as_str()).is_some(),
        "response must contain an id field; got: {body}"
    );
}

// ── Test 9: POST /jmap/auth/token wrong password → 401 ───────────────────────

/// The token issuance endpoint must enforce Basic auth in non-dev mode.
/// A wrong password must return 401 — no token is issued.
#[tokio::test]
async fn post_token_wrong_password_returns_401() {
    let (pool, _tmp) = make_mail_pool("t09").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "wrong-password"))
        .json(&serde_json::json!({"label": "should-not-be-issued"}))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "wrong password on token issuance must return 401; got {}",
        resp.status()
    );
}

// ── Test 10: POST /jmap/auth/token no credentials → 401 ──────────────────────

/// Without any Authorization header in non-dev mode, the token issuance
/// endpoint must return 401 — no token is issued.
#[tokio::test]
async fn post_token_no_credentials_returns_401() {
    let (pool, _tmp) = make_mail_pool("t10").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .json(&serde_json::json!({"label": "should-not-be-issued"}))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "no credentials on token issuance must return 401; got {}",
        resp.status()
    );
}

// ── Test 11: Bearer token session identity matches issuing user ────────────────

/// A token issued for alice must authenticate as alice on /jmap/session.
/// The session endpoint must return username = "alice".
///
/// This verifies that the user identity bound to the token is the one used
/// to build the session object — not some default or arbitrary value.
#[tokio::test]
async fn bearer_token_session_identity_matches_issuing_user() {
    let (pool, _tmp) = make_mail_pool("t11").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(Arc::clone(&token_store))).await;

    let issue_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "correct-horse"))
        .json(&serde_json::json!({"label": "identity-check"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(issue_resp.status(), 201, "token issuance must return 201");
    let body: serde_json::Value = issue_resp.json().await.unwrap();
    let token = body["token"]
        .as_str()
        .expect("token must be a string")
        .to_string();

    let session_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/session"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("session request must succeed");
    assert_eq!(
        session_resp.status(),
        200,
        "valid token must return 200 on session; got {}",
        session_resp.status()
    );

    let session: serde_json::Value = session_resp.json().await.expect("body must be JSON");
    assert_eq!(
        session["username"].as_str(),
        Some("alice"),
        "session username must be 'alice'; got: {}",
        session["username"]
    );
}

// ── Test 12: GET /jmap/auth/token without auth → 401 ─────────────────────────

/// The token list endpoint must require authentication.
/// Unauthenticated requests must return 401, not leak token metadata.
#[tokio::test]
async fn list_tokens_without_auth_returns_401() {
    let (pool, _tmp) = make_mail_pool("t12").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/jmap/auth/token"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "unauthenticated GET /jmap/auth/token must return 401; got {}",
        resp.status()
    );
}

// ── Test 13: DELETE /jmap/auth/token/:id without auth → 401 ──────────────────

/// Unauthenticated DELETE must return 401 without deleting anything.
#[tokio::test]
async fn delete_token_without_auth_returns_401() {
    let (pool, _tmp) = make_mail_pool("t13").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_alice(token_store)).await;

    // Use a plausible UUID that doesn't exist — must still get 401 before lookup.
    let fake_id = "00000000-0000-4000-8000-000000000001";

    let resp = reqwest::Client::new()
        .delete(format!("{base}/jmap/auth/token/{fake_id}"))
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(
        resp.status(),
        401,
        "unauthenticated DELETE must return 401; got {}",
        resp.status()
    );
}

// ── Test 14: GET /jmap/auth/token — list only shows own tokens ────────────────

/// Each user sees only their own tokens in the list.
/// Alice's tokens must not appear in Bob's list and vice versa.
#[tokio::test]
async fn list_tokens_returns_only_own_tokens() {
    let (pool, _tmp) = make_mail_pool("t14").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(auth_app_state_two_users(Arc::clone(&token_store))).await;

    // Alice issues a token.
    let alice_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "alice-pass"))
        .json(&serde_json::json!({"label": "alice-only"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(alice_resp.status(), 201);
    let alice_body: serde_json::Value = alice_resp.json().await.unwrap();
    let alice_token_id = alice_body["id"].as_str().unwrap().to_string();

    // Bob issues a token.
    let bob_resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("bob", "bob-pass"))
        .json(&serde_json::json!({"label": "bob-only"}))
        .send()
        .await
        .expect("issue request must succeed");
    assert_eq!(bob_resp.status(), 201);
    let bob_body: serde_json::Value = bob_resp.json().await.unwrap();
    let bob_token_id = bob_body["id"].as_str().unwrap().to_string();

    // Alice's list must contain alice's id but not bob's.
    let alice_list_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("alice", "alice-pass"))
        .send()
        .await
        .expect("list request must succeed");
    assert_eq!(alice_list_resp.status(), 200);
    let alice_list: serde_json::Value = alice_list_resp.json().await.unwrap();
    let alice_ids: Vec<&str> = alice_list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("id").and_then(|v| v.as_str()))
        .collect();
    assert!(
        alice_ids.contains(&alice_token_id.as_str()),
        "alice's list must contain alice's token id"
    );
    assert!(
        !alice_ids.contains(&bob_token_id.as_str()),
        "alice's list MUST NOT contain bob's token id"
    );

    // Bob's list must contain bob's id but not alice's.
    let bob_list_resp = reqwest::Client::new()
        .get(format!("{base}/jmap/auth/token"))
        .header("Authorization", basic_header("bob", "bob-pass"))
        .send()
        .await
        .expect("list request must succeed");
    assert_eq!(bob_list_resp.status(), 200);
    let bob_list: serde_json::Value = bob_list_resp.json().await.unwrap();
    let bob_ids: Vec<&str> = bob_list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("id").and_then(|v| v.as_str()))
        .collect();
    assert!(
        bob_ids.contains(&bob_token_id.as_str()),
        "bob's list must contain bob's token id"
    );
    assert!(
        !bob_ids.contains(&alice_token_id.as_str()),
        "bob's list MUST NOT contain alice's token id"
    );
}

// ── UUID v4 helper self-test ──────────────────────────────────────────────────

/// Validate the is_uuid_v4 helper against known-good and known-bad values.
/// This is not an integration test — it validates the test oracle itself.
#[test]
fn uuid_v4_helper_correctly_validates_format() {
    // Valid UUID v4.
    assert!(
        is_uuid_v4("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
        "standard v4 must pass"
    );
    assert!(
        is_uuid_v4("00000000-0000-4000-8000-000000000000"),
        "all-zero with correct v4/variant nibbles must pass"
    );
    assert!(
        is_uuid_v4("ffffffff-ffff-4fff-bfff-ffffffffffff"),
        "all-f with correct v4/variant nibbles must pass"
    );

    // Invalid: version nibble is not '4'.
    assert!(
        !is_uuid_v4("f47ac10b-58cc-1372-a567-0e02b2c3d479"),
        "version nibble '1' must fail"
    );
    assert!(
        !is_uuid_v4("f47ac10b-58cc-3372-a567-0e02b2c3d479"),
        "version nibble '3' must fail"
    );
    assert!(
        !is_uuid_v4("f47ac10b-58cc-5372-a567-0e02b2c3d479"),
        "version nibble '5' must fail"
    );
    // Verify a known-good v4 to be sure the helper accepts it.
    // 550e8400-e29b-41d4-a716-446655440000: third group '41d4' → version '4';
    // fourth group 'a716' → variant 'a' ∈ {8,9,a,b}.  This IS valid v4.
    assert!(
        is_uuid_v4("550e8400-e29b-41d4-a716-446655440000"),
        "550e8400-e29b-41d4-a716-446655440000 is a valid v4 UUID and must pass"
    );

    // Invalid: wrong variant nibble (must be 8, 9, a, b).
    assert!(
        !is_uuid_v4("f47ac10b-58cc-4372-0567-0e02b2c3d479"),
        "variant nibble '0' must fail"
    );
    assert!(
        !is_uuid_v4("f47ac10b-58cc-4372-c567-0e02b2c3d479"),
        "variant nibble 'c' must fail"
    );

    // Invalid: wrong number of segments.
    assert!(
        !is_uuid_v4("f47ac10b-58cc-4372-a567"),
        "short UUID must fail"
    );

    // Invalid: non-hex character.
    assert!(
        !is_uuid_v4("f47ac10b-58cc-4372-a567-0e02b2c3d4zz"),
        "non-hex char must fail"
    );

    // Invalid: wrong segment length.
    assert!(
        !is_uuid_v4("f47ac10-58cc-4372-a567-0e02b2c3d479"),
        "short first segment must fail"
    );
}

// ── Test 15: Dev mode token username is "dev", not empty string ───────────────

/// In dev mode, POST /jmap/auth/token must bind the issued token to the
/// canonical username "dev", not to an empty string.
///
/// Oracle: after issuing the token via HTTP, we call token_store.verify() on
/// the raw token directly.  verify() returns Some(username) on success.
/// An empty username would indicate the pre-fix bug; "dev" is the correct value.
/// This test does NOT read the issue_token implementation — it uses verify() as
/// an independent oracle.
#[tokio::test]
async fn dev_mode_token_username_is_dev_not_empty() {
    let (pool, _tmp) = make_mail_pool("t15").await;
    let token_store = Arc::new(TokenStore::new(Arc::new(pool)));
    let base = spawn_server(dev_app_state(Arc::clone(&token_store))).await;

    // Issue a token in dev mode (no credentials).
    let resp = reqwest::Client::new()
        .post(format!("{base}/jmap/auth/token"))
        .json(&serde_json::json!({"label": "dev-user-check"}))
        .send()
        .await
        .expect("request must succeed");
    assert_eq!(resp.status(), 201, "dev mode must issue a token");

    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    let raw_token = body["token"]
        .as_str()
        .expect("response must contain a token field")
        .to_string();

    // Verify the token and check the bound username via the store directly.
    let verified_username = token_store
        .verify(&raw_token)
        .await
        .expect("verify must not fail")
        .expect("token must be found and valid");

    assert_eq!(
        verified_username, "dev",
        "dev mode token must be bound to username 'dev', not '{verified_username}'"
    );
    assert!(
        !verified_username.is_empty(),
        "dev mode token username must not be empty"
    );
}
