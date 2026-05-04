//! Integration tests for SMTP AUTH PLAIN — bead stoa-1c8.6.
//!
//! External oracles:
//!   - RFC 4954 §4: AUTH command syntax and reply codes.
//!   - RFC 4616 §2: SASL PLAIN mechanism — NUL-delimited authzid/authcid/passwd.
//!   - RFC 4616 §4: Known test vector (tim / tanstaafltanstaafl).
//!   - RFC 5321 §4.2.2: Enhanced status codes (5.7.x, 5.5.x).
//!
//! RFC 4616 §4 known-good vector (independently verified with `printf` + `base64`):
//!   authzid  = ""  (empty)
//!   authcid  = "tim"
//!   passwd   = "tanstaafltanstaafl"
//!   wire     = NUL "tim" NUL "tanstaafltanstaafl"
//!   base64   = "AHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw="
//!
//! Verification: `printf '\x00tim\x00tanstaafltanstaafl' | base64`
//!               produces `AHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw=`
//!
//! COMPILATION NOTE: These tests require Agent I's implementation of 1c8.6
//! before they will compile.  Required changes to the production code:
//!
//!   1. `run_session` must accept `is_tls: bool` as its second argument
//!      (between `stream` and `peer_addr`).
//!   2. `Config` must have an `auth: stoa_auth::AuthConfig` field.
//!   3. `stoa_smtp::config` must re-export `AuthConfig` from
//!      `stoa_auth` (or the test imports it directly from that crate).
//!
//! These tests MUST NOT be modified to make them pass.  Fix the implementation.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use stoa_auth::{AuthConfig, UserCredential};
use stoa_smtp::{
    config::{
        Config, DatabaseConfig, DnsResolver, LimitsConfig, ListenConfig, LogConfig, LogFormat,
        ReaderConfig, SieveAdminConfig, TlsConfig,
    },
    queue::NntpQueue,
    session::run_session,
};

// ─── RFC 4616 §4 known test vector ───────────────────────────────────────────

/// SASL PLAIN base64 for authzid="" authcid="tim" passwd="tanstaafltanstaafl".
/// Independently verified: `printf '\x00tim\x00tanstaafltanstaafl' | base64`
const RFC4616_TIM_B64: &str = "AHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw=";

/// authzid="tim" authcid="tim" passwd="tanstaafltanstaafl" (non-empty authzid).
/// Independently verified: `printf 'tim\x00tim\x00tanstaafltanstaafl' | base64`
const RFC4616_TIM_AUTHZID_NONEMPTY_B64: &str = "dGltAHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw=";

// ─── Test infrastructure ──────────────────────────────────────────────────────

/// Build a `UserCredential` for "tim" / "tanstaafltanstaafl" with bcrypt cost 4.
///
/// Cost 4 is the minimum valid bcrypt cost — fast enough for test suites.
/// The hash is non-deterministic (random salt each call) but `bcrypt::verify`
/// accepts any valid hash of the same password.
fn make_tim_credential() -> UserCredential {
    let hash = bcrypt::hash("tanstaafltanstaafl", 4).expect("bcrypt::hash must not fail at cost 4");
    UserCredential {
        username: "tim".to_string(),
        password: hash,
    }
}

/// Build a test `Config`.
///
/// `tim_credential`: when `Some`, adds "tim" with password "tanstaafltanstaafl"
/// to `config.auth.users`.  When `None`, `auth` is default (dev-mode: empty).
fn test_config(tim_credential: Option<UserCredential>) -> Arc<Config> {
    let auth = match tim_credential {
        Some(cred) => AuthConfig {
            required: false,
            users: vec![cred],
            credential_file: None,
            client_certs: vec![],
            trusted_issuers: vec![],
            oidc_providers: vec![],
            operator_usernames: vec![],
        },
        None => AuthConfig::default(),
    };
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
        auth,
        peer_whitelist: vec![],
        mta_sts: Default::default(),
    })
}

/// Drive a session with configurable `is_tls`.
///
/// Creates an in-process TCP loopback pair, spawns `run_session` on the server
/// side with `is_tls`, sends `client_script`, shuts down the write half, and
/// collects the full server response string.
async fn drive(client_script: &[u8], is_tls: bool, config: Arc<Config>) -> String {
    let queue_dir = tempfile::tempdir().expect("tempdir");
    let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let config2 = Arc::clone(&config);
    let queue2 = Arc::clone(&nntp_queue);
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        let cred_store = Arc::new({
            let mut s = stoa_auth::CredentialStore::from_credentials(&config2.auth.users)
                .expect("test setup: valid bcrypt hashes in config");
            if let Some(ref p) = config2.auth.credential_file {
                let _ = s.merge_from_file(p);
            }
            s
        });
        run_session(
            stream,
            is_tls,
            false,
            peer.to_string(),
            config2,
            cred_store,
            queue2,
            None,
            std::sync::Arc::new(stoa_smtp::dns_cache::DnsCache::new()),
            None,
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

    response
}

// ─── Test 1: AUTH PLAIN on plaintext port (is_tls=false) → 534 5.7.9 ────────

/// RFC 4954 §4: A server MUST NOT permit authentication mechanisms that are
/// not sufficiently strong for the current connection.  AUTH PLAIN over a
/// non-TLS connection must be rejected with 534 5.7.9.
///
/// Even if the credentials would be valid, the transport is insecure and the
/// attempt must be denied before any credential bytes are evaluated.
#[tokio::test]
async fn auth_plain_on_plaintext_port_returns_534() {
    let config = test_config(Some(make_tim_credential()));

    let script = format!(
        "EHLO client.example.com\r\nAUTH PLAIN {}\r\nQUIT\r\n",
        RFC4616_TIM_B64
    );
    let response = drive(script.as_bytes(), false, config).await;

    assert!(
        response.contains("534"),
        "AUTH PLAIN on plaintext port must return 534; got:\n{response}"
    );
    assert!(
        response.contains("5.7.9"),
        "534 must carry enhanced status 5.7.9; got:\n{response}"
    );
}

// ─── Test 2: AUTH PLAIN on TLS port with valid credentials → 235 2.7.0 ───────

/// RFC 4954 §4: Successful authentication returns 235 2.7.0.
/// RFC 4616 §4 known-good vector: tim / tanstaafltanstaafl.
#[tokio::test]
async fn auth_plain_on_tls_port_valid_credentials_returns_235() {
    let config = test_config(Some(make_tim_credential()));

    let script = format!(
        "EHLO client.example.com\r\nAUTH PLAIN {}\r\nQUIT\r\n",
        RFC4616_TIM_B64
    );
    let response = drive(script.as_bytes(), true, config).await;

    assert!(
        response.contains("235"),
        "valid AUTH PLAIN on TLS port must return 235; got:\n{response}"
    );
    assert!(
        response.contains("2.7.0"),
        "235 must carry enhanced status 2.7.0; got:\n{response}"
    );
}

// ─── Test 3: AUTH PLAIN on TLS port with wrong password → 535 5.7.8 ─────────

/// RFC 4954 §4: Authentication failure returns 535 5.7.8
/// ("Authentication credentials invalid").
///
/// base64 of NUL "tim" NUL "wrongpassword":
///   `printf '\x00tim\x00wrongpassword' | base64` = AHRpbQB3cm9uZ3Bhc3N3b3Jk
#[tokio::test]
async fn auth_plain_on_tls_port_wrong_password_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nAUTH PLAIN AHRpbQB3cm9uZ3Bhc3N3b3Jk\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("535"),
        "wrong password must return 535; got:\n{response}"
    );
    assert!(
        response.contains("5.7.8"),
        "535 must carry enhanced status 5.7.8; got:\n{response}"
    );
}

// ─── Test 4: AUTH PLAIN with malformed base64 → 535 5.7.8 ────────────────────

/// RFC 4954 §4 (last paragraph): Decode failure is treated as authentication
/// failure → 535 5.7.8.  "!!!notbase64!!!" is not valid base64.
#[tokio::test]
async fn auth_plain_malformed_base64_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nAUTH PLAIN !!!notbase64!!!\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("535"),
        "malformed base64 must return 535; got:\n{response}"
    );
    assert!(
        response.contains("5.7.8"),
        "535 must carry enhanced status 5.7.8; got:\n{response}"
    );
}

// ─── Test 5: AUTH PLAIN with invalid NUL-split format → 535 5.7.8 ────────────

/// RFC 4616 §2: The SASL PLAIN message is `authzid NUL authcid NUL passwd`.
/// A decoded payload that contains no NUL bytes is structurally malformed.
///
/// base64 of "notanullseparatedstring" (no NULs):
///   `printf 'notanullseparatedstring' | base64` = bm90YW51bGxzZXBhcmF0ZWRzdHJpbmc=
#[tokio::test]
async fn auth_plain_invalid_nul_format_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script =
        b"EHLO client.example.com\r\nAUTH PLAIN bm90YW51bGxzZXBhcmF0ZWRzdHJpbmc=\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("535"),
        "no NUL separators must return 535; got:\n{response}"
    );
    assert!(
        response.contains("5.7.8"),
        "535 must carry enhanced status 5.7.8; got:\n{response}"
    );
}

// ─── Test 6: EHLO on plaintext port does NOT advertise AUTH ──────────────────

/// RFC 4954 §3: The server SHOULD NOT advertise authentication mechanisms
/// that cannot succeed on the current connection.  On a non-TLS connection
/// no AUTH keyword must appear in the EHLO response.
#[tokio::test]
async fn ehlo_on_plaintext_port_does_not_advertise_auth() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nQUIT\r\n";
    let response = drive(script, false, config).await;

    assert!(
        response.contains("250"),
        "expected 250 EHLO response; got:\n{response}"
    );
    assert!(
        !response.contains("AUTH"),
        "AUTH must not appear in EHLO on plaintext port; got:\n{response}"
    );
}

// ─── Test 7: EHLO on TLS port advertises AUTH PLAIN ──────────────────────────

/// RFC 4954 §3: When AUTH is available the server MUST include
/// "AUTH mechanism-list" in EHLO.  On a TLS session with credentials
/// configured, "AUTH PLAIN" must appear in the EHLO response.
#[tokio::test]
async fn ehlo_on_tls_port_advertises_auth_plain() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("250"),
        "expected 250 EHLO response; got:\n{response}"
    );
    assert!(
        response.contains("AUTH PLAIN"),
        "AUTH PLAIN must appear in EHLO on TLS port when credentials configured; \
         got:\n{response}"
    );
}

// ─── Test 8: AUTH twice in same session → 503 5.5.1 ──────────────────────────

/// RFC 4954 §4: After successful AUTH it is a protocol error to issue AUTH
/// again in the same session.  The server must return 503 5.5.1
/// ("Bad sequence of commands").
#[tokio::test]
async fn auth_plain_twice_returns_503() {
    let config = test_config(Some(make_tim_credential()));

    let script = format!(
        "EHLO client.example.com\r\n\
         AUTH PLAIN {0}\r\n\
         AUTH PLAIN {0}\r\n\
         QUIT\r\n",
        RFC4616_TIM_B64
    );
    let response = drive(script.as_bytes(), true, config).await;

    assert!(
        response.contains("235"),
        "first AUTH PLAIN must return 235; got:\n{response}"
    );
    assert!(
        response.contains("503"),
        "second AUTH in same session must return 503; got:\n{response}"
    );
    assert!(
        response.contains("5.5.1"),
        "503 must carry enhanced status 5.5.1; got:\n{response}"
    );
}

// ─── Test 9: AUTH with unknown mechanism → 504 5.5.4 ─────────────────────────

/// RFC 4954 §4: An AUTH command naming an unrecognised mechanism returns
/// 504 5.5.4 ("Command parameter not implemented").
#[tokio::test]
async fn auth_unknown_mechanism_returns_504() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nAUTH GSSAPI sometoken\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("504"),
        "unknown mechanism must return 504; got:\n{response}"
    );
    assert!(
        response.contains("5.5.4"),
        "504 must carry enhanced status 5.5.4; got:\n{response}"
    );
}

// ─── Test 10: Non-empty authzid → 535 5.7.8 ──────────────────────────────────

/// RFC 4616 §2: The authzid is the authorisation identity.  When it is
/// non-empty the client is requesting identity substitution ("act as authzid").
/// This server does not implement identity substitution → 535 5.7.8.
///
/// Wire: "tim\0tim\0tanstaafltanstaafl"
///   (authzid="tim", authcid="tim", passwd="tanstaafltanstaafl")
/// Independently verified:
///   `printf 'tim\x00tim\x00tanstaafltanstaafl' | base64`
///   = dGltAHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw=
#[tokio::test]
async fn auth_plain_nonempty_authzid_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script = format!(
        "EHLO client.example.com\r\nAUTH PLAIN {}\r\nQUIT\r\n",
        RFC4616_TIM_AUTHZID_NONEMPTY_B64
    );
    let response = drive(script.as_bytes(), true, config).await;

    assert!(
        response.contains("535"),
        "non-empty authzid must return 535; got:\n{response}"
    );
    assert!(
        response.contains("5.7.8"),
        "535 must carry enhanced status 5.7.8; got:\n{response}"
    );
}

// ─── Test 11: RFC 4616 §4 canonical vector test ───────────────────────────────

/// This is the primary oracle test.  It exercises the exact test vector
/// from RFC 4616 §4 and asserts 235 2.7.0.
///
/// If this test fails, the SASL PLAIN implementation does not conform to
/// RFC 4616 regardless of whether other tests pass.
///
/// authzid=""  authcid="tim"  passwd="tanstaafltanstaafl"
/// base64="AHRpbQB0YW5zdGFhZmx0YW5zdGFhZmw="
#[tokio::test]
async fn rfc4616_s4_known_vector_accepted() {
    let config = test_config(Some(make_tim_credential()));

    let script = format!(
        "EHLO client.example.com\r\nAUTH PLAIN {}\r\nQUIT\r\n",
        RFC4616_TIM_B64
    );
    let response = drive(script.as_bytes(), true, config).await;

    assert!(
        response.contains("235"),
        "RFC 4616 §4 known test vector MUST return 235 2.7.0; got:\n{response}"
    );
    assert!(
        response.contains("2.7.0"),
        "235 MUST carry enhanced status 2.7.0; got:\n{response}"
    );
}

// ─── SASL PLAIN decode contract tests ────────────────────────────────────────
//
// These tests verify specific edge cases in NUL-split parsing, exercised
// through the session layer with known base64 inputs.

/// One NUL byte only → authzid="", authcid="", passwd="" which has an empty
/// authcid.  RFC 4616 §2 does not permit an empty authcid → 535 5.7.8.
/// base64("\0") = "AA=="
#[tokio::test]
async fn sasl_plain_single_nul_empty_authcid_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nAUTH PLAIN AA==\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("535"),
        "single-NUL PLAIN payload (empty authcid) must return 535; got:\n{response}"
    );
}

/// Empty argument to AUTH PLAIN (space then CRLF, no base64 token).
/// This is a decode failure → 535 5.7.8.
#[tokio::test]
async fn sasl_plain_empty_argument_returns_535() {
    let config = test_config(Some(make_tim_credential()));

    let script = b"EHLO client.example.com\r\nAUTH PLAIN \r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        response.contains("535"),
        "empty AUTH PLAIN argument must return 535; got:\n{response}"
    );
}

// ─── No-credentials-configured edge cases ────────────────────────────────────

/// When no credentials are configured (`config.auth` is default / dev-mode),
/// AUTH PLAIN must not be advertised in EHLO even on a TLS session, because
/// there are no users to authenticate against.
#[tokio::test]
async fn ehlo_tls_no_credentials_configured_no_auth_advertised() {
    let config = test_config(None);

    let script = b"EHLO client.example.com\r\nQUIT\r\n";
    let response = drive(script, true, config).await;

    assert!(
        !response.contains("AUTH"),
        "AUTH must not appear in EHLO when no credentials configured; got:\n{response}"
    );
}
