//! Integration tests for port 465 implicit TLS (SMTPS) — RFC 8314 §3.
//!
//! These tests verify the EXTERNAL CONTRACT of SMTPS support:
//!
//! 1. `smtps_addr` absent in config → `smtps_addr` field is `None`.
//! 2. `smtps_addr` present in config → field parses as `Some(String)`.
//! 3. SMTPS listener binds: plain TCP connect succeeds (TCP handshake before TLS).
//! 4. TLS handshake completes BEFORE the SMTP "220" greeting arrives.
//! 5. Plain TCP (no TLS) to SMTPS port: no SMTP greeting bytes arrive.
//! 6. EHLO works over an SMTPS session (is_tls = true, session stays up).
//! 7. Port 25 is unaffected — still sends "220" without TLS (regression guard).
//!
//! External oracles consulted:
//!   - RFC 8314 §3: TLS negotiation must complete before any SMTP commands.
//!   - RFC 5321 §4.2: The "220" greeting is the first application-layer byte
//!     the server sends.
//!   - RFC 8446: TLS 1.3 handshake — ClientHello from client, ServerHello +
//!     EncryptedExtensions + Certificate + CertificateVerify + Finished from
//!     server, then Finished from client.  Only after all of this does the
//!     server write application-layer data.
//!
//! TLS client: rustls with a custom `ServerCertVerifier` that accepts the
//! server certificate by its exact DER bytes (pin-by-DER).  This is standard
//! integration-test practice: avoids a CA trust store, accepts only the cert
//! generated for this test run, and is clearly scoped to tests.
//!
//! Self-signed cert: generated fresh per test using `rcgen 0.13`.
//! PEM files are written to a `tempfile::tempdir` and passed to
//! `stoa_smtp::tls::build_tls_acceptor`, which is the same code path
//! used by the production server startup.

use std::{io, sync::Arc};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

/// Install the `ring` crypto provider as the process-level rustls default.
///
/// rustls 0.23 requires an explicit provider selection when multiple
/// providers are compiled in (ring and aws-lc-rs are both present as
/// transitive deps of sqlx's `runtime-tokio-rustls` feature).  This must be
/// called before any rustls operation in the test process.
///
/// Uses `std::sync::OnceLock` so the install is idempotent across tests.
fn install_crypto_provider() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap_or(()); // ok if another thread beat us to it
    });
}

use stoa_smtp::{
    config::{
        AuthConfig, Config, DatabaseConfig, DeliveryConfig, DnsResolver, LimitsConfig,
        ListenConfig, LogConfig, LogFormat, ReaderConfig, SieveAdminConfig, TlsConfig,
    },
    queue::NntpQueue,
    server::run_server,
    tls::{build_tls_acceptor, TlsAcceptor},
};

// ─── Certificate helpers ─────────────────────────────────────────────────────

/// Write the PEM strings to temp files and return their paths alongside the
/// cert DER bytes (needed for the pinned-cert client verifier).
///
/// Returns `(cert_der, tls_acceptor, _tempdir)`.  The caller must keep
/// `_tempdir` alive for the duration of the test; dropping it deletes the
/// temp files.
///
/// Installs the ring crypto provider on first call so rustls can function.
fn make_test_tls_pair() -> (Vec<u8>, TlsAcceptor, tempfile::TempDir) {
    install_crypto_provider();
    let cert_key = generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("rcgen self-signed cert generation must not fail");

    let cert_pem = cert_key.cert.pem();
    let key_pem = cert_key.key_pair.serialize_pem();
    let cert_der: Vec<u8> = cert_key.cert.der().to_vec();

    let dir = tempfile::tempdir().expect("tempdir for TLS test certs");
    let cert_path = dir.path().join("test.crt");
    let key_path = dir.path().join("test.key");

    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write test cert PEM");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write test key PEM");

    let acceptor = build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
        .expect("build_tls_acceptor must succeed for valid PEM cert+key");

    (cert_der, acceptor, dir)
}

/// Build a rustls `ClientConfig` that accepts exactly the certificate whose
/// DER bytes match `expected_der`.
///
/// This is a test-only verifier: it checks the raw cert bytes against a
/// pre-shared expectation instead of verifying against a CA trust store.
fn pinned_client_config(expected_der: Vec<u8>) -> Arc<ClientConfig> {
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier { expected_der }))
        .with_no_client_auth();
    Arc::new(client_config)
}

/// A `ServerCertVerifier` that accepts exactly one certificate by its DER bytes.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_der: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_der.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── Config and queue helpers ────────────────────────────────────────────────

/// Build a test `Config` with ephemeral port_25 and port_587.
/// `smtps_addr` is `None` — the SMTPS listener is passed directly to
/// `run_server` in tests, not derived from the config address string.
fn base_config() -> Arc<Config> {
    Arc::new(Config {
        hostname: "localhost".to_string(),
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
            command_timeout_secs: 30,
            max_connections: 10,
            sieve_eval_timeout_ms: 5_000,
        },
        log: LogConfig {
            level: "error".to_string(),
            format: LogFormat::Text,
        },
        reader: ReaderConfig::default(),
        delivery: DeliveryConfig::default(),
        database: DatabaseConfig::default(),
        sieve_admin: SieveAdminConfig::default(),
        dns_resolver: DnsResolver::System,
        auth: AuthConfig::default(),
        peer_whitelist: vec![],
        mta_sts: Default::default(),
        shutdown: Default::default(),
    })
}

/// Build an `NntpQueue` backed by a temporary directory.
fn test_queue() -> (Arc<NntpQueue>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir for NntpQueue");
    let q = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
    (q, dir)
}

// ─── Test 1: config field is present and defaults to None ─────────────────────

/// `smtps_addr` must exist as a field in `ListenConfig`.  When absent from
/// TOML it must deserialize as `None` — verified by constructing the config
/// struct directly and by parsing a TOML file.
///
/// This test does NOT start a server.
#[test]
fn config_smtps_addr_field_exists_and_defaults_to_none() {
    install_crypto_provider();
    let config = base_config();
    assert!(
        config.listen.smtps_addr.is_none(),
        "smtps_addr must be None when not set"
    );
}

// ─── Test 2: config parsing — smtps_addr round-trips through TOML ────────────

/// `smtps_addr` must be an optional TOML key in `[listen]`.  When absent the
/// field is None; when present it parses as Some(String).
#[test]
fn config_smtps_addr_parses_from_toml() {
    use std::io::Write;
    use stoa_smtp::config::Config;
    use tempfile::NamedTempFile;

    // Without smtps_addr — must parse with None.
    let toml_without = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(toml_without.as_bytes()).unwrap();
    let cfg = Config::from_file(f.path()).expect("config without smtps_addr must parse");
    assert!(
        cfg.listen.smtps_addr.is_none(),
        "smtps_addr must be None when absent from TOML"
    );

    // With smtps_addr — requires tls.cert_path and tls.key_path too (validation).
    // Use the same cert/key temp files from make_test_tls_pair to satisfy validation.
    let (_, _, cert_dir) = make_test_tls_pair();
    let cert_path = cert_dir.path().join("test.crt");
    let key_path = cert_dir.path().join("test.key");

    let toml_with = format!(
        r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
smtps_addr = "0.0.0.0:465"

[tls]
cert_path = "{}"
key_path = "{}"
"#,
        cert_path.display(),
        key_path.display()
    );
    let mut f2 = NamedTempFile::new().unwrap();
    f2.write_all(toml_with.as_bytes()).unwrap();
    let cfg2 = Config::from_file(f2.path()).expect("config with smtps_addr must parse");
    assert_eq!(
        cfg2.listen.smtps_addr.as_deref(),
        Some("0.0.0.0:465"),
        "smtps_addr must be Some(\"0.0.0.0:465\") when set in TOML"
    );
}

// ─── Test 3: SMTPS listener binds — TCP connect succeeds ─────────────────────

/// When a SMTPS listener is passed to `run_server`, plain TCP connect must
/// succeed (the TCP handshake completes before TLS starts).
#[tokio::test]
async fn smtps_listener_binds_and_accepts_tcp() {
    let (cert_der, tls_acceptor, _cert_dir) = make_test_tls_pair();
    let _ = cert_der; // not needed for this test

    let smtps_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtps_addr = smtps_listener.local_addr().unwrap();

    let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (nntp_queue, _dir) = test_queue();

    tokio::spawn(run_server(
        listener_25,
        listener_587,
        Some((smtps_listener, tls_acceptor)),
        None, // starttls_acceptor: use SMTPS, not STARTTLS on 25/587
        base_config(),
        nntp_queue,
        None,
        None,
    ));

    // Plain TCP connect succeeds — the OS accepts the connection before TLS.
    let result = tokio::net::TcpStream::connect(smtps_addr).await;
    assert!(
        result.is_ok(),
        "TCP connect to SMTPS listener must succeed; got: {:?}",
        result.err()
    );
}

// ─── Test 4: implicit TLS — greeting arrives only after TLS handshake ─────────

/// RFC 8314 §3 core contract: TLS negotiation completes BEFORE any SMTP bytes
/// are exchanged.  A TLS client connects, completes the handshake, and then
/// reads the "220" greeting as the first application-layer data.
#[tokio::test]
async fn smtps_greeting_arrives_after_tls_handshake() {
    let (cert_der, tls_acceptor, _cert_dir) = make_test_tls_pair();
    let client_config = pinned_client_config(cert_der);

    let smtps_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtps_addr = smtps_listener.local_addr().unwrap();

    let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (nntp_queue, _dir) = test_queue();

    tokio::spawn(run_server(
        listener_25,
        listener_587,
        Some((smtps_listener, tls_acceptor)),
        None, // starttls_acceptor: use SMTPS, not STARTTLS on 25/587
        base_config(),
        nntp_queue,
        None,
        None,
    ));

    // Connect via TLS.
    let tcp = tokio::net::TcpStream::connect(smtps_addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake must succeed with pinned cert");

    // After the TLS handshake, the first application-layer bytes must be
    // the SMTP greeting (RFC 5321 §4.2).
    let mut buf = [0u8; 512];
    let n = tls_stream.read(&mut buf).await.unwrap();
    let greeting = std::str::from_utf8(&buf[..n]).unwrap();

    assert!(
        greeting.starts_with("220 "),
        "expected SMTP 220 greeting over TLS, got: {greeting:?}"
    );

    // Send QUIT cleanly.
    tls_stream.write_all(b"QUIT\r\n").await.unwrap();
}

// ─── Test 5: plain TCP to SMTPS port — no SMTP greeting ──────────────────────

/// RFC 8314 §3: a plain TCP connection (no TLS) to the SMTPS port MUST NOT
/// receive an SMTP "220" greeting.  The server expects a ClientHello first;
/// a client that sends none will stall, get a TLS alert, or be disconnected —
/// but it must never see application-layer SMTP data.
///
/// We connect with raw TCP, wait briefly, and confirm that the first bytes
/// received (if any) are NOT an SMTP greeting.
#[tokio::test]
async fn plain_tcp_to_smtps_port_receives_no_smtp_greeting() {
    let (cert_der, tls_acceptor, _cert_dir) = make_test_tls_pair();
    let _ = cert_der;

    let smtps_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtps_addr = smtps_listener.local_addr().unwrap();

    let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (nntp_queue, _dir) = test_queue();

    tokio::spawn(run_server(
        listener_25,
        listener_587,
        Some((smtps_listener, tls_acceptor)),
        None, // starttls_acceptor: use SMTPS, not STARTTLS on 25/587
        base_config(),
        nntp_queue,
        None,
        None,
    ));

    // Connect with plain TCP — send no TLS ClientHello.
    let mut tcp = tokio::net::TcpStream::connect(smtps_addr).await.unwrap();

    // Read with a short timeout.  The server is waiting for a TLS ClientHello;
    // it will not send any SMTP bytes.  Expected outcomes:
    //   (a) timeout — server silently waits for ClientHello.
    //   (b) TLS alert bytes — server sends a TLS record (content type 0x15),
    //       NOT an SMTP greeting starting with '2' (0x32).
    //   (c) EOF / connection reset — server drops the plain connection.
    let mut buf = [0u8; 16];
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(500), tcp.read(&mut buf)).await;

    match result {
        Ok(Ok(0)) => {
            // EOF — server closed the connection.  Acceptable.
        }
        Ok(Ok(n)) => {
            // Bytes received — must NOT be an SMTP greeting.
            let first = buf[0];
            assert_ne!(
                first,
                b'2',
                "SMTPS port must not send an SMTP '2xx' greeting to a plain TCP client; \
                 got first byte 0x{first:02x}, full received: {:?}",
                &buf[..n]
            );
            // A TLS alert has content type 0x15 (21). A TLS handshake record
            // has content type 0x16 (22).  Either is correct behavior.
        }
        Ok(Err(e)) => {
            let is_acceptable = matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
            );
            assert!(
                is_acceptable,
                "unexpected IO error on plain-TCP to SMTPS port: {e}"
            );
        }
        Err(_timeout) => {
            // Server is waiting for ClientHello — no bytes sent.  Correct.
        }
    }
}

// ─── Test 6: session stability — EHLO works over SMTPS ───────────────────────

/// After a successful TLS handshake the SMTP session must be fully functional.
/// EHLO must return a "250" response listing the server's capabilities.
///
/// This exercises the `is_tls = true` code path end-to-end.
/// AUTH PLAIN availability over SMTPS is NOT tested here — that is bead 1c8.6.
#[tokio::test]
async fn smtps_session_responds_to_ehlo() {
    let (cert_der, tls_acceptor, _cert_dir) = make_test_tls_pair();
    let client_config = pinned_client_config(cert_der);

    let smtps_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtps_addr = smtps_listener.local_addr().unwrap();

    let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (nntp_queue, _dir) = test_queue();

    tokio::spawn(run_server(
        listener_25,
        listener_587,
        Some((smtps_listener, tls_acceptor)),
        None, // starttls_acceptor: use SMTPS, not STARTTLS on 25/587
        base_config(),
        nntp_queue,
        None,
        None,
    ));

    let tcp = tokio::net::TcpStream::connect(smtps_addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake must succeed");

    // Read 220 greeting.
    let mut buf = [0u8; 512];
    let n = tls_stream.read(&mut buf).await.unwrap();
    let greeting = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        greeting.starts_with("220 "),
        "expected 220 greeting: {greeting:?}"
    );

    // Send EHLO.
    tls_stream
        .write_all(b"EHLO testclient.example.com\r\n")
        .await
        .unwrap();

    // Read the multi-line EHLO response.  The final line begins with "250 "
    // (space, not dash).  Read in a loop until we have seen it.
    let mut ehlo_resp = String::new();
    let mut tmp = [0u8; 512];
    loop {
        let n = tls_stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "server closed connection unexpectedly during EHLO");
        ehlo_resp.push_str(std::str::from_utf8(&tmp[..n]).unwrap());
        // The last EHLO response line starts with "250 " (250 + space).
        if ehlo_resp.lines().any(|l| l.starts_with("250 ")) {
            break;
        }
    }

    // RFC 5321 §4.1.1.1: every EHLO response begins with "250".
    assert!(
        ehlo_resp.contains("250"),
        "expected 250 EHLO response over SMTPS, got: {ehlo_resp:?}"
    );

    // Send QUIT cleanly.
    tls_stream.write_all(b"QUIT\r\n").await.unwrap();
}

// ─── Test 7: port 25 regression ──────────────────────────────────────────────

/// Enabling SMTPS must not break the existing port_25 listener.
/// A standard non-TLS connect to port_25 must still receive "220" first.
#[tokio::test]
async fn port_25_unaffected_by_smtps_configuration() {
    let (cert_der, tls_acceptor, _cert_dir) = make_test_tls_pair();
    let _ = cert_der;

    let smtps_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_25 = listener_25.local_addr().unwrap();
    let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (nntp_queue, _dir) = test_queue();

    tokio::spawn(run_server(
        listener_25,
        listener_587,
        Some((smtps_listener, tls_acceptor)),
        None, // starttls_acceptor: use SMTPS, not STARTTLS on 25/587
        base_config(),
        nntp_queue,
        None,
        None,
    ));

    // Plain TCP to port_25 — no TLS needed.
    let mut client = tokio::net::TcpStream::connect(addr_25).await.unwrap();
    let mut buf = [0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    let greeting = std::str::from_utf8(&buf[..n]).unwrap();

    assert!(
        greeting.starts_with("220 "),
        "port_25 must still send 220 greeting without TLS when SMTPS is also configured: \
         got {greeting:?}"
    );

    client.write_all(b"QUIT\r\n").await.unwrap();
}
