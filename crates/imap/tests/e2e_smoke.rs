//! End-to-end smoke test: raw TCP client connects to the session loop.
//!
//! Plain-connection tests (no TLS) exercise CAPABILITY/NOOP/LOGOUT.
//! Authenticated tests use a TLS session with a self-signed cert generated at
//! test time (rcgen) and a client-side `ServerCertVerifier` that accepts it.
//! AUTH=PLAIN with an inline initial response is used to reach Authenticated
//! state, which is required for ENABLE and NAMESPACE (RFC 5161, RFC 2342).

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use stoa_imap::{
    config::{
        AuthConfig, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, TlsConfig,
        UserCredential,
    },
    session::{run_session_plain, run_session_tls},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Build an in-memory pool with the IMAP schema applied.
async fn test_pool() -> Arc<sqlx::SqlitePool> {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory pool");
    sqlx::query(
        "CREATE TABLE imap_uid_validity (
            mailbox     TEXT    NOT NULL PRIMARY KEY,
            uidvalidity INTEGER NOT NULL,
            next_uid    INTEGER NOT NULL DEFAULT 1
        )",
    )
    .execute(&pool)
    .await
    .expect("create table");
    Arc::new(pool)
}

fn test_config() -> Arc<stoa_imap::config::Config> {
    Arc::new(stoa_imap::config::Config {
        listen: ListenConfig {
            addr: "127.0.0.1:0".into(),
            tls_addr: None,
        },
        database: DatabaseConfig {
            path: ":memory:".into(),
        },
        limits: LimitsConfig::default(),
        auth: AuthConfig {
            mechanisms: vec!["PLAIN".into(), "LOGIN".into()],
            users: vec![UserCredential {
                username: "testuser".into(),
                password: bcrypt::hash("testpass", 4).expect("bcrypt hash"),
            }],
            credential_file: None,
            required: false,
        },
        tls: TlsConfig {
            cert_path: None,
            key_path: None,
        },
        log: LogConfig::default(),
    })
}

fn test_store(config: &stoa_imap::config::Config) -> Arc<stoa_auth::CredentialStore> {
    Arc::new(
        stoa_auth::CredentialStore::from_credentials(&config.auth.users)
            .expect("test setup: valid bcrypt hashes in config"),
    )
}

/// Read one IMAP line, stripping CRLF.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read line");
    line.trim_end_matches(['\r', '\n']).to_owned()
}

#[tokio::test]
async fn smoke_greeting_capability_noop_logout() {
    let pool = test_pool().await;
    let config = test_config();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // Spawn the server session; it handles exactly one connection.
    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(stream, peer, srv_config, srv_pool, srv_store, None).await;
    });

    // Connect a raw client.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Greeting.
    let greeting = read_line(&mut rd).await;
    assert!(
        greeting.starts_with("* OK"),
        "expected greeting, got: {greeting}"
    );

    // CAPABILITY.
    wr.write_all(b"T01 CAPABILITY\r\n").await.expect("write");
    let cap_data = read_line(&mut rd).await;
    assert!(cap_data.starts_with("* CAPABILITY"), "got: {cap_data}");
    // LOGINDISABLED is omitted until STARTTLS is wired (RFC 3501 §6.2.1 requires
    // STARTTLS to be advertised alongside LOGINDISABLED).
    assert!(
        !cap_data.contains("AUTH=PLAIN"),
        "plain session must not advertise AUTH=PLAIN, got: {cap_data}"
    );
    assert!(
        cap_data.contains("IMAP4rev2"),
        "IMAP4rev2 must always be advertised, got: {cap_data}"
    );
    assert!(
        cap_data.contains("NAMESPACE"),
        "NAMESPACE must always be advertised, got: {cap_data}"
    );
    assert!(
        cap_data.contains("ENABLE"),
        "ENABLE must always be advertised, got: {cap_data}"
    );
    assert!(
        cap_data.contains("UNSELECT"),
        "UNSELECT must always be advertised, got: {cap_data}"
    );
    let cap_ok = read_line(&mut rd).await;
    assert!(cap_ok.starts_with("T01 OK"), "got: {cap_ok}");

    // NOOP.
    wr.write_all(b"T02 NOOP\r\n").await.expect("write");
    let noop_ok = read_line(&mut rd).await;
    assert!(noop_ok.starts_with("T02 OK"), "got: {noop_ok}");

    // LOGOUT.
    wr.write_all(b"T03 LOGOUT\r\n").await.expect("write");
    let bye = read_line(&mut rd).await;
    assert!(bye.starts_with("* BYE"), "got: {bye}");
    let logout_ok = read_line(&mut rd).await;
    assert!(logout_ok.starts_with("T03 OK"), "got: {logout_ok}");
}

#[tokio::test]
async fn smoke_unknown_command_returns_bad() {
    let pool = test_pool().await;
    let config = test_config();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(stream, peer, srv_config, srv_pool, srv_store, None).await;
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let _ = read_line(&mut rd).await;

    // COPY (unimplemented) → BAD.
    wr.write_all(b"U01 COPY 1:* INBOX\r\n")
        .await
        .expect("write");
    let bad = read_line(&mut rd).await;
    assert!(
        bad.starts_with("U01 BAD"),
        "expected BAD for unimplemented command, got: {bad}"
    );

    // Clean shutdown.
    wr.write_all(b"U02 LOGOUT\r\n").await.expect("write");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

// ── TLS helper types ──────────────────────────────────────────────────────────

/// A `ServerCertVerifier` that accepts any certificate.
///
/// Only used in test TLS sessions against a locally-generated self-signed cert
/// where the server and client run in the same process.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
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
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `TlsAcceptor` + `TlsConnector` pair backed by a fresh self-signed
/// cert generated with rcgen.
///
/// The connector uses `AcceptAnyCert` so it accepts the self-signed cert without
/// any system trust store. Both sides use the ring crypto provider.
fn make_test_tls_pair() -> (TlsAcceptor, TlsConnector) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Generate ephemeral self-signed cert.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("rcgen cert generation must succeed");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .expect("rcgen key must be a valid PrivateKeyDer");

    // Server config.
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server TLS config must build");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    // Client config — accepts any certificate.
    let client_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    (acceptor, connector)
}

/// Authenticate over a TLS connection using AUTH=PLAIN with an inline initial
/// response.
///
/// PLAIN payload (RFC 4616): `\0authcid\0passwd`
/// base64("\x00testuser\x00testpass") = "AHRlc3R1c2VyAHRlc3RwYXNz"
///
/// Sends the AUTHENTICATE command, reads the tagged OK, and returns.
/// Panics on unexpected responses.
async fn authenticate_plain<R, W>(tag: &str, rd: &mut R, wr: &mut W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // AUTH=PLAIN with inline initial response — one round trip, no continuation.
    let cmd = format!("{tag} AUTHENTICATE PLAIN AHRlc3R1c2VyAHRlc3RwYXNz\r\n");
    wr.write_all(cmd.as_bytes())
        .await
        .expect("write AUTHENTICATE");
    let auth_ok = read_line(rd).await;
    assert!(
        auth_ok.starts_with(&format!("{tag} OK")),
        "AUTHENTICATE PLAIN must succeed, got: {auth_ok}"
    );
}

// ── Authenticated TLS smoke tests ─────────────────────────────────────────────

/// RFC 9051 §6.3.2: ENABLE IMAP4rev2 over an authenticated TLS session must
/// produce `* ENABLED IMAP4rev2` followed by a tagged OK.
#[tokio::test]
async fn smoke_enable_imap4rev2() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        run_session_tls(tls, peer, srv_config, srv_pool, srv_store).await;
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // Authenticate.
    authenticate_plain("A001", &mut rd, &mut wr).await;

    // ENABLE IMAP4rev2.
    wr.write_all(b"A002 ENABLE IMAP4rev2\r\n")
        .await
        .expect("write ENABLE");
    let enabled = read_line(&mut rd).await;
    assert!(
        enabled.starts_with("* ENABLED"),
        "expected untagged ENABLED, got: {enabled}"
    );
    assert!(
        enabled.contains("IMAP4rev2"),
        "IMAP4rev2 must appear in ENABLED response, got: {enabled}"
    );
    let enable_ok = read_line(&mut rd).await;
    assert!(
        enable_ok.starts_with("A002 OK"),
        "expected tagged OK for ENABLE, got: {enable_ok}"
    );

    // Clean shutdown.
    wr.write_all(b"A003 LOGOUT\r\n")
        .await
        .expect("write LOGOUT");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

/// RFC 2342 §5: NAMESPACE over an authenticated TLS session must produce
/// `* NAMESPACE (("" ".")) NIL NIL` followed by a tagged OK.
#[tokio::test]
async fn smoke_namespace() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        run_session_tls(tls, peer, srv_config, srv_pool, srv_store).await;
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // Authenticate.
    authenticate_plain("N001", &mut rd, &mut wr).await;

    // NAMESPACE.
    wr.write_all(b"N002 NAMESPACE\r\n")
        .await
        .expect("write NAMESPACE");
    let ns_data = read_line(&mut rd).await;
    assert!(
        ns_data.starts_with("* NAMESPACE"),
        "expected untagged NAMESPACE, got: {ns_data}"
    );
    // RFC 2342 §5: other-users and shared namespace lists must be NIL.
    // Wire: * NAMESPACE (("" ".")) NIL NIL
    let nil_count = ns_data.matches("NIL").count();
    assert!(
        nil_count >= 2,
        "NAMESPACE response must contain at least two NIL tokens (other, shared), got: {ns_data}"
    );
    let ns_ok = read_line(&mut rd).await;
    assert!(
        ns_ok.starts_with("N002 OK"),
        "expected tagged OK for NAMESPACE, got: {ns_ok}"
    );

    // Clean shutdown.
    wr.write_all(b"N003 LOGOUT\r\n")
        .await
        .expect("write LOGOUT");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

/// RFC 5161 §3: a second ENABLE IMAP4rev2 on the same session must produce
/// `* ENABLED` with an empty capability list (IMAP4rev2 already active).
#[tokio::test]
async fn smoke_enable_imap4rev2_is_idempotent() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        run_session_tls(tls, peer, srv_config, srv_pool, srv_store).await;
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // Authenticate.
    authenticate_plain("E001", &mut rd, &mut wr).await;

    // First ENABLE IMAP4rev2 — must list IMAP4rev2 as newly enabled.
    wr.write_all(b"E002 ENABLE IMAP4rev2\r\n")
        .await
        .expect("write first ENABLE");
    let first_enabled = read_line(&mut rd).await;
    assert!(
        first_enabled.starts_with("* ENABLED"),
        "expected untagged ENABLED, got: {first_enabled}"
    );
    assert!(
        first_enabled.contains("IMAP4rev2"),
        "first ENABLE must list IMAP4rev2 as newly enabled (RFC 5161 §3), got: {first_enabled}"
    );
    let first_ok = read_line(&mut rd).await;
    assert!(
        first_ok.starts_with("E002 OK"),
        "expected tagged OK for first ENABLE, got: {first_ok}"
    );

    // Second ENABLE IMAP4rev2 — already active; ENABLED list must be empty.
    wr.write_all(b"E003 ENABLE IMAP4rev2\r\n")
        .await
        .expect("write second ENABLE");
    let second_enabled = read_line(&mut rd).await;
    assert!(
        second_enabled.starts_with("* ENABLED"),
        "expected untagged ENABLED, got: {second_enabled}"
    );
    assert!(
        !second_enabled.contains("IMAP4rev2"),
        "second ENABLE must NOT list IMAP4rev2 (already active, RFC 5161 §3), got: {second_enabled}"
    );
    let second_ok = read_line(&mut rd).await;
    assert!(
        second_ok.starts_with("E003 OK"),
        "expected tagged OK for second ENABLE, got: {second_ok}"
    );

    // Clean shutdown.
    wr.write_all(b"E004 LOGOUT\r\n")
        .await
        .expect("write LOGOUT");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

// ── STARTTLS tests ────────────────────────────────────────────────────────────

/// RFC 9051 §6.2.1: on a plain connection with a TLS acceptor wired in,
/// STARTTLS must:
///   1. appear in the CAPABILITY response
///   2. respond `tag OK Begin TLS negotiation now`
///   3. complete a TLS handshake on the same socket
///   4. allow AUTH=PLAIN on the upgraded session
///
/// Oracle: RFC 9051 §6.2.1, RFC 3501 §6.2.1.
#[tokio::test]
async fn starttls_upgrade_succeeds() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    let srv_acceptor = Arc::new(acceptor);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(
            stream,
            peer,
            srv_config,
            srv_pool,
            srv_store,
            Some(srv_acceptor),
        )
        .await;
    });

    // Connect plain TCP.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // CAPABILITY before upgrade — STARTTLS must be present.
    wr.write_all(b"S01 CAPABILITY\r\n").await.expect("write");
    let cap_data = read_line(&mut rd).await;
    assert!(
        cap_data.contains("STARTTLS"),
        "STARTTLS must be advertised on plain connection, got: {cap_data}"
    );
    assert!(
        !cap_data.contains("AUTH=PLAIN"),
        "AUTH=PLAIN must NOT be advertised before STARTTLS, got: {cap_data}"
    );
    let cap_ok = read_line(&mut rd).await;
    assert!(cap_ok.starts_with("S01 OK"), "got: {cap_ok}");

    // STARTTLS command.
    wr.write_all(b"S02 STARTTLS\r\n").await.expect("write");
    let starttls_ok = read_line(&mut rd).await;
    assert!(
        starttls_ok.starts_with("S02 OK"),
        "STARTTLS must respond OK, got: {starttls_ok}"
    );
    assert!(
        starttls_ok.contains("Begin TLS"),
        "OK text must mention TLS negotiation, got: {starttls_ok}"
    );

    // Perform TLS handshake — reassemble the OwnedRead/WriteHalves into a
    // TcpStream by connecting a fresh socket through the connector.
    // Because we split the TcpStream into halves, we cannot unsplit here.
    // Instead: reconnect through the TLS connector.
    //
    // The server session is now waiting for TLS; the TCP socket is the one
    // we already have.  We must upgrade it in place by wrapping the reunited
    // halves.  tokio::net::tcp::OwnedReadHalf + OwnedWriteHalf do not expose
    // reunite without going through the original TcpStream — so we use
    // tokio::io::join to create a combined stream and wrap it in TlsConnector.
    //
    // However, tokio_rustls::TlsConnector::connect requires AsyncRead + AsyncWrite,
    // which the joined stream satisfies.
    let joined = tokio::io::join(rd, wr);
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, joined)
        .await
        .expect("TLS handshake must succeed after STARTTLS OK");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Post-upgrade CAPABILITY — AUTH=PLAIN must now be present.
    wr.write_all(b"S03 CAPABILITY\r\n").await.expect("write");
    let cap2_data = read_line(&mut rd).await;
    assert!(
        cap2_data.contains("AUTH=PLAIN"),
        "AUTH=PLAIN must be advertised after STARTTLS upgrade, got: {cap2_data}"
    );
    assert!(
        !cap2_data.contains("STARTTLS"),
        "STARTTLS must NOT be advertised after upgrade, got: {cap2_data}"
    );
    let cap2_ok = read_line(&mut rd).await;
    assert!(cap2_ok.starts_with("S03 OK"), "got: {cap2_ok}");

    // Authenticate to confirm the session is fully functional post-upgrade.
    authenticate_plain("S04", &mut rd, &mut wr).await;

    // Clean shutdown.
    wr.write_all(b"S05 LOGOUT\r\n").await.expect("write");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

/// RFC 9051 §6.2.1: on an implicit-TLS (IMAPS) connection, STARTTLS must
/// be rejected with `BAD Already in TLS`.
///
/// Oracle: RFC 9051 §6.2.1 — "An IMAP server that is in the Selected state
/// MUST NOT accept a STARTTLS command."  The standard also forbids STARTTLS
/// when already in TLS.
#[tokio::test]
async fn starttls_rejected_when_already_tls() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        run_session_tls(tls, peer, srv_config, srv_pool, srv_store).await;
    });

    // Connect via implicit TLS.
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // STARTTLS on an already-TLS session must return BAD.
    wr.write_all(b"T01 STARTTLS\r\n").await.expect("write");
    let bad = read_line(&mut rd).await;
    assert!(
        bad.starts_with("T01 BAD"),
        "STARTTLS on implicit-TLS must return BAD, got: {bad}"
    );
    assert!(
        bad.to_ascii_uppercase().contains("ALREADY"),
        "BAD response must mention already-in-TLS, got: {bad}"
    );

    // Clean shutdown.
    wr.write_all(b"T02 LOGOUT\r\n").await.expect("write");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}

/// RFC 9051 §6.2.1: a second STARTTLS on the same session (after a
/// successful upgrade) must be rejected with `BAD Already in TLS`.
///
/// Oracle: RFC 9051 §6.2.1 — the server resets state after STARTTLS; the
/// upgraded session is in TLS and a further STARTTLS is forbidden.
#[tokio::test]
async fn double_starttls_rejected() {
    let pool = test_pool().await;
    let config = test_config();
    let (acceptor, connector) = make_test_tls_pair();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    let srv_store = test_store(&config);
    let srv_acceptor = Arc::new(acceptor);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(
            stream,
            peer,
            srv_config,
            srv_pool,
            srv_store,
            Some(srv_acceptor),
        )
        .await;
    });

    // Plain connection.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Greeting.
    let _ = read_line(&mut rd).await;

    // First STARTTLS — must succeed.
    wr.write_all(b"D01 STARTTLS\r\n").await.expect("write");
    let ok = read_line(&mut rd).await;
    assert!(
        ok.starts_with("D01 OK"),
        "first STARTTLS must succeed, got: {ok}"
    );

    // Upgrade.
    let joined = tokio::io::join(rd, wr);
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls = connector
        .connect(server_name, joined)
        .await
        .expect("TLS handshake");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut rd = BufReader::new(rd);

    // Second STARTTLS on the upgraded session must return BAD.
    wr.write_all(b"D02 STARTTLS\r\n").await.expect("write");
    let bad = read_line(&mut rd).await;
    assert!(
        bad.starts_with("D02 BAD"),
        "second STARTTLS must return BAD, got: {bad}"
    );

    // Clean shutdown.
    wr.write_all(b"D03 LOGOUT\r\n").await.expect("write");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}
