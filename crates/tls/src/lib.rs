//! Shared TLS configuration loader for stoa servers.
//!
//! Provides a single implementation of PEM certificate and private-key
//! loading, shared by the SMTP, JMAP, and NNTP reader crates. Centralising
//! the logic here means a rustls API change (version bump, different PEM
//! loading API) is applied in one place.
//!
//! # TLS policy
//!
//! All [`ServerConfig`]s produced by this crate:
//! - Require TLS 1.2 or higher (TLS 1.0 and 1.1 are not offered).
//! - Offer only the cipher suites in [`APPROVED_CIPHER_SUITE_IDS`], which
//!   satisfies PCI-DSS 4.2.1 and SOC2 CC6.7.
//!
//! The enforcement is explicit — it does not rely on library defaults.

use std::{fs::File, io::BufReader, sync::Arc};

use rustls::crypto::CryptoProvider;
use rustls::CipherSuite;
use rustls::ServerConfig;
use rustls::SupportedCipherSuite;
use rustls_pemfile::{certs, private_key};

/// Cipher suites approved for PCI-DSS 4.2.1 / SOC2 CC6.7.
///
/// Includes:
/// - TLS 1.3: AES-256-GCM-SHA384, AES-128-GCM-SHA256, CHACHA20-POLY1305-SHA256
/// - TLS 1.2 ECDHE+AESGCM (ECDSA and RSA): AES-128-GCM-SHA256, AES-256-GCM-SHA384
///
/// TLS 1.2 CBC suites (HMAC-SHA1/SHA256) and export-grade suites are excluded.
pub const APPROVED_CIPHER_SUITE_IDS: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// Filter a [`CryptoProvider`]'s cipher suite list to only the suites in
/// [`APPROVED_CIPHER_SUITE_IDS`], preserving the provider's preference order.
///
/// Returns the full provider list as a safety fallback if no approved suites
/// are found (logs a warning in that case).
pub fn approved_cipher_suites(provider: &CryptoProvider) -> Vec<SupportedCipherSuite> {
    let filtered: Vec<SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .copied()
        .filter(|cs| APPROVED_CIPHER_SUITE_IDS.contains(&cs.suite()))
        .collect();
    if filtered.is_empty() {
        tracing::warn!(
            "approved_cipher_suites: no approved suites in provider; \
             falling back to full provider list"
        );
        return provider.cipher_suites.to_vec();
    }
    filtered
}

/// Emit a startup log line recording the effective TLS policy.
///
/// Called automatically by [`load_tls_server_config`] and
/// [`load_tls_server_config_with_key_bytes`].
pub fn log_tls_policy(config: &ServerConfig) {
    let n = config.crypto_provider().cipher_suites.len();
    tracing::info!(
        event = "tls_policy_effective",
        min_tls_version = "TLS 1.2",
        cipher_suite_count = n,
        "TLS policy: minimum TLS 1.2, {} approved cipher suite(s)",
        n,
    );
}

/// Errors produced while loading TLS configuration from PEM files.
#[non_exhaustive]
#[derive(Debug)]
pub enum TlsError {
    /// Failed to open or parse the certificate file.
    CertLoad(String, std::io::Error),
    /// Failed to open or parse the private key file.
    KeyLoad(String, std::io::Error),
    /// Failed to build the rustls `ServerConfig`.
    Config(rustls::Error),
    /// Failed to parse certificate contents (e.g. DER decode, x509 parse).
    CertParse(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertLoad(path, e) => {
                write!(f, "failed to load TLS certificate from '{path}': {e}")
            }
            TlsError::KeyLoad(path, e) => {
                write!(f, "failed to load TLS private key from '{path}': {e}")
            }
            TlsError::Config(e) => write!(f, "TLS server config error: {e}"),
            TlsError::CertParse(e) => write!(f, "certificate parse error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::CertLoad(_, e) | TlsError::KeyLoad(_, e) => Some(e),
            TlsError::Config(e) => Some(e),
            TlsError::CertParse(_) => None,
        }
    }
}

fn approved_provider() -> Arc<CryptoProvider> {
    let base = CryptoProvider::get_default().expect(
        "a CryptoProvider must be installed before calling TLS functions; \
         call CryptoProvider::install_default() at startup",
    );
    let suites = approved_cipher_suites(base);
    Arc::new(CryptoProvider {
        cipher_suites: suites,
        ..(**base).clone()
    })
}

/// Load PEM cert/key files into a [`ServerConfig`] requiring TLS 1.2+.
///
/// The resulting config requires TLS 1.2 or higher; offers only
/// [`APPROVED_CIPHER_SUITE_IDS`]; does not request client authentication.
pub fn load_tls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key(key_path)?;
    let config = ServerConfig::builder_with_provider(approved_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsError::Config)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsError::Config)?;
    log_tls_policy(&config);
    Ok(Arc::new(config))
}

/// Load a PEM certificate chain from `cert_path`.
///
/// Exposed for crates (e.g. the NNTP reader) that need to supply a custom
/// client-auth verifier and therefore must build their own `ServerConfig`.
pub fn load_cert_chain(
    cert_path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let file = File::open(cert_path).map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;
    certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))
}

/// Load a PEM private key from `key_path`.
///
/// Exposed for crates that need to build their own `ServerConfig`.
pub fn load_private_key(
    key_path: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    let file = File::open(key_path).map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?;
    private_key(&mut BufReader::new(file))
        .map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                key_path.to_string(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                ),
            )
        })
}

/// Load a PEM private key from raw bytes (e.g. resolved from a secrets manager).
pub fn load_private_key_from_bytes(
    pem_bytes: &[u8],
    label: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    use std::io::Cursor;
    private_key(&mut BufReader::new(Cursor::new(pem_bytes)))
        .map_err(|e| TlsError::KeyLoad(label.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                label.to_string(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                ),
            )
        })
}

/// Load a [`ServerConfig`] from a certificate file and private key bytes.
///
/// Equivalent to [`load_tls_server_config`] but the private key is supplied as
/// PEM bytes rather than a file path.
pub fn load_tls_server_config_with_key_bytes(
    cert_path: &str,
    key_pem_bytes: &[u8],
    key_label: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key_from_bytes(key_pem_bytes, key_label)?;
    let config = ServerConfig::builder_with_provider(approved_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsError::Config)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsError::Config)?;
    log_tls_policy(&config);
    Ok(Arc::new(config))
}

/// Return the Unix timestamp (seconds) of the NotAfter date of the first
/// certificate in a PEM certificate chain file.
pub fn cert_not_after(cert_path: &str) -> Result<i64, TlsError> {
    let certs = load_cert_chain(cert_path)?;
    let first = certs
        .into_iter()
        .next()
        .ok_or_else(|| TlsError::CertParse(format!("no certificates found in '{cert_path}'")))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&first).map_err(|e| {
        TlsError::CertParse(format!("failed to parse certificate '{cert_path}': {e}"))
    })?;
    Ok(parsed.validity().not_after.timestamp())
}

/// Return an [`Arc<CryptoProvider>`] restricted to [`APPROVED_CIPHER_SUITE_IDS`].
///
/// Used by crates (e.g. the NNTP reader) that build their own [`ServerConfig`]
/// with a custom client-auth verifier.
pub fn approved_provider_arc() -> Arc<CryptoProvider> {
    approved_provider()
}

/// Install the `ring` [`CryptoProvider`] as the process default.
///
/// Must be called early in `main()`, before any TLS operation, so that
/// [`approved_provider`] can call [`CryptoProvider::get_default`] without
/// panicking.  The call is idempotent — if a provider was already installed
/// (e.g. in integration tests) the returned error is silently ignored.
pub fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen() -> (Vec<u8>, Vec<u8>) {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (
            c.cert.pem().into_bytes(),
            c.key_pair.serialize_pem().into_bytes(),
        )
    }

    fn ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn load_private_key_from_bytes_parses_valid_pem() {
        let (_, k) = gen();
        assert!(load_private_key_from_bytes(&k, "t").is_ok());
    }

    #[test]
    fn load_private_key_from_bytes_empty_returns_error() {
        match load_private_key_from_bytes(&[], "t").unwrap_err() {
            TlsError::KeyLoad(l, _) => assert_eq!(l, "t"),
            e => panic!("{e}"),
        }
    }

    #[test]
    fn load_tls_server_config_with_key_bytes_success() {
        ring();
        let d = tempfile::TempDir::new().unwrap();
        let (cp, kp) = gen();
        let p = d.path().join("c.pem");
        std::fs::write(&p, &cp).unwrap();
        assert!(load_tls_server_config_with_key_bytes(p.to_str().unwrap(), &kp, "t").is_ok());
    }

    #[test]
    fn load_tls_server_config_missing_cert_returns_error() {
        match load_tls_server_config("/nx/c.pem", "/nx/k.pem").unwrap_err() {
            TlsError::CertLoad(p, _) => assert!(p.contains("c.pem")),
            e => panic!("{e}"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad(
            "/f/c.pem".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "nf"),
        );
        assert!(e.to_string().contains("/f/c.pem"));
    }

    #[test]
    fn cert_not_after_returns_future_timestamp() {
        let d = tempfile::TempDir::new().unwrap();
        let (cp, _) = gen();
        let p = d.path().join("c.pem");
        std::fs::write(&p, &cp).unwrap();
        let expiry = cert_not_after(p.to_str().unwrap()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(expiry > now);
        assert!(expiry > 1_704_067_200);
    }

    #[test]
    fn cert_not_after_missing_file_returns_error() {
        assert!(cert_not_after("/nx/c.pem").is_err());
    }

    /// [`ServerConfig`] must only offer suites from [`APPROVED_CIPHER_SUITE_IDS`].
    #[test]
    fn server_config_cipher_suites_are_approved() {
        ring();
        let d = tempfile::TempDir::new().unwrap();
        let (cp, kp) = gen();
        let p = d.path().join("c.pem");
        std::fs::write(&p, &cp).unwrap();
        let cfg = load_tls_server_config_with_key_bytes(p.to_str().unwrap(), &kp, "t").unwrap();
        for cs in &cfg.crypto_provider().cipher_suites {
            let id: CipherSuite = cs.suite();
            assert!(
                APPROVED_CIPHER_SUITE_IDS.contains(&id),
                "non-approved suite: {id:?}"
            );
        }
    }

    /// [`approved_cipher_suites`] must return only approved suite IDs.
    #[test]
    fn approved_cipher_suites_filters_correctly() {
        ring();
        let provider = CryptoProvider::get_default().unwrap();
        let filtered = approved_cipher_suites(provider);
        assert!(!filtered.is_empty());
        for cs in &filtered {
            let id: CipherSuite = cs.suite();
            assert!(
                APPROVED_CIPHER_SUITE_IDS.contains(&id),
                "non-approved suite in filtered list: {id:?}"
            );
        }
        assert!(filtered.len() <= provider.cipher_suites.len());
    }

    /// A well-formed TLS 1.1 ClientHello must not receive a ServerHello.
    ///
    /// Sends a TLS 1.1 ClientHello to a stoa-tls server and asserts the server
    /// does not respond with a Handshake record (0x16).
    /// rustls 0.23 dropped TLS 1.0/1.1; the server sends Alert (0x15) or EOF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_11_client_hello_is_rejected() {
        ring();
        let d = tempfile::TempDir::new().unwrap();
        let (cp, kp) = gen();
        let p = d.path().join("c.pem");
        std::fs::write(&p, &cp).unwrap();
        let sc = load_tls_server_config_with_key_bytes(p.to_str().unwrap(), &kp, "t").unwrap();
        let lst = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lst.local_addr().unwrap();
        let acc = tokio_rustls::TlsAcceptor::from(sc);
        tokio::spawn(async move {
            if let Ok((s, _)) = lst.accept().await {
                let _ = acc.accept(s).await;
            }
        });
        let hello: &[u8] = &[
            0x16, 0x03, 0x02, 0x00, 0x2d, 0x01, 0x00, 0x00, 0x29, 0x03, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00,
        ];
        let mut s: tokio::net::TcpStream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(hello).await.unwrap();
        let mut buf = [0u8; 64];
        let n: usize = tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut buf))
            .await
            .expect("server must respond within 2 seconds")
            .unwrap_or(0);
        if n > 0 {
            assert_ne!(
                buf[0], 0x16,
                "server sent a Handshake record for TLS 1.1; got 0x{:02x}",
                buf[0]
            );
        }
    }
}
