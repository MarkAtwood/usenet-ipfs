//! TLS configuration loader for the SMTP listener.
//!
//! Delegates PEM loading to `stoa-tls` and adds SMTP-specific helpers
//! (`build_tls_acceptor`, `accept_tls`, `tls_configured`).

pub use stoa_tls::TlsError;
use stoa_tls::{load_tls_server_config, load_tls_server_config_with_key_bytes};

/// A `tokio_rustls` TLS acceptor for the SMTPS listener.
pub type TlsAcceptor = tokio_rustls::TlsAcceptor;

/// Build a [`TlsAcceptor`] from PEM certificate and private-key files.
///
/// Loads the certificate chain and private key, constructs a `rustls::ServerConfig`
/// requiring TLS 1.2 or higher, and wraps it in a `tokio_rustls::TlsAcceptor`.
pub fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, TlsError> {
    let server_config = load_tls_server_config(cert_path, key_path)?;
    Ok(tokio_rustls::TlsAcceptor::from(server_config))
}

/// Build a [`TlsAcceptor`] from a certificate file and private-key bytes.
///
/// `key_label` identifies the key source in error messages (typically the
/// `secretx:` URI used to retrieve the key).
///
/// Equivalent to [`build_tls_acceptor`] but the private key is supplied as PEM
/// bytes rather than a file path.  Use this when the key was retrieved from a
/// secrets manager via a `secretx:` URI.
pub fn build_tls_acceptor_with_key_bytes(
    cert_path: &str,
    key_pem_bytes: &[u8],
    key_label: &str,
) -> Result<TlsAcceptor, TlsError> {
    let server_config = load_tls_server_config_with_key_bytes(cert_path, key_pem_bytes, key_label)?;
    Ok(tokio_rustls::TlsAcceptor::from(server_config))
}

/// Perform the TLS handshake on an accepted TCP stream.
///
/// Returns the wrapped TLS stream on success. Handshake errors are non-fatal —
/// the caller should drop the stream and continue accepting new connections.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    acceptor.accept(stream).await
}

/// Returns `true` if both `cert_path` and `key_path` are set in the config.
pub fn tls_configured(config: &crate::config::Config) -> bool {
    config.tls.cert_path.is_some() && config.tls.key_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tls_acceptor_missing_cert_returns_cert_load_error() {
        let result = build_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
        match result {
            Err(TlsError::CertLoad(path, _)) => assert!(path.contains("cert.pem")),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad(
            "/foo/cert.pem".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        );
        let msg = e.to_string();
        assert!(msg.contains("cert.pem"), "display: {msg}");
    }

    #[test]
    fn tls_configured_both_set() {
        use crate::config::{
            AuthConfig, Config, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig,
            ReaderConfig, SieveAdminConfig, TlsConfig,
        };
        let cfg = Config {
            listen: ListenConfig {
                port_25: "0.0.0.0:25".into(),
                port_587: "0.0.0.0:587".into(),
                smtps_addr: None,
            },
            hostname: "localhost".into(),
            tls: TlsConfig {
                cert_path: Some("/etc/ssl/cert.pem".into()),
                key_path: Some("/etc/ssl/key.pem".into()),
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        };
        assert!(tls_configured(&cfg));
    }

    #[test]
    fn tls_configured_neither_set() {
        use crate::config::{
            AuthConfig, Config, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig,
            ReaderConfig, SieveAdminConfig, TlsConfig,
        };
        let cfg = Config {
            listen: ListenConfig {
                port_25: "0.0.0.0:25".into(),
                port_587: "0.0.0.0:587".into(),
                smtps_addr: None,
            },
            hostname: "localhost".into(),
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        };
        assert!(!tls_configured(&cfg));
    }
}
