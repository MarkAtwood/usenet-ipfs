//! TLS acceptor for the NNTP listener.
//!
//! When TLS is configured, wraps the TCP stream in a rustls ServerConnection.
//! The `NntpStream` enum unifies plain and TLS streams so the session handler
//! does not need to know which variant is active.
//!
//! PEM loading is delegated to `stoa-tls`; this module adds the
//! NNTP-specific `PermissiveClientAuth` verifier for mutual TLS and the
//! `extract_client_cert_data` helper for fingerprint-based auth.

use std::sync::Arc;

use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::ServerConfig;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use sha2::Digest as _;
use stoa_tls::{
    approved_provider_arc, load_cert_chain, load_private_key, load_private_key_from_bytes,
};

pub use stoa_tls::TlsError;

/// A rustls-backed TLS acceptor for incoming TCP connections.
pub struct TlsAcceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// A `ClientCertVerifier` that requests a client certificate, skips CA chain
/// validation (no trusted roots required), but fully verifies the TLS
/// handshake signature to prove key possession.
///
/// Chain validation (fingerprint-to-username binding) happens at the
/// application layer after the handshake.  The TLS handshake signature MUST
/// be verified here — without it, any client that possesses a copy of
/// someone's certificate (but not their private key) could forge an identity.
#[derive(Debug)]
struct PermissiveClientAuth;

impl ClientCertVerifier for PermissiveClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // CA chain validation is skipped — trust is established by fingerprint
        // at the application layer.  Key-possession proof is handled by the
        // verify_tls12_signature / verify_tls13_signature methods below.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or(Error::General("no default crypto provider".into()))?;
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or(Error::General("no default crypto provider".into()))?;
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// Extract the SHA-256 fingerprint and raw DER bytes of the client's TLS leaf
/// certificate.
///
/// Returns `(fingerprint, raw_der)` where:
/// - `fingerprint` is `Some("sha256:<64-lowercase-hex-chars>")`.
/// - `raw_der` is `Some(<leaf cert DER bytes>)`.
///
/// Both fields are `None` if no client certificate was presented.
pub fn extract_client_cert_data(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> (Option<String>, Option<Vec<u8>>) {
    let certs = match tls_stream.get_ref().1.peer_certificates() {
        Some(c) => c,
        None => return (None, None),
    };
    let leaf = match certs.first() {
        Some(l) => l,
        None => return (None, None),
    };
    let der = leaf.as_ref().to_vec();
    let digest = sha2::Sha256::digest(&der);
    let fingerprint = format!("sha256:{}", hex::encode(digest));
    (Some(fingerprint), Some(der))
}

/// Load a TLS acceptor from a certificate file and private key bytes.
///
/// `key_label` identifies the key source in error messages (typically the
/// `secretx:` URI used to retrieve the key).
///
/// Equivalent to [`load_tls_acceptor`] but the private key is supplied as PEM
/// bytes rather than a file path.  Use this when the key was retrieved from a
/// secrets manager via a `secretx:` URI.
pub fn load_tls_acceptor_with_key_bytes(
    cert_path: &str,
    key_pem_bytes: &[u8],
    key_label: &str,
) -> Result<TlsAcceptor, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key_from_bytes(key_pem_bytes, key_label)?;
    let config = ServerConfig::builder_with_provider(approved_provider_arc())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsError::Config)?
        .with_client_cert_verifier(Arc::new(PermissiveClientAuth))
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsError::Config)?;
    stoa_tls::log_tls_policy(&config);
    Ok(TlsAcceptor {
        inner: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    })
}

/// Build a `TlsAcceptor` from PEM certificate and private-key files.
///
/// The resulting `ServerConfig` requires TLS 1.2 or higher; TLS 1.0 and 1.1
/// are not offered. Client certificates are requested but not required —
/// fingerprint validation happens at the application layer.
///
/// PEM loading is handled by `stoa-tls`; the NNTP-specific
/// `PermissiveClientAuth` verifier is assembled here.
pub fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key(key_path)?;
    let config = ServerConfig::builder_with_provider(approved_provider_arc())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsError::Config)?
        .with_client_cert_verifier(Arc::new(PermissiveClientAuth))
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsError::Config)?;

    stoa_tls::log_tls_policy(&config);
    Ok(TlsAcceptor {
        inner: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    })
}

/// Check TLS certificate expiry, update the Prometheus gauge, log
/// warnings/errors, and return a JSON summary for API responses.
///
/// - ≤ 30 days remaining: WARN log (`event=cert_expiry_warning`)
/// - ≤  7 days remaining: ERROR log (`event=cert_expiry_critical`)
///
/// Parse failures are logged at WARN and return an object with an `"error"` key.
pub fn check_cert_expiry(cert_path: &str) -> serde_json::Value {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    match stoa_tls::cert_not_after(cert_path) {
        Ok(expiry_unix) => {
            let days_remaining = (expiry_unix - now_secs) / 86400;
            let expires_at = chrono::DateTime::from_timestamp(expiry_unix, 0)
                .map(|t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| expiry_unix.to_string());
            crate::metrics::TLS_CERT_EXPIRY_SECONDS
                .with_label_values(&[cert_path])
                .set(expiry_unix as f64);
            if days_remaining <= 7 {
                tracing::error!(
                    event = "cert_expiry_critical",
                    path = cert_path,
                    days_remaining,
                    expires_at = %expires_at,
                    "TLS certificate expires very soon"
                );
            } else if days_remaining <= 30 {
                tracing::warn!(
                    event = "cert_expiry_warning",
                    path = cert_path,
                    days_remaining,
                    expires_at = %expires_at,
                    "TLS certificate expiring soon"
                );
            }
            serde_json::json!({
                "path": cert_path,
                "expires_at": expires_at,
                "days_remaining": days_remaining,
            })
        }
        Err(e) => {
            tracing::warn!(path = cert_path, "TLS cert expiry check failed: {e}");
            serde_json::json!({ "path": cert_path, "error": e.to_string() })
        }
    }
}

/// Perform the TLS handshake on an already-accepted TCP stream.
///
/// Returns the wrapped TLS stream on success, or an `std::io::Error` on
/// handshake failure. Handshake errors are non-fatal — the caller should log
/// and drop the stream.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    acceptor.inner.accept(stream).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_acceptor_missing_cert_returns_error() {
        let result = load_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertLoad(path, _) => assert!(path.contains("cert.pem")),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad(
            "/foo/cert.pem".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        );
        let msg = e.to_string();
        assert!(msg.contains("/foo/cert.pem"), "display: {msg}");
    }
}
