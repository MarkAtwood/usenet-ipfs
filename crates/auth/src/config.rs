//! Shared authentication configuration types.

use serde::Deserialize;

/// A username/password credential pair used in SMTP/IMAP/NNTP auth config.
///
/// The `password` field must be a **bcrypt hash**, never plaintext.
///
/// # TOML config stability
/// The field names `username` and `password` are operator-visible config keys
/// (e.g. `[[auth.users]]` sections). Renaming either field is a **breaking
/// change** for deployed operator configs — serde deserialization will silently
/// ignore unknown keys and use defaults, producing auth failures at runtime
/// with no compile-time warning.
#[derive(Debug, Clone, Deserialize)]
pub struct UserCredential {
    pub username: String,
    /// bcrypt hash, never plaintext.
    pub password: String,
}

/// A TLS client certificate pinned to a username.
///
/// When a client presents a certificate whose SHA-256 fingerprint matches
/// `sha256_fingerprint`, the session is authenticated as `username` without
/// requiring a password. Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertEntry {
    /// SHA-256 fingerprint of the leaf certificate DER, formatted as
    /// `"sha256:<64-hex-chars>"`.  Case-insensitive on input; stored
    /// in normalised lowercase form.
    pub sha256_fingerprint: String,
    /// Username to authenticate when this certificate is presented.
    pub username: String,
}

/// A trusted CA issuer for client certificate authentication.
///
/// When a client presents a certificate signed by this CA, the leaf
/// certificate's Common Name (CN) is used as the authenticated username.
/// Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct TrustedIssuerEntry {
    /// Path to a PEM-encoded CA certificate.  The CA's SubjectPublicKeyInfo
    /// (SPKI) is extracted at startup and used for Ed25519 signature
    /// verification.
    pub cert_path: String,
}

/// One OIDC identity provider entry from `[[auth.oidc_providers]]`.
///
/// JWTs issued by this provider are accepted as Bearer tokens in JMAP requests.
/// JWKS keys are fetched lazily and cached for `jwks_ttl_secs` seconds (default 3600).
#[derive(Debug, Deserialize, Clone)]
pub struct OidcProviderConfig {
    /// OIDC issuer URL, e.g. `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxx`.
    ///
    /// Used both as the expected `iss` claim value and as the base URL for
    /// `/.well-known/openid-configuration` discovery.
    pub issuer: String,
    /// OAuth2 `audience` — the client ID this server should accept tokens for.
    ///
    /// The JWT's `aud` claim must contain this value.
    pub audience: String,
    /// JWT claim name to use as the JMAP/IMAP username.
    ///
    /// Default: `"email"`. Falls back to `"sub"` if the configured claim is absent.
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
}

fn default_username_claim() -> String {
    "email".to_owned()
}

/// Authentication configuration shared across NNTP, JMAP, and SMTP services.
#[derive(Debug, Default, Deserialize)]
pub struct AuthConfig {
    pub required: bool,
    /// User accounts for authentication.
    ///
    /// If empty and `required = false` and `credential_file` is unset, all
    /// credential attempts succeed (development mode).
    #[serde(default)]
    pub users: Vec<UserCredential>,
    /// Path to a file of `username:bcrypt_hash` credential pairs.
    ///
    /// Each non-blank, non-comment line must be `username:$2b$...`. Lines
    /// starting with `#` are ignored. Loaded at startup and merged with the
    /// inline `users` list.
    #[serde(default)]
    pub credential_file: Option<String>,
    /// TLS client certificate pins.
    ///
    /// Each entry maps a certificate SHA-256 fingerprint to a username.
    /// When a client presents a matching certificate over TLS, the session
    /// is authenticated without a password exchange.
    #[serde(default)]
    pub client_certs: Vec<ClientCertEntry>,
    /// Trusted CA issuers for client certificate chain authentication.
    ///
    /// When a client presents a certificate signed by one of these CAs, the
    /// leaf certificate's CN is used as the username — no password required.
    /// Takes effect only after fingerprint-based auth has been attempted first.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuerEntry>,
    /// OIDC identity providers for JWT Bearer authentication.
    ///
    /// When non-empty, JWT Bearer tokens are validated against these providers
    /// before falling through to the bcrypt / self-issued token path.
    /// Multiple providers are tried in order; the first match wins.
    #[serde(default)]
    pub oidc_providers: Vec<OidcProviderConfig>,
    /// Usernames that receive the operator-role admin capability in JMAP sessions.
    ///
    /// Users in this list see the `urn:ietf:params:jmap:usenet-ipfs-admin`
    /// capability in their session document and may call admin JMAP methods
    /// (`ServerStatus/get`, `Peer/get`, `GroupLog/get`).  Regular users do not
    /// see this capability and receive `forbidden` if they call admin methods.
    #[serde(default)]
    pub operator_usernames: Vec<String>,
}

impl AuthConfig {
    /// Returns `true` when `username` is in the operator list.
    ///
    /// Comparison is case-insensitive (ASCII-lowercase normalization) because
    /// OIDC providers may deliver the same identity in mixed or lowercase form
    /// depending on the IdP, while the operator may have configured the username
    /// with different casing in the config file.
    pub fn is_operator(&self, username: &str) -> bool {
        let lower = username.to_ascii_lowercase();
        self.operator_usernames
            .iter()
            .any(|u| u.to_ascii_lowercase() == lower)
    }

    /// Returns `true` when no credentials are configured and auth is not
    /// required — the development / open-access mode.
    pub fn is_dev_mode(&self) -> bool {
        !self.required
            && self.users.is_empty()
            && self.credential_file.is_none()
            && self.client_certs.is_empty()
            && self.trusted_issuers.is_empty()
            && self.oidc_providers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_mode_when_nothing_configured() {
        let cfg = AuthConfig::default();
        assert!(cfg.is_dev_mode());
    }

    #[test]
    fn not_dev_mode_when_required() {
        let mut cfg = AuthConfig::default();
        cfg.required = true;
        assert!(!cfg.is_dev_mode());
    }

    #[test]
    fn not_dev_mode_when_users_configured() {
        let mut cfg = AuthConfig::default();
        cfg.users.push(UserCredential {
            username: "alice".into(),
            password: "$2b$10$placeholder".into(),
        });
        assert!(!cfg.is_dev_mode());
    }

    #[test]
    fn not_dev_mode_when_credential_file_set() {
        let mut cfg = AuthConfig::default();
        cfg.credential_file = Some("/etc/stoa/creds".into());
        assert!(!cfg.is_dev_mode());
    }

    #[test]
    fn not_dev_mode_when_client_certs_configured() {
        let mut cfg = AuthConfig::default();
        cfg.client_certs.push(ClientCertEntry {
            sha256_fingerprint: "sha256:aabbcc".into(),
            username: "alice".into(),
        });
        assert!(!cfg.is_dev_mode());
    }

    #[test]
    fn not_dev_mode_when_trusted_issuers_configured() {
        let mut cfg = AuthConfig::default();
        cfg.trusted_issuers.push(TrustedIssuerEntry {
            cert_path: "/etc/stoa/ca.pem".into(),
        });
        assert!(!cfg.is_dev_mode());
    }

    #[test]
    fn is_operator_returns_true_for_listed_username() {
        let mut cfg = AuthConfig::default();
        cfg.operator_usernames = vec!["admin".to_string(), "ops".to_string()];
        assert!(cfg.is_operator("admin"));
        assert!(cfg.is_operator("ops"));
        assert!(!cfg.is_operator("alice"));
        assert!(!cfg.is_operator(""));
    }

    #[test]
    fn is_operator_returns_false_when_list_empty() {
        let cfg = AuthConfig::default();
        assert!(!cfg.is_operator("admin"));
    }

    #[test]
    fn is_operator_is_case_insensitive() {
        let mut cfg = AuthConfig::default();
        cfg.operator_usernames = vec!["Admin@Example.COM".to_string()];
        // Token-delivered username in all lowercase must still match.
        assert!(cfg.is_operator("admin@example.com"));
        // All-uppercase must also match.
        assert!(cfg.is_operator("ADMIN@EXAMPLE.COM"));
        // Non-member must still be rejected.
        assert!(!cfg.is_operator("other@example.com"));
    }
}
