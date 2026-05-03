use base64::Engine as _;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

use stoa_auth::looks_like_bcrypt_hash;
pub use stoa_auth::AuthConfig;

/// Database key used to identify the single global Sieve script.
///
/// The `user_sieve_scripts` table is keyed by `(username, script_name)`.
/// In the single-user delivery model there are no per-user namespaces, so
/// the global policy script is stored under this sentinel username.
///
/// `_global` is the reserved script key for the server-wide Sieve script
/// that applies to all messages, regardless of recipient.
pub const GLOBAL_SCRIPT_KEY: &str = "_global";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub reader: ReaderConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub sieve_admin: SieveAdminConfig,
    /// DNS resolver to use for SPF/DKIM/DMARC/ARC lookups.
    ///
    /// Valid values: `"system"` (reads `/etc/resolv.conf`), `"cloudflare"`,
    /// `"google"`, `"quad9"`.  Defaults to `"system"` so that split-horizon
    /// DNS and air-gapped deployments work correctly out of the box.
    #[serde(default)]
    pub dns_resolver: DnsResolver,
    /// SMTP AUTH PLAIN credentials.  Optional; when absent AUTH is not
    /// advertised and no credentials are accepted.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Trusted peer CIDRs. Once DNSBL (usenet-ipfs-1d63), FCrDNS (usenet-ipfs-fxxx), and
    /// greylisting (usenet-ipfs-mgzn) are implemented, connections from these IPs will bypass
    /// all three. Currently, the flag is computed but no filters are wired in yet. Empty by
    /// default. Both IPv4 and IPv6 CIDRs are supported. An invalid CIDR is a fatal startup
    /// error.
    #[serde(default)]
    pub peer_whitelist: Vec<IpNet>,
    /// MTA-STS policy configuration (RFC 8461).
    #[serde(default)]
    pub mta_sts: MtaStsConfig,
}

fn default_db_path() -> String {
    "smtp.db".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// File path for the SQLite database, or `:memory:` for in-process testing.
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

fn default_sieve_admin_bind() -> String {
    "127.0.0.1:4190".to_owned()
}

fn default_max_script_bytes() -> u64 {
    65_536
}

/// Configuration for the HTTP Sieve script management API.
///
/// The API listens on `bind` (default `127.0.0.1:4190`) and requires no
/// credentials — access control is enforced by the bind address.
/// Binding to a non-loopback address without additional network-level
/// protection (firewall, VPN) exposes script read/write to any host with
/// HTTP access.  A warning is logged at startup unless
/// `allow_non_loopback = true` is set explicitly.
#[derive(Debug, Deserialize)]
pub struct SieveAdminConfig {
    #[serde(default = "default_sieve_admin_bind")]
    pub bind: String,
    /// Maximum size of a Sieve script in bytes (default 64 KiB).
    #[serde(default = "default_max_script_bytes")]
    pub max_script_bytes: u64,
    /// Suppress the non-loopback warning.  Set to `true` only when you have
    /// verified that the admin API is protected by a firewall or reverse proxy
    /// with its own authentication.
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// Optional bearer token for HTTP authentication.
    ///
    /// When set, every request must include `Authorization: Bearer <token>`.
    /// Strongly recommended when `bind` is a non-loopback address.
    /// If unset, all requests are allowed (loopback-only access control).
    #[serde(default)]
    pub bearer_token: Option<String>,
}

impl Default for SieveAdminConfig {
    fn default() -> Self {
        Self {
            bind: default_sieve_admin_bind(),
            max_script_bytes: default_max_script_bytes(),
            allow_non_loopback: false,
            bearer_token: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReaderConfig {
    #[serde(default = "default_nntp_addr")]
    pub nntp_addr: String,
    /// Optional AUTHINFO USER credential for submission to the local NNTP reader.
    #[serde(default)]
    pub nntp_username: Option<String>,
    /// Optional AUTHINFO PASS credential for submission to the local NNTP reader.
    #[serde(default)]
    pub nntp_password: Option<String>,
    /// Maximum retry attempts on transient 436 failures (default: 3).
    #[serde(default = "default_nntp_max_retries")]
    pub nntp_max_retries: u32,
}

fn default_nntp_addr() -> String {
    "127.0.0.1:119".to_owned()
}

fn default_nntp_max_retries() -> u32 {
    3
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            nntp_addr: default_nntp_addr(),
            nntp_username: None,
            nntp_password: None,
            nntp_max_retries: default_nntp_max_retries(),
        }
    }
}

fn default_relay_port() -> u16 {
    587
}

fn default_true() -> bool {
    true
}

/// Configuration for a single outbound SMTP relay peer.
///
/// At least one relay peer must be configured for outbound email delivery.
/// If `smtp_relay_peers` is empty, delivery is a no-op (no error at startup;
/// messages are queued but never sent).
///
/// # Security
/// `password` is never serialized back to TOML output and never appears in
/// `Debug` output — it is always shown as `<redacted>`.
#[derive(Clone, Deserialize, Serialize)]
pub struct SmtpRelayPeerConfig {
    /// Hostname or IP address of the relay MTA.
    pub host: String,
    /// TCP port. Defaults to 587 (submission with STARTTLS).
    #[serde(default = "default_relay_port")]
    pub port: u16,
    /// Whether to use TLS (STARTTLS on submission, or implicit TLS on 465).
    /// Defaults to `true`.
    #[serde(default = "default_true")]
    pub tls: bool,
    /// SMTP AUTH username, if the relay requires authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// SMTP AUTH password. Never serialized; never logged.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
}

impl fmt::Debug for SmtpRelayPeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpRelayPeerConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl SmtpRelayPeerConfig {
    /// Returns `"host:port"` for use in log messages and connection targets.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn default_queue_dir() -> String {
    "smtp-queue".to_owned()
}

fn default_nntp_retry_secs() -> u64 {
    60
}

fn default_smtp_relay_queue_dir() -> String {
    "smtp-relay-queue".to_owned()
}

fn default_smtp_relay_retry_secs() -> u64 {
    60
}

fn default_peer_down_secs() -> u64 {
    300
}

/// DKIM signing configuration for outbound messages.
///
/// `key_seed_b64` is the base64-encoded 32-byte Ed25519 seed (private key material).
/// It is intentionally redacted from `Debug` output.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct DkimConfig {
    pub domain: String,
    pub selector: String,
    pub key_seed_b64: String,
    pub public_key_b64: String,
}

impl std::fmt::Debug for DkimConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimConfig")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .field("key_seed_b64", &"[REDACTED]")
            .field("public_key_b64", &self.public_key_b64)
            .finish()
    }
}

/// A ready-to-use DKIM signer for Ed25519-SHA256 (RFC 8463).
///
/// The signer is constructed once at startup and shared via `Arc`.  All fields
/// that influence the signature (domain, selector, signed headers) are baked in
/// at construction time by `mail_auth::dkim::DkimSigner::from_key(…).domain(…)…`.
pub type DkimSignerArc = std::sync::Arc<
    mail_auth::dkim::DkimSigner<mail_auth::common::crypto::Ed25519Key, mail_auth::dkim::Done>,
>;

/// RFC 5322 header fields covered by the DKIM signature on all outbound messages.
///
/// Per RFC 6376 §5.4, `From` is mandatory.  `To`, `Subject`, `Date`, and
/// `Message-ID` are recommended.  `MIME-Version` ensures the MIME structure is
/// covered.  All fields listed here must be present in outbound messages;
/// `mail_auth` silently skips any absent field rather than erroring.
pub const DKIM_SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
];

/// Build a [`DkimSignerArc`] from a pre-constructed `Ed25519Key` and DKIM config.
///
/// Extracts domain, selector, and signed headers from `cfg`.  The `ed_key` must
/// already have been derived from the config's seed and public key.
pub fn build_dkim_signer_arc(
    cfg: &DkimConfig,
    ed_key: mail_auth::common::crypto::Ed25519Key,
) -> DkimSignerArc {
    std::sync::Arc::new(
        mail_auth::dkim::DkimSigner::from_key(ed_key)
            .domain(cfg.domain.as_str())
            .selector(cfg.selector.as_str())
            .headers(DKIM_SIGNED_HEADERS.iter().copied()),
    )
}

/// Configuration for the durable NNTP injection queue and outbound SMTP relay.
#[derive(Debug, Deserialize)]
pub struct DeliveryConfig {
    /// Path to the mail crate's SQLite database file.
    ///
    /// When set, SMTP delivery writes messages into the JMAP mail store
    /// (`mailbox_messages` table) instead of the smtp-local store.  The
    /// mail binary must have already run its migrations against this file.
    /// If the file does not exist at startup, SMTP→JMAP bridging is
    /// disabled and a warning is logged; the server continues running using
    /// the smtp-local store as fallback.
    #[serde(default)]
    pub mail_db_path: Option<String>,
    /// Directory for queued outbound NNTP articles. Created on startup if absent.
    #[serde(default = "default_queue_dir")]
    pub queue_dir: String,
    /// Seconds between retry scans when NNTP delivery fails. Defaults to 60.
    #[serde(default = "default_nntp_retry_secs")]
    pub nntp_retry_secs: u64,
    /// Outbound SMTP relay peers. If empty, no SMTP relay delivery is performed.
    #[serde(default)]
    pub smtp_relay_peers: Vec<SmtpRelayPeerConfig>,
    /// Directory for queued outbound SMTP relay messages. Created on startup if absent.
    #[serde(default = "default_smtp_relay_queue_dir")]
    pub smtp_relay_queue_dir: String,
    /// Seconds between retry scans when SMTP relay delivery fails. Defaults to 60.
    #[serde(default = "default_smtp_relay_retry_secs")]
    pub smtp_relay_retry_secs: u64,
    /// How long (in seconds) a relay peer stays in the "down" state after a
    /// delivery failure before it is retried.  Defaults to 300 (5 minutes).
    ///
    /// **Semantics**: after any failed delivery attempt to a peer, that peer is
    /// marked *down* for this duration.  During the down period it is skipped by
    /// the round-robin selector, preventing repeated hammering of an unavailable
    /// host.  Once the backoff window expires the peer is eligible again on the
    /// next retry scan.  A successful delivery resets the peer to *up*
    /// immediately regardless of the remaining backoff.
    ///
    /// **Tuning guidance**:
    /// - *Intra-datacenter or local relay* (very reliable): 30–60 s.  Low
    ///   latency means short backoff still avoids tight retry loops.
    /// - *Default (cloud or internet peer)*: 300 s (5 min).  Enough time for
    ///   a remote MTA to recover from a transient outage without long queue backlog.
    /// - *Unreliable or geographically distant peer*: 600–1800 s.  Reduces
    ///   noise in logs and queue churn during extended outages.
    ///
    /// Setting this too low causes rapid retry loops that waste connections and
    /// generate noisy logs.  Setting it too high delays delivery after a peer
    /// recovers.  The metrics counter  transitions are a good
    /// signal for tuning: frequent up↔down oscillation suggests too-low a value.
    #[serde(default = "default_peer_down_secs")]
    pub smtp_peer_down_secs: u64,
    /// Optional DKIM signing configuration. When absent, outbound messages are
    /// not DKIM-signed.
    #[serde(default)]
    pub dkim: Option<DkimConfig>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            mail_db_path: None,
            queue_dir: default_queue_dir(),
            nntp_retry_secs: default_nntp_retry_secs(),
            smtp_relay_peers: Vec::new(),
            smtp_relay_queue_dir: default_smtp_relay_queue_dir(),
            smtp_relay_retry_secs: default_smtp_relay_retry_secs(),
            smtp_peer_down_secs: default_peer_down_secs(),
            dkim: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub port_25: String,
    pub port_587: String,
    /// Optional SMTPS listener address for implicit TLS on port 465.
    ///
    /// When set, a third TCP listener is bound at this address.  Clients must
    /// initiate TLS immediately (no STARTTLS upgrade).  Requires
    /// `tls.cert_path` and `tls.key_path` to be set.
    #[serde(default)]
    pub smtps_addr: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

fn default_max_message_bytes() -> u64 {
    26_214_400
}

fn default_max_recipients() -> usize {
    100
}

fn default_command_timeout_secs() -> u64 {
    300
}

fn default_max_connections() -> usize {
    100
}

fn default_sieve_eval_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: u64,
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    #[serde(default = "default_command_timeout_secs")]
    pub command_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum time allowed for Sieve script evaluation per message (milliseconds).
    /// Evaluation that exceeds this limit is aborted and treated as Keep (fail-safe).
    #[serde(default = "default_sieve_eval_timeout_ms")]
    pub sieve_eval_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: default_max_message_bytes(),
            max_recipients: default_max_recipients(),
            command_timeout_secs: default_command_timeout_secs(),
            max_connections: default_max_connections(),
            sieve_eval_timeout_ms: default_sieve_eval_timeout_ms(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// Log output format.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// Structured JSON output.
    Json,
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    /// Log level filter (e.g. "info", "debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

/// DNS resolver backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsResolver {
    /// System resolver.
    #[default]
    System,
    /// Cloudflare public DNS (1.1.1.1).
    Cloudflare,
    /// Google public DNS (8.8.8.8).
    Google,
    /// Quad9 public DNS (9.9.9.9).
    Quad9,
}

impl std::fmt::Display for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsResolver::System => write!(f, "system"),
            DnsResolver::Cloudflare => write!(f, "cloudflare"),
            DnsResolver::Google => write!(f, "google"),
            DnsResolver::Quad9 => write!(f, "quad9"),
        }
    }
}

fn default_hostname() -> String {
    "localhost".to_owned()
}

/// MTA-STS operating mode for a hosted domain (RFC 8461 §3.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum MtaStsMode {
    /// Do not enforce TLS; publish policy for testing purposes only.
    #[default]
    None,
    /// Enforce check but do not block delivery on failure; report only.
    Testing,
    /// Block delivery if TLS or MX validation fails.
    Enforce,
}

/// MTA-STS policy configuration for one hosted domain.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MtaStsDomainConfig {
    /// The domain this policy applies to (e.g. "example.com").
    pub domain: String,
    /// Policy enforcement mode.
    #[serde(default)]
    pub mode: MtaStsMode,
    /// MX hostname patterns for this domain (e.g. ["*.example.com"]).
    #[serde(default)]
    pub mx_patterns: Vec<String>,
    /// Cache lifetime in seconds (1–31557600). Default: 86400 (1 day).
    #[serde(default = "default_mta_sts_max_age_secs")]
    pub max_age_secs: u32,
}

/// Top-level MTA-STS configuration block.
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct MtaStsConfig {
    /// Whether MTA-STS checking is enabled at all.
    #[serde(default)]
    pub enabled: bool,
    /// Per-domain policy configuration for domains this server hosts.
    #[serde(default)]
    pub hosted_domains: Vec<MtaStsDomainConfig>,
    /// Timeout in milliseconds for HTTPS policy fetch. Default: 10000.
    #[serde(default = "default_mta_sts_fetch_timeout_ms")]
    pub fetch_timeout_ms: u64,
    /// Maximum allowed policy body size in bytes. Default: 65536 (64 KiB).
    #[serde(default = "default_mta_sts_max_policy_body_bytes")]
    pub max_policy_body_bytes: usize,
}

fn default_mta_sts_max_age_secs() -> u32 {
    86400
}
fn default_mta_sts_fetch_timeout_ms() -> u64 {
    10_000
}
fn default_mta_sts_max_policy_body_bytes() -> usize {
    65_536
}

#[non_exhaustive]
#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "I/O error: {msg}"),
            ConfigError::Parse(msg) => write!(f, "parse error: {msg}"),
            ConfigError::Validation(msg) => write!(f, "validation error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hostname.is_empty() {
            return Err(ConfigError::Validation("hostname must not be empty".into()));
        }
        if self.listen.port_25.is_empty() {
            return Err(ConfigError::Validation(
                "listen.port_25 must not be empty".into(),
            ));
        }
        if self.listen.port_587.is_empty() {
            return Err(ConfigError::Validation(
                "listen.port_587 must not be empty".into(),
            ));
        }
        match (&self.tls.cert_path, &self.tls.key_path) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "tls.cert_path and tls.key_path must both be set or both be absent".into(),
                ));
            }
            _ => {}
        }
        if self.listen.smtps_addr.is_some()
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(ConfigError::Validation(
                "listen.smtps_addr requires tls.cert_path and tls.key_path to be set".into(),
            ));
        }
        for peer in &self.delivery.smtp_relay_peers {
            if peer.host.is_empty() {
                return Err(ConfigError::Validation(
                    "smtp relay peer host must not be empty".into(),
                ));
            }
            if peer.port == 0 {
                return Err(ConfigError::Validation(
                    "smtp relay peer port must be > 0".into(),
                ));
            }
            match (&peer.username, &peer.password) {
                (Some(_), None) => {
                    return Err(ConfigError::Validation(
                        "smtp relay peer has username but no password".into(),
                    ));
                }
                (None, Some(_)) => {
                    return Err(ConfigError::Validation(
                        "smtp relay peer has password but no username".into(),
                    ));
                }
                _ => {}
            }
        }
        if !self.delivery.smtp_relay_peers.is_empty()
            && self.delivery.smtp_relay_queue_dir.trim().is_empty()
        {
            return Err(ConfigError::Validation(
                "delivery.smtp_relay_queue_dir must not be empty when relay peers are configured"
                    .into(),
            ));
        }
        for u in &self.auth.users {
            if !looks_like_bcrypt_hash(&u.password) {
                return Err(ConfigError::Validation(format!(
                    "auth.users['{}']: password is not a valid bcrypt hash (cost must be 4–31)",
                    u.username
                )));
            }
        }
        if let Some(dcfg) = &self.delivery.dkim {
            if dcfg.domain.is_empty() {
                return Err(ConfigError::Validation(
                    "dkim.domain must not be empty".into(),
                ));
            }
            if dcfg.selector.is_empty() {
                return Err(ConfigError::Validation(
                    "dkim.selector must not be empty".into(),
                ));
            }
            let pubkey_bytes = base64::engine::general_purpose::STANDARD
                .decode(&dcfg.public_key_b64)
                .map_err(|_| {
                    ConfigError::Validation("dkim.public_key_b64: invalid base64".into())
                })?;
            if pubkey_bytes.len() != 32 {
                return Err(ConfigError::Validation(format!(
                    "dkim.public_key_b64: must decode to 32 bytes, got {}",
                    pubkey_bytes.len()
                )));
            }
            if !dcfg.key_seed_b64.starts_with("secretx:") {
                let mut seed_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&dcfg.key_seed_b64)
                    .map_err(|_| {
                        ConfigError::Validation("dkim.key_seed_b64: invalid base64".into())
                    })?;
                use zeroize::Zeroize as _;
                if seed_bytes.len() != 32 {
                    let got = seed_bytes.len();
                    seed_bytes.zeroize();
                    return Err(ConfigError::Validation(format!(
                        "dkim.key_seed_b64: must decode to 32 bytes, got {}",
                        got
                    )));
                }
                // Validate that seed and public key form a matching Ed25519 keypair.
                // A mismatched pair produces invalid DKIM signatures that remote
                // MTAs reject — catch this at config validation time.
                if let Err(e) = mail_auth::common::crypto::Ed25519Key::from_seed_and_public_key(
                    &seed_bytes,
                    &pubkey_bytes,
                ) {
                    seed_bytes.zeroize();
                    return Err(ConfigError::Validation(format!(
                        "dkim: seed and public_key_b64 do not form a valid Ed25519 keypair: {e}"
                    )));
                }
                seed_bytes.zeroize();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parse_minimal_valid_toml() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.port_25, "0.0.0.0:25");
        assert_eq!(cfg.listen.port_587, "0.0.0.0:587");
        assert_eq!(cfg.hostname, "localhost");
    }

    #[test]
    fn defaults_applied() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.max_message_bytes, 26_214_400);
        assert_eq!(cfg.limits.max_recipients, 100);
        assert_eq!(cfg.limits.command_timeout_secs, 300);
        assert_eq!(cfg.limits.max_connections, 100);
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.log.format, LogFormat::Text);
    }

    #[test]
    fn tls_both_or_neither_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[tls]
cert_path = "/etc/ssl/certs/smtp.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn smtps_addr_without_tls_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
smtps_addr = "0.0.0.0:465"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn smtps_addr_with_tls_passes_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
smtps_addr = "0.0.0.0:465"

[tls]
cert_path = "/etc/ssl/certs/smtp.pem"
key_path = "/etc/ssl/private/smtp.key"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.smtps_addr.as_deref(), Some("0.0.0.0:465"));
    }

    #[test]
    fn empty_hostname_fails_validation() {
        let toml = r#"
hostname = ""

[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn relay_peers_empty_default() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.delivery.smtp_relay_peers.is_empty());
        assert_eq!(cfg.delivery.smtp_relay_queue_dir, "smtp-relay-queue");
        assert_eq!(cfg.delivery.smtp_relay_retry_secs, 60);
        assert_eq!(cfg.delivery.smtp_peer_down_secs, 300);
    }

    #[test]
    fn relay_peer_defaults() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.delivery.smtp_relay_peers.len(), 1);
        assert_eq!(cfg.delivery.smtp_relay_peers[0].port, 587);
        assert!(cfg.delivery.smtp_relay_peers[0].tls);
        assert_eq!(
            cfg.delivery.smtp_relay_peers[0].host_port(),
            "smtp.example.com:587"
        );
    }

    #[test]
    fn relay_peer_debug_redacts_password() {
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: true,
            username: Some("user".to_string()),
            password: Some("supersecret".to_string()),
        };
        let debug_str = format!("{:?}", peer);
        assert!(!debug_str.contains("supersecret"));
        assert!(debug_str.contains("redacted"));
    }

    #[test]
    fn relay_peer_username_without_password_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
username = "user"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("password")),
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn relay_peer_empty_host_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = ""
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn relay_peers_with_empty_queue_dir_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[delivery]
smtp_relay_queue_dir = "   "

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("smtp_relay_queue_dir"))
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    // ── T1: valid CIDRs in peer_whitelist parse correctly ──────────────────
    //
    // Oracle: ipnet::IpNet::from_str accepts "10.0.0.0/8" and "2001:db8::/32"
    // per the ipnet crate docs and RFC 4632 / RFC 4291 notation.
    // peer_whitelist must appear before [listen] so TOML treats it as a
    // top-level key, not listen.peer_whitelist.
    #[test]
    fn peer_whitelist_valid_cidrs_parse() {
        let toml = r#"
peer_whitelist = ["10.0.0.0/8", "2001:db8::/32"]

[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.peer_whitelist.len(), 2);
    }

    // ── T2: invalid CIDR in peer_whitelist fails deserialization ───────────
    //
    // Oracle: "not_a_cidr" fails IpNet FromStr, which serde propagates as a
    // parse error.
    #[test]
    fn peer_whitelist_invalid_cidr_fails_deserialization() {
        let toml = r#"
peer_whitelist = ["not_a_cidr"]

[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    // ── T3: peer_whitelist absent → empty Vec (serde(default)) ────────────
    //
    // Oracle: #[serde(default)] on Vec<T> yields an empty Vec when the key is
    // absent — guaranteed by the Rust std Default impl for Vec.
    #[test]
    fn peer_whitelist_absent_is_empty_default() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.peer_whitelist.is_empty());
    }

    // ── Helper for T4–T8: normalization + containment via production code ──
    //
    // Parses peer_addr as a SocketAddr to extract the IP, then delegates
    // normalization to the production `normalize_peer_ip` function so that
    // T7 actually exercises session.rs:normalize_peer_ip rather than a
    // local re-implementation.
    fn whitelist_check(whitelist: &[&str], peer_addr: &str) -> bool {
        use std::net::{IpAddr, SocketAddr};

        let client_ip: IpAddr = peer_addr
            .parse::<SocketAddr>()
            .map(|sa| sa.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));

        let client_ip = crate::session::normalize_peer_ip(client_ip);

        whitelist
            .iter()
            .map(|s| s.parse::<IpNet>().unwrap())
            .any(|net| net.contains(&client_ip))
    }

    // ── T4: whitelisted IP matches ─────────────────────────────────────────
    //
    // Oracle: 192.168.1.50 ∈ 192.168.0.0/16 — RFC 1918 block, ipnet contains
    // semantics.
    #[test]
    fn peer_whitelist_whitelisted_ip_matches() {
        assert!(whitelist_check(&["192.168.0.0/16"], "192.168.1.50:12345"));
    }

    // ── T5: non-whitelisted IP does not match ──────────────────────────────
    //
    // Oracle: 10.0.0.1 ∉ 192.168.0.0/16 — different RFC 1918 block.
    #[test]
    fn peer_whitelist_non_whitelisted_ip_no_match() {
        assert!(!whitelist_check(&["192.168.0.0/16"], "10.0.0.1:12345"));
    }

    // ── T6: empty whitelist never matches ─────────────────────────────────
    //
    // Oracle: Iterator::any() on an empty iterator always returns false —
    // Rust std guarantee.
    #[test]
    fn peer_whitelist_empty_never_matches() {
        assert!(!whitelist_check(&[], "192.168.1.50:12345"));
    }

    // ── T7: IPv4-mapped IPv6 is normalized and matches IPv4 CIDR ──────────
    //
    // Oracle: RFC 4291 §2.5.5.2 — ::ffff:192.168.1.50 is the IPv4-mapped
    // representation of 192.168.1.50.  After normalization the address must
    // match an IPv4 CIDR that covers 192.168.1.50.  This is the regression
    // test for the IPv4-mapped normalization path.
    #[test]
    fn peer_whitelist_ipv4_mapped_ipv6_matches_ipv4_cidr() {
        assert!(whitelist_check(
            &["192.168.0.0/16"],
            "[::ffff:192.168.1.50]:12345"
        ));
    }

    // ── T8: native IPv6 address matches IPv6 CIDR ─────────────────────────
    //
    // Oracle: fd00::1 ∈ fd00::/8 — per ipnet contains semantics for IPv6.
    #[test]
    fn peer_whitelist_ipv6_cidr_matches_ipv6_addr() {
        assert!(whitelist_check(&["fd00::/8"], "[fd00::1]:12345"));
    }

    // ── DKIM config validation tests ───────────────────────────────────────
    //
    // Oracle: 32 zero bytes base64-encodes to
    //   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    // 16 zero bytes base64-encodes to "AAAAAAAAAAAAAAAAAAAAAA=="
    // Verified independently with: python3 -c "import base64; print(base64.b64encode(bytes(32)))"

    fn minimal_toml_with_dkim(extra: &str) -> String {
        format!(
            r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

{extra}
"#
        )
    }

    #[test]
    fn test_dkim_config_valid() {
        // RFC 8463 §A.2 test vectors: seed "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
        // public key "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" — these are a matched pair.
        let toml = minimal_toml_with_dkim(
            r#"[delivery.dkim]
domain = "example.com"
selector = "mail"
key_seed_b64 = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
public_key_b64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=""#,
        );
        let f = write_toml(&toml);
        Config::from_file(f.path()).expect("valid dkim config should pass validation");
    }

    #[test]
    fn test_dkim_config_missing_domain() {
        let toml = minimal_toml_with_dkim(
            r#"[delivery.dkim]
domain = ""
selector = "mail"
key_seed_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
public_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#,
        );
        let f = write_toml(&toml);
        let err = Config::from_file(f.path()).expect_err("empty domain should fail");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("domain"), "msg={msg}"),
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn test_dkim_config_bad_seed_b64() {
        let toml = minimal_toml_with_dkim(
            r#"[delivery.dkim]
domain = "example.com"
selector = "mail"
key_seed_b64 = "!!!"
public_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#,
        );
        let f = write_toml(&toml);
        let err = Config::from_file(f.path()).expect_err("bad base64 should fail");
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("key_seed_b64"), "msg={msg}")
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn test_dkim_config_bad_seed_length() {
        // 16 zero bytes in base64 — valid base64 but wrong length
        let toml = minimal_toml_with_dkim(
            r#"[delivery.dkim]
domain = "example.com"
selector = "mail"
key_seed_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="
public_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#,
        );
        let f = write_toml(&toml);
        let err = Config::from_file(f.path()).expect_err("16-byte seed should fail");
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("32 bytes"), "msg={msg}")
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn test_dkim_config_absent() {
        let toml = minimal_toml_with_dkim("");
        let f = write_toml(&toml);
        let cfg = Config::from_file(f.path()).expect("absent dkim should pass validation");
        assert!(cfg.delivery.dkim.is_none());
    }

    // ── T: secretx URI for key_seed_b64 skips base64 validation ──────────
    //
    // Oracle: a `secretx:` prefix must bypass the base64/length check so that
    // the server can load its config before secretx resolution runs.  The
    // value is intentionally a well-formed secretx URI whose payload cannot
    // be resolved at test time; validation must still return Ok because the
    // seed check is deferred to post-resolution startup.
    #[test]
    fn test_dkim_config_secretx_seed_skips_validation() {
        let toml = minimal_toml_with_dkim(
            r#"[delivery.dkim]
domain = "example.com"
selector = "mail"
key_seed_b64 = "secretx:file:///dev/null"
public_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#,
        );
        let f = write_toml(&toml);
        Config::from_file(f.path())
            .expect("secretx URI for key_seed_b64 must pass config validation");
    }
}
