use serde::Deserialize;
use std::path::Path;
use stoa_auth::looks_like_bcrypt_hash;
pub use stoa_core::util::is_loopback_addr;
use stoa_core::util::is_loopback_url_host;

// Re-export stoa_auth::UserCredential so AuthConfig::users (Vec<UserCredential>)
// resolves to the same type that stoa_auth::CredentialStore::from_credentials()
// expects, with no conversion shim needed at call sites.
pub use stoa_auth::{ClientCertEntry, TrustedIssuerEntry, UserCredential};

// ── Backend config (pluggable block store) ────────────────────────────────────
// Types are defined in stoa_core::ipfs_backend and re-exported here so that
// reader config validation code can use them without a long path prefix.
pub use stoa_core::ipfs_backend::{
    AzureBackendConfig, BackendConfig, BackendType, FsBackendConfig, GcsBackendConfig,
    GitSha256BackendConfig, KuboBackendConfig, LmdbBackendConfig, PgBlobBackendConfig,
    RocksDbBackendConfig, S3BackendConfig, SqliteBackendConfig, WebDavBackendConfig,
};

/// Default hostname for the NNTP Path: header injected on POST.
fn default_path_hostname() -> String {
    "localhost".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Hostname used to build the Path: header on incoming NNTP POST articles
    /// (RFC 5536 §3.1).  Defaults to `"localhost"`.
    #[serde(default = "default_path_hostname")]
    pub path_hostname: String,
    pub listen: ListenConfig,
    pub limits: LimitsConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    /// Legacy Kubo connection settings.  Retained for backward compatibility.
    /// New deployments should use `[backend]` instead.
    #[serde(default)]
    pub ipfs: IpfsConfig,
    /// Pluggable block store backend.  When present, takes precedence over `[ipfs]`.
    #[serde(default)]
    pub backend: Option<BackendConfig>,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub smtp_relay: SmtpRelayConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub audit: stoa_core::audit::AuditConfig,
    /// OpenTelemetry observability configuration.  Omit for Prometheus-only mode.
    #[serde(default)]
    pub telemetry: stoa_core::telemetry::TelemetryConfig,
    /// When true, the server sends 201 in the greeting and rejects POST with 440.
    /// Default: false (posting allowed).
    #[serde(default)]
    pub read_only: bool,
}

/// Database URL configuration for the reader daemon.
///
/// Three separate databases are required because `sqlx` validates that every
/// previously-applied migration is still present in the migrator; mixing
/// schemas in a single pool would cause `VersionMissing` errors.
///
/// URL format:
/// - SQLite: `sqlite:///absolute/path/to/file.db`
/// - PostgreSQL: `postgres://user:pass@host/dbname`
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// URL for the reader-schema database (article_numbers, overview).
    /// Created if it does not exist (SQLite). Default: `sqlite:///reader.db`.
    #[serde(default = "DatabaseConfig::default_reader_url")]
    pub reader_url: String,
    /// URL for the core-schema database (msgid_map).
    /// Created if it does not exist (SQLite). Default: `sqlite:///reader_core.db`.
    #[serde(default = "DatabaseConfig::default_core_url")]
    pub core_url: String,
    /// URL for the verify-schema database (article_verifications, seen_keys).
    /// Created if it does not exist (SQLite). Default: `sqlite:///reader_verify.db`.
    #[serde(default = "DatabaseConfig::default_verify_url")]
    pub verify_url: String,
    /// URL for the transit-schema database (transit_staging).
    ///
    /// When set, the reader opens a read-only connection pool to the transit
    /// daemon's database so that ARTICLE/HEAD/BODY/STAT commands can serve
    /// articles that are staged but not yet written to IPFS.  Set this to the
    /// same value as transit's `database.url` (`sqlite:///transit.db`).
    ///
    /// Optional.  When absent, staged-but-not-yet-IPFS articles return 430.
    #[serde(default)]
    pub transit_url: Option<String>,
}

impl DatabaseConfig {
    fn default_reader_url() -> String {
        "sqlite:///reader.db".to_owned()
    }
    fn default_core_url() -> String {
        "sqlite:///reader_core.db".to_owned()
    }
    fn default_verify_url() -> String {
        "sqlite:///reader_verify.db".to_owned()
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            reader_url: Self::default_reader_url(),
            core_url: Self::default_core_url(),
            verify_url: Self::default_verify_url(),
            transit_url: None,
        }
    }
}

/// Configuration for outbound SMTP relay of posted articles.
///
/// When `peers` is non-empty and `queue_dir` is set, articles that arrive
/// via NNTP POST and contain email recipients in their `To:` or `Cc:` headers
/// are enqueued for SMTP relay delivery.  Failures are non-fatal — the NNTP
/// POST still returns 240.
#[derive(Debug, Deserialize, Default)]
pub struct SmtpRelayConfig {
    /// Directory for queued outbound SMTP relay messages.
    /// When absent, SMTP relay is disabled regardless of `peers`.
    #[serde(default)]
    pub queue_dir: Option<String>,
    /// Outbound SMTP relay peers.  An empty list disables relay delivery.
    #[serde(default)]
    pub peers: Vec<stoa_smtp::config::SmtpRelayPeerConfig>,
    /// Seconds a peer stays in the "down" state after a delivery failure
    /// before being retried.  Defaults to 300.
    #[serde(default = "SmtpRelayConfig::default_peer_down_secs")]
    pub peer_down_secs: u64,
    /// Optional DKIM signing configuration for outbound SMTP relay messages.
    /// When absent, relayed messages are not DKIM-signed.
    #[serde(default)]
    pub dkim: Option<stoa_smtp::config::DkimConfig>,
    /// Whether MTA-STS enforcement (RFC 8461) is enabled for outbound delivery.
    ///
    /// When `true`, before each delivery attempt the enforcer looks up the
    /// recipient domain's MTA-STS policy and blocks plaintext or MX-mismatched
    /// connections when the policy mode is `enforce`.  Policy fetch failures
    /// are non-blocking per RFC 8461 §2.  Default: `false`.
    #[serde(default)]
    pub mta_sts_enabled: bool,
    /// Connect+read timeout in milliseconds for HTTPS policy fetch.
    /// Default: 10000 (10 s).
    #[serde(default = "SmtpRelayConfig::default_mta_sts_fetch_timeout_ms")]
    pub mta_sts_fetch_timeout_ms: u64,
    /// Maximum policy body size in bytes accepted from remote servers.
    /// Default: 65536 (64 KiB).
    #[serde(default = "SmtpRelayConfig::default_mta_sts_max_policy_body_bytes")]
    pub mta_sts_max_policy_body_bytes: usize,
}

impl SmtpRelayConfig {
    fn default_peer_down_secs() -> u64 {
        300
    }

    fn default_mta_sts_fetch_timeout_ms() -> u64 {
        10_000
    }

    fn default_mta_sts_max_policy_body_bytes() -> usize {
        65_536
    }
}

/// Kubo IPFS node connection and local block cache settings.
#[derive(Debug, Deserialize)]
pub struct IpfsConfig {
    /// Kubo HTTP RPC API URL (e.g. `"http://127.0.0.1:5001"`).
    #[serde(default = "IpfsConfig::default_api_url")]
    pub api_url: String,
    /// Directory for the local block cache. Created at startup if absent.
    /// Omit to disable caching (every block fetch goes directly to Kubo).
    #[serde(default)]
    pub cache_path: Option<String>,
}

impl IpfsConfig {
    fn default_api_url() -> String {
        // Intentionally empty. Previously defaulted to "http://127.0.0.1:5001", which
        // silently assumed a local Kubo daemon. Config validation now rejects an empty
        // api_url when no [backend] section is present, forcing operators to be explicit.
        // Upgrade note: if your config omits [ipfs], add:
        //   [ipfs]
        //   api_url = "http://127.0.0.1:5001"
        // or switch to a [backend] section.
        String::new()
    }
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: Self::default_api_url(),
            cache_path: None,
        }
    }
}

/// Operator identity configuration.
#[derive(Debug, Deserialize, Default)]
pub struct OperatorConfig {
    /// Path to the 32-byte raw Ed25519 operator signing key seed file.
    ///
    /// The file must contain exactly 32 bytes (the Ed25519 seed / private scalar).
    /// If unset, an ephemeral key is generated at startup — articles signed by
    /// different process instances will have different keys and cannot be
    /// cross-verified.  Set this for any production deployment.
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Email address for the `mail-complaints-to` field in the
    /// `Injection-Info:` header (RFC 5536 §3.2.9).
    ///
    /// When set, every article injected via NNTP POST includes:
    /// `Injection-Info: ...; mail-complaints-to="<address>"`.
    /// Omit to suppress the field.
    #[serde(default)]
    pub mail_complaints_to: Option<String>,
}

/// Full-text search configuration (Tantivy-backed).
#[derive(Debug, Deserialize, Clone)]
pub struct SearchConfig {
    /// Directory where Tantivy index is stored. None = search disabled.
    pub index_dir: Option<String>,
    /// Max total index size in bytes before old entries are evicted (soft limit).
    #[serde(default = "SearchConfig::default_max_index_bytes")]
    pub max_index_bytes: u64,
    /// Max bytes of body text indexed per article (truncate beyond this).
    #[serde(default = "SearchConfig::default_body_index_max_bytes")]
    pub body_index_max_bytes: usize,
    /// Max length of a SEARCH query string (bytes) before rejecting with syntax error.
    #[serde(default = "SearchConfig::default_max_query_len")]
    pub max_query_len: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            index_dir: None,
            max_index_bytes: Self::default_max_index_bytes(),
            body_index_max_bytes: Self::default_body_index_max_bytes(),
            max_query_len: Self::default_max_query_len(),
        }
    }
}

impl SearchConfig {
    fn default_max_index_bytes() -> u64 {
        10_737_418_240 // 10 GiB
    }

    fn default_body_index_max_bytes() -> usize {
        102_400 // 100 KiB
    }

    fn default_max_query_len() -> usize {
        4096
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// Socket address for the NNTP reader listener.
    ///
    /// Format: `IP:port` or `[IPv6]:port`. Port 119 is the NNTP standard.
    /// Production (public): `"0.0.0.0:119"` — binds all interfaces.
    /// Development (local only): `"127.0.0.1:119"`.
    /// Binding to a non-loopback address exposes NNTP to the network; pair with
    /// TLS (port 563 / NNTPS) or restrict access via firewall when public-facing.
    pub addr: String,
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub command_timeout_secs: u64,
    /// Seconds to wait for a POST body to be fully uploaded.  Default: 300.
    ///
    /// A slow-uploading client that sends one byte at a time would otherwise
    /// hold a session open indefinitely.  The connection is closed with a 400
    /// response if the upload does not complete within this window.
    #[serde(default = "default_post_body_timeout_secs")]
    pub post_body_timeout_secs: u64,
    /// Maximum accepted article size in bytes for POST.  Default: 1 MiB.
    ///
    /// Articles larger than this value are rejected with 441 after the body is
    /// fully drained (so the NNTP connection stays valid for subsequent commands).
    /// Operators who want to reduce storage load or enforce a site policy can
    /// lower this value; operators who carry large text articles can raise it.
    #[serde(default = "default_max_article_bytes")]
    pub max_article_bytes: usize,
    /// Seconds to wait for in-flight connections to finish after a shutdown
    /// signal before forcing exit.  Default: 30.  Set to 0 to exit immediately.
    #[serde(default)]
    pub drain_timeout_secs: Option<u64>,
    /// Emit a WARN log for NNTP commands slower than this many milliseconds.
    /// 0 disables slow-command WARN events; the histogram is always recorded.
    /// Default: 1000 ms.
    #[serde(default = "default_slow_command_threshold_ms")]
    pub slow_command_threshold_ms: u64,
    /// Maximum allowed clock skew between the article's `Date:` header and
    /// server time (seconds).  When set and the skew exceeds this threshold,
    /// an `Injection-Date:` header is added with the server's current time
    /// (RFC 5536 §3.2.3).  When absent, no `Injection-Date:` is ever added.
    #[serde(default)]
    pub max_clock_skew_secs: Option<u64>,
}

fn default_slow_command_threshold_ms() -> u64 {
    1000
}

fn default_max_connections() -> usize {
    100
}

fn default_post_body_timeout_secs() -> u64 {
    300
}

fn default_max_article_bytes() -> usize {
    // Match DEFAULT_MAX_ARTICLE_BYTES in crates/reader/src/session/commands/post.rs.
    1_048_576
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub required: bool,
    /// User accounts for AUTHINFO USER/PASS authentication.
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
    /// Attempted only after fingerprint-based auth has been tried first.
    /// Only valid on NNTPS (port 563) connections.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuerEntry>,
    /// OIDC provider configurations for SASL OAUTHBEARER (RFC 7628).
    ///
    /// When non-empty, `AUTHINFO SASL OAUTHBEARER` is advertised in
    /// CAPABILITIES.  Clients may authenticate by presenting a Bearer JWT
    /// that validates against any configured provider.
    #[serde(default)]
    pub oidc_providers: Vec<stoa_auth::OidcProviderConfig>,
    /// Username of the SMTP queue drain service account.
    ///
    /// When set and a session authenticates with this username (via AUTHINFO
    /// USER/PASS), the session is marked as a trusted drain session.  Only
    /// drain sessions are allowed to set the article's `InjectionSource` via
    /// the `X-Stoa-Injection-Source` header — all other sessions have the
    /// header stripped and are always classified as `NntpPost`.
    ///
    /// The drain user's bcrypt hash must appear in `users` or `credential_file`
    /// alongside regular user credentials.  Case-insensitive match.
    #[serde(default)]
    pub drain_username: Option<String>,
}

impl AuthConfig {
    /// Returns `true` when no credentials are configured and auth is not
    /// required — the development / open-access mode.
    pub fn is_dev_mode(&self) -> bool {
        !self.required
            && self.users.is_empty()
            && self.credential_file.is_none()
            && self.oidc_providers.is_empty()
            && self.client_certs.is_empty()
            && self.trusted_issuers.is_empty()
    }
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Bind address for the NNTPS listener (implicit TLS, port 563 by convention).
    ///
    /// When set, a second TCP listener is started at this address and every
    /// connection is wrapped in TLS before any NNTP bytes are exchanged.
    /// Requires `cert_path` and `key_path` to also be set.
    pub tls_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Whether the admin HTTP endpoint is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Address to bind the admin HTTP endpoint.
    /// Default: 127.0.0.1:9090 (loopback-only).
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    /// Bearer token for admin endpoint authentication.
    ///
    /// Required when `addr` is a non-loopback address — the server refuses to
    /// start on a reachable interface without a token (fail-closed).
    /// Optional on loopback; omitting it leaves the endpoint open to any local
    /// process, which is acceptable in a trusted environment.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// Maximum requests per minute per IP (default 60). 0 = unlimited.
    #[serde(default = "default_admin_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_rate_limit_rpm() -> u32 {
    60
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: default_admin_addr(),
            admin_token: None,
            rate_limit_rpm: default_admin_rate_limit_rpm(),
        }
    }
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
    /// Log level filter (e.g. "info", "debug", "stoa_reader=debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_level() -> String {
    "info".to_owned()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
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
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let mut config: Config = match path {
            Some(p) => {
                let content =
                    std::fs::read_to_string(p).map_err(|e| ConfigError::Io(e.to_string()))?;
                toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?
            }
            None => toml::from_str(
                r#"
[listen]
addr = ""
"#,
            )
            .expect("internal default TOML is valid"),
        };
        config.apply_env();
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) {
        fn env_str(var: &str, field: &mut String) {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    *field = v;
                }
            }
        }
        env_str("STOA_NNTP_ADDR", &mut self.listen.addr);
        if let Ok(v) = std::env::var("STOA_TLS_CERT_PATH") {
            self.tls.cert_path = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("STOA_TLS_KEY_PATH") {
            self.tls.key_path = if v.is_empty() { None } else { Some(v) };
        }
        env_str("STOA_DB_URL", &mut self.database.reader_url);
        env_str("STOA_DB_READER_URL", &mut self.database.reader_url);
        env_str("STOA_DB_CORE_URL", &mut self.database.core_url);
        env_str("STOA_DB_VERIFY_URL", &mut self.database.verify_url);
        env_str("STOA_LOG_LEVEL", &mut self.log.level);
        if let Ok(fmt) = std::env::var("STOA_LOG_FORMAT") {
            match fmt.to_lowercase().as_str() {
                "json" => self.log.format = LogFormat::Json,
                "text" => self.log.format = LogFormat::Text,
                _ => {}
            }
        }
    }

    /// Returns the effective Kubo API URL: `[backend.kubo.api_url]` when a Kubo
    /// backend is configured, otherwise `[ipfs.api_url]`.  Returns `None` when
    /// a non-Kubo backend is selected (no connectivity check is needed).
    pub fn kubo_api_url(&self) -> Option<&str> {
        if let Some(backend) = &self.backend {
            match &backend.backend_type {
                BackendType::Kubo => backend.kubo.as_ref().map(|k| k.api_url.as_str()),
                _ => None,
            }
        } else if !self.ipfs.api_url.is_empty() {
            Some(self.ipfs.api_url.as_str())
        } else {
            None
        }
    }

    pub fn from_file(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the parsed configuration against structural invariants that can
    /// be evaluated at parse time (field combinations, URL formats, credential
    /// pairings).
    ///
    /// Guards in `validate()` check structural config invariants that can be
    /// evaluated at parse time (field combinations, URL formats, credential pairings).
    /// Guards in `main.rs` check runtime invariants that require context not available
    /// at parse time (listen address resolution, signing key file existence).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation(
                "listen.addr must not be empty".into(),
            ));
        }
        if self.limits.max_connections == 0 {
            return Err(ConfigError::Validation(
                "limits.max_connections must be greater than 0".into(),
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
        if self.tls.tls_addr.is_some()
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(ConfigError::Validation(
                "tls.tls_addr requires tls.cert_path and tls.key_path to be set".into(),
            ));
        }
        if let Some(backend) = &self.backend {
            match &backend.backend_type {
                BackendType::Kubo => {
                    if backend.kubo.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'kubo' requires a [backend.kubo] section".into(),
                        ));
                    }
                }
                BackendType::Lmdb => {
                    if backend.lmdb.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'lmdb' requires a [backend.lmdb] section".into(),
                        ));
                    }
                    if let Some(lmdb) = &backend.lmdb {
                        if lmdb.map_size_gb == 0 {
                            return Err(ConfigError::Validation(
                                "backend.lmdb.map_size_gb must be ≥ 1".into(),
                            ));
                        }
                        // Mirror the overflow check in LmdbBlockDb::open().
                        const GIB: u64 = 1024 * 1024 * 1024;
                        let platform_max_gb = usize::MAX as u64 / GIB;
                        if lmdb.map_size_gb > platform_max_gb {
                            return Err(ConfigError::Validation(format!(
                                "backend.lmdb.map_size_gb {} exceeds platform maximum {}",
                                lmdb.map_size_gb, platform_max_gb
                            )));
                        }
                    }
                }
                BackendType::Filesystem => {
                    if backend.filesystem.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'filesystem' requires a [backend.filesystem] section"
                                .into(),
                        ));
                    }
                }
                BackendType::Sqlite => {
                    if backend.sqlite.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'sqlite' requires a [backend.sqlite] section".into(),
                        ));
                    }
                }
                BackendType::S3 => {
                    let s3 = backend.s3.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 's3' requires a [backend.s3] section".into(),
                        )
                    })?;
                    if s3.bucket.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.s3.bucket must not be empty".into(),
                        ));
                    }
                    if s3.region.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.s3.region must not be empty".into(),
                        ));
                    }
                    // Validate secretx URI syntax for credentials.
                    for (field, val) in [
                        ("backend.s3.access_key_id", s3.access_key_id.as_deref()),
                        (
                            "backend.s3.secret_access_key",
                            s3.secret_access_key.as_deref(),
                        ),
                    ] {
                        if let Some(v) = val {
                            if v.starts_with("secretx:") {
                                if let Err(e) = secretx::from_uri(v) {
                                    return Err(ConfigError::Validation(format!(
                                        "{field}: invalid secretx URI: {e}"
                                    )));
                                }
                            }
                        }
                    }
                    // Guard: allow_http = true with explicit credentials on a non-loopback
                    // S3-compatible endpoint transmits AWS keys in cleartext.
                    if s3.allow_http.unwrap_or(false)
                        && (s3.access_key_id.is_some() || s3.secret_access_key.is_some())
                    {
                        if let Some(endpoint_url) = &s3.endpoint {
                            if !is_loopback_url_host(endpoint_url) {
                                let host_display = endpoint_url
                                    .find("://")
                                    .map(|i| &endpoint_url[i + 3..])
                                    .and_then(|s| s.split('/').next())
                                    .unwrap_or("(endpoint)");
                                return Err(ConfigError::Validation(format!(
                                     "backend.s3.allow_http = true with credentials configured \
                                      transmits your access keys in cleartext to {host_display}. \
                                      Use https:// and set allow_http = false, \
                                      or change the endpoint to a loopback address for local testing."
                                 )));
                            }
                        }
                    }
                }
                BackendType::Azure => {
                    let azure = backend.azure.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'azure' requires a [backend.azure] section".into(),
                        )
                    })?;
                    if azure.account.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.azure.account must not be empty".into(),
                        ));
                    }
                    if azure.container.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.azure.container must not be empty".into(),
                        ));
                    }
                    if azure.use_emulator.unwrap_or(false) && azure.endpoint.is_some() {
                        return Err(ConfigError::Validation(
                            "backend.azure: use_emulator = true and endpoint are mutually exclusive; \
                             use_emulator implies the Azurite well-known URL".into(),
                        ));
                    }
                    if azure.use_emulator.unwrap_or(false) && !is_loopback_addr(&self.listen.addr) {
                        return Err(ConfigError::Validation(format!(
                            "backend.azure.use_emulator = true is a local development setting \
                             (Azurite). The daemon is listening on {} which is a non-loopback \
                             address. Set listen.addr to 127.0.0.1 for local testing, or set \
                             use_emulator = false for production Azure.",
                            self.listen.addr
                        )));
                    }
                    if let Some(v) = azure.access_key.as_deref() {
                        if v.starts_with("secretx:") {
                            if let Err(e) = secretx::from_uri(v) {
                                return Err(ConfigError::Validation(format!(
                                    "backend.azure.access_key: invalid secretx URI: {e}"
                                )));
                            }
                        }
                    }
                    // Fatal guard: allow_http = true with an access_key on a
                    // non-loopback custom endpoint transmits credentials in cleartext.
                    // Azurite (use_emulator = true) is always loopback — skip that case.
                    if azure.allow_http.unwrap_or(false)
                        && azure.access_key.is_some()
                        && !azure.use_emulator.unwrap_or(false)
                    {
                        if let Some(endpoint_url) = &azure.endpoint {
                            if !is_loopback_url_host(endpoint_url) {
                                let host_display = endpoint_url
                                    .find("://")
                                    .map(|i| &endpoint_url[i + 3..])
                                    .and_then(|s| s.split('/').next())
                                    .unwrap_or("(endpoint)");
                                return Err(ConfigError::Validation(format!(
                                    "backend.azure.allow_http = true with access_key configured \
                                     transmits your credentials in cleartext to {host_display}. \
                                     Use https:// and set allow_http = false, \
                                     or change the endpoint to a loopback address for local testing."
                                )));
                            }
                        }
                    }
                }
                BackendType::Gcs => {
                    let gcs = backend.gcs.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'gcs' requires a [backend.gcs] section".into(),
                        )
                    })?;
                    if gcs.bucket.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.gcs.bucket must not be empty".into(),
                        ));
                    }
                    if gcs.service_account_path.is_some() && gcs.service_account_key.is_some() {
                        return Err(ConfigError::Validation(
                            "backend.gcs: service_account_path and service_account_key are \
                             mutually exclusive; set at most one"
                                .into(),
                        ));
                    }
                    if let Some(v) = gcs.service_account_key.as_deref() {
                        if v.starts_with("secretx:") {
                            if let Err(e) = secretx::from_uri(v) {
                                return Err(ConfigError::Validation(format!(
                                    "backend.gcs.service_account_key: invalid secretx URI: {e}"
                                )));
                            }
                        } else if !v.starts_with('{') {
                            return Err(ConfigError::Validation(
                                "backend.gcs.service_account_key must be a JSON object \
                                 starting with '{' or a secretx:// URI"
                                    .into(),
                            ));
                        }
                    }
                }
                BackendType::WebDav => {
                    let webdav = backend.webdav.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'web_dav' requires a [backend.webdav] section".into(),
                        )
                    })?;
                    if webdav.url.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.webdav.url must not be empty".into(),
                        ));
                    }
                    if webdav.url.ends_with('/') {
                        return Err(ConfigError::Validation(
                            "backend.webdav.url must not end with a trailing slash".into(),
                        ));
                    }
                    if !webdav.allow_http.unwrap_or(false) && webdav.url.starts_with("http://") {
                        return Err(ConfigError::Validation(
                            "backend.webdav.url uses plain HTTP; set allow_http = true to \
                             permit (not recommended when credentials are configured)"
                                .into(),
                        ));
                    }
                    if webdav.username.is_some() != webdav.password.is_some() {
                        return Err(ConfigError::Validation(
                            "backend.webdav: username and password must both be set or both \
                             be absent; partial credentials are not supported"
                                .into(),
                        ));
                    }
                    if let Some(v) = webdav.password.as_deref() {
                        if v.starts_with("secretx:") {
                            if let Err(e) = secretx::from_uri(v) {
                                return Err(ConfigError::Validation(format!(
                                    "backend.webdav.password: invalid secretx URI: {e}"
                                )));
                            }
                        }
                    }
                    // Fatal guard: allow_http = true with credentials on a non-loopback
                    // host transmits the password in cleartext over the network.
                    if webdav.allow_http.unwrap_or(false)
                        && webdav.password.is_some()
                        && !is_loopback_url_host(&webdav.url)
                    {
                        let host_display = webdav
                            .url
                            .find("://")
                            .map(|i| &webdav.url[i + 3..])
                            .and_then(|s| s.split('/').next())
                            .unwrap_or("(url)");
                        return Err(ConfigError::Validation(format!(
                            "backend.webdav.allow_http = true with credentials configured \
                             transmits your password in cleartext to {host_display}. \
                             Use https:// and set allow_http = false, \
                             or change the URL to a loopback address for local testing."
                        )));
                    }
                }
                BackendType::RocksDb => {
                    let rocksdb = backend.rocksdb.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'rocks_db' requires a [backend.rocksdb] section".into(),
                        )
                    })?;
                    if rocksdb.path.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.rocksdb.path must not be empty".into(),
                        ));
                    }
                }
                BackendType::PgBlob => {
                    let pg = backend.pg_blob.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'pg_blob' requires a [backend.pg_blob] section".into(),
                        )
                    })?;
                    if pg.database_url.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.pg_blob.database_url must not be empty".into(),
                        ));
                    }
                }
                BackendType::GitSha256 => {
                    let git = backend.git_sha256.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'git_sha256' requires a [backend.git_sha256] section"
                                .into(),
                        )
                    })?;
                    if git.repo_path.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.git_sha256.repo_path must not be empty".into(),
                        ));
                    }
                    if git.index_db.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.git_sha256.index_db must not be empty".into(),
                        ));
                    }
                }
                BackendType::Rados => {
                    return Err(ConfigError::Validation(
                        "backend.type = 'rados' is not supported in stoa-reader; \
                         use the S3 backend pointed at RADOS Gateway instead"
                            .into(),
                    ));
                }
            }
        } else if self.ipfs.api_url.is_empty() {
            return Err(ConfigError::Validation(
                "either [backend] or [ipfs] with a non-empty api_url is required".into(),
            ));
        }
        for cred in &self.auth.users {
            if !looks_like_bcrypt_hash(&cred.password) {
                return Err(ConfigError::Validation(format!(
                    "auth.users['{}']: password is not a valid bcrypt hash (cost must be 4–31)",
                    cred.username
                )));
            }
        }
        if let Some(dcfg) = &self.smtp_relay.dkim {
            use base64::Engine as _;
            if dcfg.domain.is_empty() {
                return Err(ConfigError::Validation(
                    "smtp_relay.dkim.domain must not be empty".into(),
                ));
            }
            if dcfg.selector.is_empty() {
                return Err(ConfigError::Validation(
                    "smtp_relay.dkim.selector must not be empty".into(),
                ));
            }
            if !dcfg.key_seed_b64.starts_with("secretx:") {
                let mut seed_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&dcfg.key_seed_b64)
                    .map_err(|_| {
                        ConfigError::Validation(
                            "smtp_relay.dkim.key_seed_b64: invalid base64".into(),
                        )
                    })?;
                use zeroize::Zeroize as _;
                if seed_bytes.len() != 32 {
                    let got = seed_bytes.len();
                    seed_bytes.zeroize();
                    return Err(ConfigError::Validation(format!(
                        "smtp_relay.dkim.key_seed_b64: must decode to 32 bytes, got {}",
                        got
                    )));
                }
                seed_bytes.zeroize();
            }
            let pubkey_bytes = base64::engine::general_purpose::STANDARD
                .decode(&dcfg.public_key_b64)
                .map_err(|_| {
                    ConfigError::Validation("smtp_relay.dkim.public_key_b64: invalid base64".into())
                })?;
            if pubkey_bytes.len() != 32 {
                return Err(ConfigError::Validation(format!(
                    "smtp_relay.dkim.public_key_b64: must decode to 32 bytes, got {}",
                    pubkey_bytes.len()
                )));
            }
        }
        Ok(())
    }
}

/// Validate admin configuration.
///
/// Returns `Err` if `addr` is non-loopback and no `admin_token` is set —
/// an unauthenticated admin endpoint on a reachable interface is a security
/// footgun that the server must not start with (fail-closed).
/// Returns `Ok(())` if the configuration is safe.
pub fn check_admin_addr(admin: &AdminConfig) -> Result<(), String> {
    if !is_loopback_addr(&admin.addr) && admin.admin_token.is_none() {
        Err(format!(
            "admin endpoint at '{}' is on a non-loopback interface but \
             admin.admin_token is not configured — refusing to start an \
             unauthenticated admin server",
            admin.addr
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use stoa_auth::looks_like_bcrypt_hash;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    const VALID_TOML: &str = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 50
command_timeout_secs = 30

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/server.pem"
key_path = "/etc/ssl/private/server.key"

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;

    #[test]
    fn parse_valid_config() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "127.0.0.1:119");
        assert_eq!(cfg.limits.max_connections, 50);
        assert_eq!(cfg.limits.command_timeout_secs, 30);
        assert!(!cfg.auth.required);
        assert_eq!(
            cfg.tls.cert_path.as_deref(),
            Some("/etc/ssl/certs/server.pem")
        );
    }

    #[test]
    fn default_max_connections_applied() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
command_timeout_secs = 60

[auth]
required = false

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.max_connections, 100);
    }

    #[test]
    fn missing_listen_section_is_parse_error() {
        let toml = r#"
[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn zero_max_connections_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 0
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn mismatched_tls_fields_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/server.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn no_tls_fields_is_valid() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("no TLS is valid");
        assert!(cfg.tls.cert_path.is_none());
        assert!(cfg.tls.key_path.is_none());
    }

    #[test]
    fn io_error_on_missing_file() {
        let err =
            Config::from_file(Path::new("/nonexistent/path/reader.toml")).expect_err("should fail");
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn loopback_127_is_safe() {
        assert!(is_loopback_addr("127.0.0.1:9090"));
    }

    #[test]
    fn loopback_localhost_is_safe() {
        assert!(is_loopback_addr("localhost:9090"));
    }

    #[test]
    fn ipv6_loopback_is_safe() {
        assert!(is_loopback_addr("[::1]:9090"));
    }

    #[test]
    fn non_loopback_without_token_is_err() {
        let admin = AdminConfig {
            enabled: true,
            addr: "0.0.0.0:9090".to_string(),
            admin_token: None,
            rate_limit_rpm: 60,
        };
        let result = check_admin_addr(&admin);
        assert!(result.is_err(), "non-loopback without token must be Err");
        assert!(
            result.unwrap_err().contains("non-loopback"),
            "error message must mention non-loopback"
        );
    }

    #[test]
    fn non_loopback_with_token_is_ok() {
        let admin = AdminConfig {
            enabled: true,
            addr: "0.0.0.0:9090".to_string(),
            admin_token: Some("secret".to_string()),
            rate_limit_rpm: 60,
        };
        assert!(
            check_admin_addr(&admin).is_ok(),
            "non-loopback with token must be Ok"
        );
    }

    #[test]
    fn default_addr_is_loopback() {
        let admin = AdminConfig::default();
        assert!(
            is_loopback_addr(&admin.addr),
            "default addr must be loopback"
        );
        assert!(
            check_admin_addr(&admin).is_ok(),
            "default config must be Ok"
        );
    }

    #[test]
    fn search_config_defaults_to_disabled() {
        let cfg = SearchConfig::default();
        assert!(
            cfg.index_dir.is_none(),
            "search must be disabled by default"
        );
        assert_eq!(cfg.body_index_max_bytes, 102_400);
        assert_eq!(cfg.max_query_len, 4096);
    }

    #[test]
    fn drain_timeout_secs_defaults_to_none() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.drain_timeout_secs, None);
    }

    #[test]
    fn drain_timeout_secs_parses_from_toml() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 50
command_timeout_secs = 30
drain_timeout_secs = 60

[auth]
required = false

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.drain_timeout_secs, Some(60));
    }

    /// The semaphore drain pattern used in main() after shutdown signal.
    /// Verifies that acquire_many_owned(max) completes once all permits are released.
    #[tokio::test]
    async fn semaphore_drain_completes_when_sessions_finish() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let max: u32 = 100;
        let sem = Arc::new(Semaphore::new(max as usize));

        // Simulate 3 active sessions holding permits.
        let p1 = sem.clone().acquire_owned().await.unwrap();
        let p2 = sem.clone().acquire_owned().await.unwrap();
        let p3 = sem.clone().acquire_owned().await.unwrap();

        // Sessions finish after 50 ms.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(p1);
            drop(p2);
            drop(p3);
        });

        let result =
            tokio::time::timeout(Duration::from_secs(2), sem.acquire_many_owned(max)).await;
        assert!(result.is_ok(), "drain must complete before timeout");
    }

    /// [backend] with type = "lmdb" and a [backend.lmdb] subsection parses.
    #[test]
    fn backend_lmdb_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test-lmdb"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("backend.lmdb config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be present");
        assert_eq!(backend.backend_type, BackendType::Lmdb);
        let lmdb = backend.lmdb.as_ref().expect("backend.lmdb must be present");
        assert_eq!(lmdb.path, "/tmp/test-lmdb");
        assert_eq!(lmdb.map_size_gb, 1024, "default map_size_gb must be 1024");
        assert_eq!(cfg.kubo_api_url(), None);
    }

    /// [backend] with type = "lmdb" but no [backend.lmdb] subsection is rejected.
    #[test]
    fn backend_lmdb_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "lmdb"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.lmdb must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "kubo" but no [backend.kubo] subsection is rejected.
    #[test]
    fn backend_kubo_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "kubo"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.kubo must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "s3" is rejected as not yet implemented.
    #[test]
    fn backend_s3_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "s3"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("s3 backend must fail with not-yet-implemented error");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "s3" and a [backend.s3] section parses and validates.
    #[test]
    fn backend_s3_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "s3"

[backend.s3]
bucket = "stoa-articles"
region = "us-east-1"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("s3 backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::S3));
        assert_eq!(
            backend.s3.as_ref().map(|s| s.bucket.as_str()),
            Some("stoa-articles")
        );
        assert_eq!(
            backend.s3.as_ref().map(|s| s.region.as_str()),
            Some("us-east-1")
        );
    }

    /// [backend] with type = "s3" but no [backend.s3] section is rejected.
    #[test]
    fn backend_s3_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "s3"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("s3 without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.s3] with empty bucket is rejected.
    #[test]
    fn backend_s3_empty_bucket_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "s3"

[backend.s3]
bucket = ""
region = "us-east-1"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty bucket must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "azure" and a [backend.azure] section parses and validates.
    #[test]
    fn backend_azure_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"

[backend.azure]
account = "myaccount"
container = "stoa-articles"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("azure backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::Azure));
        assert_eq!(
            backend.azure.as_ref().map(|a| a.account.as_str()),
            Some("myaccount")
        );
        assert_eq!(
            backend.azure.as_ref().map(|a| a.container.as_str()),
            Some("stoa-articles")
        );
    }

    /// [backend] with type = "azure" but no [backend.azure] section is rejected.
    #[test]
    fn backend_azure_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("azure without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.azure] with empty account is rejected.
    #[test]
    fn backend_azure_empty_account_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"

[backend.azure]
account = ""
container = "stoa-articles"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty account must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "gcs" and a [backend.gcs] section parses and validates.
    #[test]
    fn backend_gcs_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "gcs"

[backend.gcs]
bucket = "stoa-articles"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("gcs backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::Gcs));
        assert_eq!(
            backend.gcs.as_ref().map(|g| g.bucket.as_str()),
            Some("stoa-articles")
        );
    }

    /// [backend] with type = "gcs" but no [backend.gcs] section is rejected.
    #[test]
    fn backend_gcs_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "gcs"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("gcs without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.azure] with use_emulator = true and endpoint set is rejected.
    #[test]
    fn backend_azure_emulator_and_endpoint_conflict() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true
endpoint = "http://127.0.0.1:10000"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("use_emulator + endpoint must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.gcs] with both service_account_path and service_account_key is rejected.
    #[test]
    fn backend_gcs_dual_credentials_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "gcs"

[backend.gcs]
bucket = "stoa-articles"
service_account_path = "/etc/sa.json"
service_account_key = "{}"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("dual GCS credentials must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "web_dav" and a [backend.webdav] section parses and validates.
    #[test]
    fn backend_webdav_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("webdav backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::WebDav));
        assert_eq!(
            backend.webdav.as_ref().map(|w| w.url.as_str()),
            Some("https://dav.example.com/stoa/blocks")
        );
    }

    /// [backend] with type = "web_dav" but no [backend.webdav] section is rejected.
    #[test]
    fn backend_webdav_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("web_dav without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.webdav] with empty url is rejected.
    #[test]
    fn backend_webdav_empty_url_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = ""
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty url must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.webdav] with http:// url and no allow_http is rejected.
    #[test]
    fn backend_webdav_http_url_without_allow_http_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = "http://dav.example.com/stoa/blocks"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("http:// without allow_http must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.webdav] with http:// url and allow_http = true is accepted.
    #[test]
    fn backend_webdav_http_url_with_allow_http_accepted() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = "http://127.0.0.1:8080/stoa/blocks"
allow_http = true
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("webdav with allow_http must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::WebDav));
    }

    /// [backend] with type = "rocks_db" and a [backend.rocksdb] section parses and validates.
    #[test]
    fn backend_rocksdb_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "rocks_db"

[backend.rocksdb]
path = "/var/lib/stoa/rocksdb"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("rocksdb backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::RocksDb));
        assert_eq!(
            backend.rocksdb.as_ref().map(|r| r.path.as_str()),
            Some("/var/lib/stoa/rocksdb")
        );
    }

    /// [backend] with type = "rocks_db" but no [backend.rocksdb] section is rejected.
    #[test]
    fn backend_rocksdb_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "rocks_db"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("rocks_db without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.rocksdb] with empty path is rejected.
    #[test]
    fn backend_rocksdb_empty_path_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "rocks_db"

[backend.rocksdb]
path = ""
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty path must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "rados" is rejected in reader (not supported).
    #[test]
    fn backend_rados_rejected_in_reader() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "rados"

[backend.rados]
pool = "stoa_blocks"
user = "stoa"
conf_path = "/etc/ceph/ceph.conf"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("rados backend must be rejected in reader");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.webdav] with a trailing slash in url is rejected.
    #[test]
    fn backend_webdav_trailing_slash_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks/"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("trailing slash must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.webdav] with username but no password is rejected.
    #[test]
    fn backend_webdav_username_without_password_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks"
username = "alice"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("username without password must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "filesystem" and a [backend.filesystem] section parses and validates.
    #[test]
    fn backend_filesystem_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "filesystem"

[backend.filesystem]
path = "/tmp/stoa-blocks"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("filesystem backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::Filesystem));
        assert_eq!(
            backend.filesystem.as_ref().map(|fs| fs.path.as_str()),
            Some("/tmp/stoa-blocks")
        );
    }

    /// [backend] with type = "filesystem" but no [backend.filesystem] section is rejected.
    #[test]
    fn backend_filesystem_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "filesystem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("filesystem without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "sqlite" and a [backend.sqlite] section parses correctly.
    #[test]
    fn backend_sqlite_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/stoa-blocks.db"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("sqlite backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::Sqlite));
        assert_eq!(
            backend.sqlite.as_ref().map(|s| s.path.as_str()),
            Some("/tmp/stoa-blocks.db")
        );
    }

    /// [backend] with type = "sqlite" but no [backend.sqlite] section is rejected.
    #[test]
    fn backend_sqlite_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "sqlite"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("sqlite without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "pg_blob" and a [backend.pg_blob] section parses and validates.
    #[test]
    fn backend_pg_blob_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "pg_blob"

[backend.pg_blob]
database_url = "postgres://stoa:secret@localhost/stoa"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("pg_blob backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::PgBlob));
        assert_eq!(
            backend.pg_blob.as_ref().map(|p| p.database_url.as_str()),
            Some("postgres://stoa:secret@localhost/stoa")
        );
    }

    /// [backend] with type = "pg_blob" but no [backend.pg_blob] section is rejected.
    #[test]
    fn backend_pg_blob_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "pg_blob"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("pg_blob without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.pg_blob] with empty database_url is rejected.
    #[test]
    fn backend_pg_blob_empty_url_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "pg_blob"

[backend.pg_blob]
database_url = ""
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("pg_blob with empty database_url must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "git_sha256" and a [backend.git_sha256] section parses and validates.
    #[test]
    fn backend_git_sha256_section_parses() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "git_sha256"

[backend.git_sha256]
repo_path = "/var/lib/stoa/articles.git"
index_db = "/var/lib/stoa/git_index.db"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("git_sha256 backend config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be set");
        assert!(matches!(backend.backend_type, BackendType::GitSha256));
        let git = backend
            .git_sha256
            .as_ref()
            .expect("git_sha256 section must be set");
        assert_eq!(git.repo_path, "/var/lib/stoa/articles.git");
        assert_eq!(git.index_db, "/var/lib/stoa/git_index.db");
    }

    /// [backend] with type = "git_sha256" but no [backend.git_sha256] section is rejected.
    #[test]
    fn backend_git_sha256_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "git_sha256"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("git_sha256 without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.git_sha256] with empty repo_path is rejected.
    #[test]
    fn backend_git_sha256_empty_repo_path_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "git_sha256"

[backend.git_sha256]
repo_path = ""
index_db = "/var/lib/stoa/git_index.db"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("git_sha256 with empty repo_path must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.lmdb] with map_size_gb = 0 is rejected.
    #[test]
    fn backend_lmdb_map_size_zero_rejected() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test"
map_size_gb = 0
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("map_size_gb = 0 must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// Missing both [backend] and [ipfs] is a validation error.
    #[test]
    fn missing_both_backend_and_ipfs_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing ipfs and backend must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    // ── looks_like_bcrypt_hash tests ──────────────────────────────────────────

    #[test]
    fn bcrypt_hash_2b_prefix_is_valid() {
        // Real bcrypt hash generated by htpasswd -bnBC 10 '' testpass
        let hash = "$2b$10$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            looks_like_bcrypt_hash(hash),
            "$2b$ hash must be accepted: {hash}"
        );
    }

    #[test]
    fn bcrypt_hash_2a_prefix_is_valid() {
        let hash = "$2a$10$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            looks_like_bcrypt_hash(hash),
            "$2a$ hash must be accepted: {hash}"
        );
    }

    #[test]
    fn bcrypt_hash_2x_prefix_is_valid() {
        let hash = "$2x$10$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            looks_like_bcrypt_hash(hash),
            "$2x$ hash must be accepted: {hash}"
        );
    }

    #[test]
    fn bcrypt_hash_2y_prefix_is_valid() {
        let hash = "$2y$10$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            looks_like_bcrypt_hash(hash),
            "$2y$ hash must be accepted: {hash}"
        );
    }

    #[test]
    fn plaintext_password_is_rejected() {
        assert!(
            !looks_like_bcrypt_hash("hunter2"),
            "plaintext 'hunter2' must not look like a bcrypt hash"
        );
    }

    #[test]
    fn empty_string_is_rejected() {
        assert!(
            !looks_like_bcrypt_hash(""),
            "empty string must not look like a bcrypt hash"
        );
    }

    #[test]
    fn bcrypt_hash_cost_below_minimum_is_rejected() {
        // Cost 3 is below the valid minimum (4). The hash is otherwise
        // well-formed and long enough. looks_like_bcrypt_hash must reject
        // it so the startup config check catches what from_credentials panics on.
        let hash = "$2b$03$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            !looks_like_bcrypt_hash(hash),
            "cost-3 hash must be rejected by looks_like_bcrypt_hash: {hash}"
        );
    }

    #[test]
    fn bcrypt_hash_cost_above_maximum_is_rejected() {
        let hash = "$2b$32$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        assert!(
            !looks_like_bcrypt_hash(hash),
            "cost-32 hash must be rejected by looks_like_bcrypt_hash: {hash}"
        );
    }

    #[test]
    fn short_bcrypt_prefix_without_full_hash_is_rejected() {
        // Correct prefix but too short to be a real hash.
        assert!(
            !looks_like_bcrypt_hash("$2b$10$tooshort"),
            "truncated hash must not be accepted"
        );
    }

    #[test]
    fn plaintext_password_in_auth_users_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = true

[[auth.users]]
username = "alice"
password = "plaintextpassword"

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("plaintext password in auth.users must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("auth.users['alice']"),
            "error must name the offending user: {msg}"
        );
        assert!(
            msg.contains("not a valid bcrypt hash"),
            "error must describe the problem: {msg}"
        );
    }

    #[test]
    fn bcrypt_hash_in_auth_users_is_valid() {
        // Real $2b$ hash — 60 chars, correct prefix.
        let hash = "$2b$10$YzVuN3B1T0RwR3ZpVzZwbOhWv5mJkOpFgZ3KqP4D2xLz1eSBmJu6e";
        let toml = format!(
            r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = true

[[auth.users]]
username = "alice"
password = "{hash}"

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#
        );
        let f = write_toml(&toml);
        Config::from_file(f.path()).expect("valid bcrypt hash must be accepted");
    }

    /// The drain times out if sessions never release their permits.
    #[tokio::test]
    async fn semaphore_drain_times_out_when_sessions_hold() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let max: u32 = 5;
        let sem = Arc::new(Semaphore::new(max as usize));

        // Hold all permits, never release.
        let mut _held = Vec::new();
        for _ in 0..max {
            _held.push(sem.clone().acquire_owned().await.unwrap());
        }

        let result =
            tokio::time::timeout(Duration::from_millis(20), sem.acquire_many_owned(max)).await;
        assert!(
            result.is_err(),
            "drain must time out when sessions hold permits"
        );
    }

    #[test]
    fn not_dev_mode_when_client_certs_configured() {
        let auth = AuthConfig {
            required: false,
            users: vec![],
            credential_file: None,
            oidc_providers: vec![],
            client_certs: vec![ClientCertEntry {
                sha256_fingerprint: "sha256:aabbcc".to_string(),
                username: "alice".to_string(),
            }],
            trusted_issuers: vec![],
            drain_username: None,
        };
        assert!(
            !auth.is_dev_mode(),
            "client_certs configured must not be dev mode"
        );
    }

    #[test]
    fn not_dev_mode_when_trusted_issuers_configured() {
        let auth = AuthConfig {
            required: false,
            users: vec![],
            credential_file: None,
            oidc_providers: vec![],
            client_certs: vec![],
            trusted_issuers: vec![TrustedIssuerEntry {
                cert_path: "/etc/ssl/ca.pem".to_string(),
            }],
            drain_username: None,
        };
        assert!(
            !auth.is_dev_mode(),
            "trusted_issuers configured must not be dev mode"
        );
    }

    #[test]
    fn dev_mode_nonloopback_guard_condition() {
        // Verify the guard condition: dev_mode + non-loopback triggers,
        // dev_mode + loopback does not.
        let auth = AuthConfig {
            required: false,
            users: vec![],
            credential_file: None,
            client_certs: vec![],
            trusted_issuers: vec![],
            oidc_providers: vec![],
            drain_username: None,
        };
        assert!(
            auth.is_dev_mode(),
            "no credentials + required=false must be dev mode"
        );
        assert!(
            !is_loopback_addr("0.0.0.0:1119"),
            "0.0.0.0 must not be loopback"
        );
        assert!(
            is_loopback_addr("127.0.0.1:1119"),
            "127.0.0.1 must be loopback"
        );

        // Guard fires only when both conditions hold.
        let should_abort = auth.is_dev_mode() && !is_loopback_addr("0.0.0.0:1119");
        assert!(
            should_abort,
            "guard must trigger for dev-mode on non-loopback"
        );

        let should_not_abort = auth.is_dev_mode() && !is_loopback_addr("127.0.0.1:1119");
        assert!(
            !should_not_abort,
            "guard must not trigger for dev-mode on loopback"
        );
    }

    // ── is_loopback_url_host unit tests ──────────────────────────────────────

    #[test]
    fn loopback_url_host_localhost() {
        assert!(is_loopback_url_host("http://localhost/path"));
        assert!(is_loopback_url_host("http://localhost:8080/path"));
    }

    #[test]
    fn loopback_url_host_127() {
        assert!(is_loopback_url_host("http://127.0.0.1/path"));
        assert!(is_loopback_url_host("http://127.0.0.1:8080/path"));
    }

    #[test]
    fn loopback_url_host_ipv6() {
        assert!(is_loopback_url_host("http://[::1]/path"));
        assert!(is_loopback_url_host("http://[::1]:8080/path"));
    }

    #[test]
    fn non_loopback_url_host_public_ip() {
        assert!(!is_loopback_url_host("http://192.168.1.10:8080/path"));
        assert!(!is_loopback_url_host("http://203.0.113.1/dav"));
    }

    #[test]
    fn non_loopback_url_host_domain() {
        assert!(!is_loopback_url_host("http://dav.example.com/path"));
    }

    #[test]
    fn loopback_url_host_no_scheme_is_non_loopback() {
        // A malformed URL with no scheme is treated as non-loopback (fail-safe).
        assert!(!is_loopback_url_host("dav.example.com/path"));
    }

    // ── WebDAV allow_http + credentials guard tests ───────────────────────────

    const READER_WEBDAV_PREFIX: &str = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "web_dav"

"#;

    /// allow_http = true + password on a non-loopback URL is a fatal validation error.
    #[test]
    fn webdav_allow_http_with_password_nonloopback_rejected() {
        let toml = format!(
            r#"{}
[backend.webdav]
url = "http://dav.example.com/stoa/blocks"
username = "user"
password = "secret"
allow_http = true
"#,
            READER_WEBDAV_PREFIX
        );
        let f = write_toml(&toml);
        let err = Config::from_file(f.path())
            .expect_err("allow_http + credentials on non-loopback must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        // Error message must mention allow_http and must NOT contain the password.
        if let ConfigError::Validation(msg) = &err {
            assert!(
                msg.contains("allow_http"),
                "error must mention allow_http: {msg}"
            );
            assert!(
                !msg.contains("secret"),
                "error must not contain the password: {msg}"
            );
        }
    }

    /// allow_http = true + password on a loopback URL is accepted (local testing).
    #[test]
    fn webdav_allow_http_with_password_loopback_accepted() {
        let toml = format!(
            r#"{}
[backend.webdav]
url = "http://127.0.0.1:8080/stoa/blocks"
username = "user"
password = "secret"
allow_http = true
"#,
            READER_WEBDAV_PREFIX
        );
        let f = write_toml(&toml);
        Config::from_file(f.path()).expect("allow_http + credentials on loopback must be accepted");
    }

    /// allow_http = true without a password is accepted (no credential exposure risk).
    #[test]
    fn webdav_allow_http_no_password_accepted() {
        let toml = format!(
            r#"{}
[backend.webdav]
url = "http://dav.example.com/stoa/blocks"
allow_http = true
"#,
            READER_WEBDAV_PREFIX
        );
        let f = write_toml(&toml);
        Config::from_file(f.path()).expect("allow_http without credentials must be accepted");
    }

    /// allow_http = true + password on localhost hostname is accepted.
    #[test]
    fn webdav_allow_http_with_password_localhost_accepted() {
        let toml = format!(
            r#"{}
[backend.webdav]
url = "http://localhost:8080/stoa/blocks"
username = "user"
password = "secret"
allow_http = true
"#,
            READER_WEBDAV_PREFIX
        );
        let f = write_toml(&toml);
        Config::from_file(f.path())
            .expect("allow_http + credentials on localhost must be accepted");
    }

    /// use_emulator = true on a non-loopback listen address is a fatal error.
    #[test]
    fn test_azure_emulator_nonloopback_is_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("use_emulator=true on non-loopback must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("0.0.0.0"),
            "error message must include the listen address, got: {msg}"
        );
    }

    /// use_emulator = true on a loopback listen address is accepted.
    #[test]
    fn test_azure_emulator_loopback_is_ok() {
        let toml = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true
"#;
        let f = write_toml(toml);
        Config::from_file(f.path()).expect("use_emulator=true on loopback must be accepted");
    }
}
