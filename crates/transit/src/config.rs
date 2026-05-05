use serde::Deserialize;
use std::path::Path;

use crate::block_cache::CacheConfig;
use crate::retention::policy::{PinPolicy, PolicyValidationError};
use crate::retention::remote_pin_client::PinningApiKey;
use crate::staging::StagingConfig;
pub use stoa_core::util::is_loopback_addr;
use stoa_core::util::is_loopback_url_host;
use stoa_core::wildmat::GroupFilter;

// ── Backend config (pluggable block store) ────────────────────────────────────
// Types are defined in stoa_core::ipfs_backend and re-exported here so that
// transit config validation code can use them without a long path prefix.
pub use stoa_core::ipfs_backend::{
    AzureBackendConfig, BackendConfig, BackendType, FsBackendConfig, GcsBackendConfig,
    KuboBackendConfig, LmdbBackendConfig, RocksDbBackendConfig, S3BackendConfig,
    SqliteBackendConfig, WebDavBackendConfig,
};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub peers: PeersConfig,
    pub groups: GroupsConfig,
    /// Legacy Kubo connection settings.  Retained for backward compatibility.
    /// New deployments should use `[backend]` instead.
    #[serde(default)]
    pub ipfs: IpfsConfig,
    /// Pluggable block store backend.  When present, takes precedence over `[ipfs]`.
    #[serde(default)]
    pub backend: Option<BackendConfig>,
    pub pinning: PinningConfig,
    pub gc: GcConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub peering: PeeringConfig,
    /// TLS for the inbound peering TCP listener.  Optional; plain TCP is used
    /// when this section is absent (suitable for LAN / loopback peering).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// IPNS publishing configuration.  Optional; IPNS publishing is disabled by default.
    #[serde(default)]
    pub ipns: IpnsConfig,
    /// Write-ahead staging area.  Optional; omit to use the in-memory
    /// ingestion queue only (current default behaviour).
    #[serde(default)]
    pub staging: Option<StagingConfig>,
    /// Local LRU block cache for IPFS content.  Optional; omit to disable.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    /// Audit log backend configuration.  Defaults to SQLite.
    #[serde(default)]
    pub audit: stoa_core::audit::AuditConfig,
    /// SQLite backup configuration.  Omit to disable scheduled/on-demand backups.
    #[serde(default)]
    pub backup: BackupConfig,
    /// Ingestion queue limits.  Controls backpressure applied to IHAVE/TAKETHIS senders.
    #[serde(default)]
    pub ingest: IngestConfig,
    /// OpenTelemetry observability configuration.  Omit for Prometheus-only mode.
    #[serde(default)]
    pub telemetry: stoa_core::telemetry::TelemetryConfig,
}

/// Configuration for SQLite online backup.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct BackupConfig {
    /// Directory where backup files are written.
    ///
    /// Created at backup time if absent.  Backup filenames include a UTC
    /// timestamp: `transit-20260427T030000Z.db`, `core-20260427T030000Z.db`.
    /// When absent, `POST /admin/backup` returns 503.
    #[serde(default)]
    pub dest_dir: Option<String>,
    /// S3 bucket to upload backup files to after writing locally.
    ///
    /// Requires the `aws` CLI to be installed and configured with credentials.
    /// When absent, backups are written locally only.
    #[serde(default)]
    pub s3_bucket: Option<String>,
    /// S3 key prefix prepended to backup filenames.
    ///
    /// For example `"stoa/backups/"` produces keys like
    /// `stoa/backups/transit-20260427T030000Z.db`.
    /// Defaults to empty (files land at the bucket root).
    #[serde(default)]
    pub s3_prefix: Option<String>,
    /// Cron schedule for automatic backups (5-field standard cron syntax).
    ///
    /// Example: `"0 3 * * *"` runs at 03:00 UTC daily.
    /// When absent, backups run only on demand via `POST /admin/backup`.
    /// Requires `dest_dir` to be set.
    #[serde(default)]
    pub schedule: Option<String>,
}

/// Ingestion queue limits for backpressure on IHAVE/TAKETHIS senders.
///
/// When either high-water mark is exceeded, the transit daemon responds with
/// `436 Transfer not possible; try again later` (RFC 4644) until the queue
/// drains below the threshold.
#[derive(Debug, Deserialize, Clone)]
pub struct IngestConfig {
    /// Maximum number of articles that may wait in the ingestion queue.
    ///
    /// When this count is reached, new IHAVE/TAKETHIS transfers are rejected
    /// with 436 until the drain catches up.  Default: 1000.
    #[serde(default = "default_max_pending_articles")]
    pub max_pending_articles: usize,
    /// Maximum total bytes of article data in the ingestion queue.
    ///
    /// Prevents large-article floods from exhausting memory independently of
    /// the article count limit.  Default: 268435456 (256 MiB).
    #[serde(default = "default_max_pending_bytes")]
    pub max_pending_bytes: u64,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            max_pending_articles: default_max_pending_articles(),
            max_pending_bytes: default_max_pending_bytes(),
        }
    }
}

/// Operator identity configuration.
///
/// Controls the Ed25519 signing key used to sign articles before they are
/// written to IPFS and to derive the stable HLC node_id.
///
/// If `signing_key_path` is absent, an ephemeral key is generated at startup.
/// This is safe for development but breaks article signature verification across
/// restarts and makes HLC timestamps non-comparable between daemon instances.
/// Set this in production.
#[derive(Debug, Deserialize, Default)]
pub struct OperatorConfig {
    /// Path to the 32-byte raw Ed25519 operator signing key seed file.
    ///
    /// The file must contain exactly 32 bytes (the Ed25519 seed / private scalar).
    /// Use `stoa-transit keygen --output <path>` to generate a key file in the
    /// correct format.
    ///
    /// If absent, an ephemeral key is generated each startup — articles signed by
    /// different process instances will have different keys and cannot be
    /// cross-verified.  Set this for any production deployment.
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Local FQDN for the `Path:` header (Son-of-RFC-1036 §3.3).
    #[serde(default)]
    pub hostname: Option<String>,
}

/// IPNS publishing configuration.
///
/// When `enabled` is true, the transit daemon publishes a signed IPNS record
/// after each article ingestion.  The record points to a JSON index block that
/// maps every active newsgroup to its most-recently-ingested article CID.
/// The stable IPNS address is derived from the Kubo node's peer identity key.
#[derive(Debug, Deserialize)]
pub struct IpnsConfig {
    /// Publish IPNS records after each article ingestion.  Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum interval between consecutive IPNS publishes, in seconds.
    /// Prevents excessive DHT traffic on high-volume ingest.  Default: 3600.
    #[serde(default = "default_ipns_republish_interval")]
    pub republish_interval_secs: u64,
}

fn default_ipns_republish_interval() -> u64 {
    3600
}

impl Default for IpnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            republish_interval_secs: default_ipns_republish_interval(),
        }
    }
}

/// Database configuration.
///
/// Three separate databases are required because `sqlx` validates that every
/// previously-applied migration is still present in the migrator; mixing schemas
/// in a single pool would cause `VersionMissing` errors.
///
/// URLs may point to SQLite files (`sqlite:///path/to/file.db`) or a PostgreSQL
/// server (`postgres://user:pass@host/db`).
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL for the core-schema database (msgid_map, group_log).
    /// Default: `sqlite:///transit_core.db`.
    #[serde(default = "default_core_db_url")]
    pub core_url: String,
    /// Database URL for the transit-schema database (peers, peer_groups, articles).
    /// Default: `sqlite:///transit.db`.
    #[serde(default = "default_db_url")]
    pub url: String,
    /// Database URL for the verify-schema database (article_verifications, seen_keys).
    /// Default: `sqlite:///transit_verify.db`.
    #[serde(default = "default_verify_db_url")]
    pub verify_url: String,
    /// Connection pool size. Default: 8.
    #[serde(default = "default_db_pool_size")]
    pub pool_size: u32,
}

fn default_core_db_url() -> String {
    "sqlite:///transit_core.db".to_string()
}

fn default_db_url() -> String {
    "sqlite:///transit.db".to_string()
}

fn default_verify_db_url() -> String {
    "sqlite:///transit_verify.db".to_string()
}

fn default_db_pool_size() -> u32 {
    8
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            core_url: default_core_db_url(),
            url: default_db_url(),
            verify_url: default_verify_db_url(),
            pool_size: default_db_pool_size(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Address to bind the admin HTTP endpoint.
    /// Default: 127.0.0.1:9090 (loopback-only).
    /// A non-loopback address without a bearer token is rejected at startup (fail-closed).
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    /// Optional bearer token for admin endpoint authentication.
    /// Required when addr is a non-loopback address — the server refuses to start
    /// on a reachable interface without a token (fail-closed).
    /// Optional on loopback; omitting it leaves the endpoint open to local processes.
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Maximum requests per minute per IP (default 60). 0 = unlimited.
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_rate_limit_rpm() -> u32 {
    60
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            addr: default_admin_addr(),
            bearer_token: None,
            rate_limit_rpm: default_rate_limit_rpm(),
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
    /// Log level filter (e.g. "info", "debug", "stoa_transit=debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// Socket address for the NNTP peering listener.
    ///
    /// Format: `IP:port` or `[IPv6]:port`. Port 119 is the NNTP standard.
    /// Production (public): `"0.0.0.0:119"` — binds all interfaces.
    /// Development (local only): `"127.0.0.1:119"`.
    /// Binding to a non-loopback address exposes the NNTP port to the network;
    /// use firewall rules or the TLS listener when network access is required.
    pub addr: String,
}

/// TLS configuration for the inbound peering TCP listener.
///
/// When present, the peering listener wraps every accepted connection with
/// rustls before handing it to the session handler.  Plain TCP peers that do
/// not speak TLS will fail the handshake and be dropped.
///
/// Leave this section absent to accept plain TCP connections (LAN or loopback
/// peering, or when a TLS terminator sits in front of the daemon).
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain (leaf first).
    pub cert_path: String,
    /// Path to the PEM-encoded private key.
    pub key_path: String,
}

/// One entry in the structured `[[peers.peer]]` table.
#[derive(Debug, Deserialize, Default)]
pub struct PeerEntry {
    /// Socket address of the peer (IP:port or hostname:port).
    pub addr: String,
    /// Connect with TLS. Requires `cert_sha256`. Default: false.
    #[serde(default)]
    pub tls: bool,
    /// Pinned SHA-256 fingerprint of the peer's DER certificate.
    ///
    /// Required when `tls = true`. Format: colon-separated lowercase hex bytes,
    /// e.g. `"aa:bb:cc:..."`. Validation rejects `tls = true` without this field.
    #[serde(default)]
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PeersConfig {
    /// Legacy flat list of peer addresses (backward-compatible).
    ///
    /// Entries here are equivalent to `[[peers.peer]]` with `tls = false` and
    /// no cert pin.  Supported for existing configs; new deployments should use
    /// the structured `peer` table instead.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Structured per-peer table with optional TLS and cert-pin metadata.
    ///
    /// Use `[[peers.peer]]` in TOML to add entries.  Validated at startup:
    /// `tls = true` without `cert_sha256` is rejected.
    #[serde(default)]
    pub peer: Vec<PeerEntry>,
}

/// Configuration for the set of newsgroups this transit node accepts.
#[derive(Debug, Deserialize)]
pub struct GroupsConfig {
    /// Wildmat filter patterns for accepted newsgroup names.
    ///
    /// Each entry is a wildmat pattern (RFC 3977 §4.2) — NOT a literal group
    /// name.  Patterns support `*` (any sequence of characters) and `?` (any
    /// single character).  Negation patterns start with `!`:
    ///
    /// ```toml
    /// names = ["comp.*", "sci.*", "!alt.binaries.*"]
    /// ```
    ///
    /// Matching is first-match-wins in list order.  An empty list means
    /// accept nothing.  See [`GroupFilter`](crate::config::GroupsConfig) for
    /// full semantics.
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IpfsConfig {
    // Default is empty. Previously "http://127.0.0.1:5001" was implied; config
    // validation now rejects an empty api_url when no [backend] is present.
    // Upgrade: add `[ipfs]\napi_url = "http://127.0.0.1:5001"` or use [backend].
    pub api_url: String,
}

/// Configuration for one external IPFS pinning service.
///
/// External services implement the IPFS Remote Pinning API spec
/// (https://ipfs.github.io/pinning-services-api-spec/).
/// Compatible services include Pinata, web3.storage, Filebase, and others.
#[derive(Debug, Deserialize)]
pub struct ExternalPinServiceConfig {
    /// Human-readable name (used in logs and the admin API). Must be unique.
    pub name: String,
    /// Base URL of the Remote Pinning API endpoint. Must use HTTPS.
    /// Example: `"https://api.pinata.cloud/psa"`
    pub endpoint: String,
    /// Bearer token for authenticating with the pinning service.
    pub api_key: PinningApiKey,
    /// HTTP connect timeout in seconds. Must be ≥ 1. Default: 10.
    #[serde(default = "default_pin_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// HTTP request timeout in seconds. Must be ≥ 1. Default: 30.
    #[serde(default = "default_pin_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Optional glob patterns for newsgroup names to include.
    /// Empty means "pin articles from all groups". Patterns are matched
    /// against each newsgroup in the article's Newsgroups header.
    /// Example: `["comp.*", "sci.*"]`
    #[serde(default)]
    pub groups: Vec<String>,
    /// Maximum submission attempts per CID before marking as failed. Default: 5.
    #[serde(default = "default_pin_max_attempts")]
    pub max_attempts: u32,
}

fn default_pin_connect_timeout_secs() -> u64 {
    10
}

fn default_pin_request_timeout_secs() -> u64 {
    30
}

fn default_pin_max_attempts() -> u32 {
    5
}

#[derive(Debug, Deserialize)]
pub struct PinningConfig {
    pub rules: Vec<String>,
    /// External IPFS pinning services to replicate articles to.
    /// Uses the IPFS Remote Pinning API spec. Optional; default empty.
    #[serde(default)]
    pub external_services: Vec<ExternalPinServiceConfig>,
}

/// GC scheduler configuration.  The GC scheduler implementation lives in
/// `crates/transit/src/retention/gc.rs` but is not yet started from `main.rs`.
#[derive(Debug, Deserialize)]
pub struct GcConfig {
    pub schedule: String,
    pub max_age_days: u64,
    /// Directory where per-run GC reports are written as JSON files.
    /// Defaults to `None` (no files written).  The directory is created at
    /// startup if it does not exist.
    #[serde(default)]
    pub report_dir: Option<String>,
}

/// Peering session tuning parameters.
#[derive(Debug, Deserialize)]
pub struct PeeringConfig {
    /// Ingestion queue capacity (max queued articles before backpressure). Default: 1024.
    #[serde(default = "default_ingestion_queue_capacity")]
    pub ingestion_queue_capacity: usize,
    /// Per-IP rate limit: sustained articles/second. Default: 100.
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: f64,
    /// Per-IP rate limit burst: max burst articles. Default: 200.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u64,
    /// Trusted peer public keys for ed25519 challenge-response authentication.
    ///
    /// Each entry must be of the form `"ed25519:<64-lowercase-hex-digits>"`.
    /// When non-empty, every inbound peering connection must complete the
    /// mutual handshake with a key in this list before any NNTP bytes are
    /// exchanged.  Connections that fail or time out are dropped silently.
    ///
    /// When empty (the default) authentication is skipped — the port MUST be
    /// firewalled to trusted peers in that case.
    #[serde(default)]
    pub trusted_peers: Vec<String>,
    /// Seconds to wait for the ingestion queue to drain after a shutdown
    /// signal before forcing exit.  Default: 30.
    #[serde(default)]
    pub drain_timeout_secs: Option<u64>,
    /// Number of consecutive failures before a peer is blacklisted. Default: 10.
    #[serde(default = "default_blacklist_failure_threshold")]
    pub blacklist_failure_threshold: i64,
    /// How long to blacklist a peer in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_blacklist_duration_secs")]
    pub blacklist_duration_secs: i64,
}

fn default_blacklist_failure_threshold() -> i64 {
    10
}

fn default_blacklist_duration_secs() -> i64 {
    3600
}

fn default_ingestion_queue_capacity() -> usize {
    1024
}

fn default_max_pending_articles() -> usize {
    1000
}

fn default_max_pending_bytes() -> u64 {
    256 * 1024 * 1024 // 256 MiB
}

fn default_rate_limit_rps() -> f64 {
    100.0
}

fn default_rate_limit_burst() -> u64 {
    200
}

impl Default for PeeringConfig {
    fn default() -> Self {
        Self {
            ingestion_queue_capacity: default_ingestion_queue_capacity(),
            rate_limit_rps: default_rate_limit_rps(),
            rate_limit_burst: default_rate_limit_burst(),
            trusted_peers: Vec::new(),
            drain_timeout_secs: None,
            blacklist_failure_threshold: default_blacklist_failure_threshold(),
            blacklist_duration_secs: default_blacklist_duration_secs(),
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
            ConfigError::Io(msg) => write!(f, "I/O error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "parse error: {}", msg),
            ConfigError::Validation(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

fn env_str(var: &str, field: &mut String) {
    if let Ok(v) = std::env::var(var) {
        if !v.is_empty() {
            *field = v;
        }
    }
}

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
        env_str("STOA_TRANSIT_ADDR", &mut self.listen.addr);
        let cert = std::env::var("STOA_TLS_CERT_PATH")
            .ok()
            .filter(|v| !v.is_empty());
        let key = std::env::var("STOA_TLS_KEY_PATH")
            .ok()
            .filter(|v| !v.is_empty());
        if cert.is_some() || key.is_some() {
            let tls = self.tls.get_or_insert_with(|| TlsConfig {
                cert_path: String::new(),
                key_path: String::new(),
            });
            if let Some(c) = cert {
                tls.cert_path = c;
            }
            if let Some(k) = key {
                tls.key_path = k;
            }
        }
        env_str("STOA_DB_URL", &mut self.database.url);
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

    pub fn from_file(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
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

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation(
                "listen.addr must not be empty".into(),
            ));
        }
        // Require either [backend] or a non-empty [ipfs.api_url].
        match &self.backend {
            Some(backend) => match &backend.backend_type {
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
                    return Err(ConfigError::Validation(
                        "backend.type = 'pg_blob' is not supported in stoa-transit".into(),
                    ));
                }
                BackendType::GitSha256 => {
                    return Err(ConfigError::Validation(
                        "backend.type = 'git_sha256' is not supported in stoa-transit; \
                         git object store is a reader-only backend"
                            .into(),
                    ));
                }
                BackendType::Rados => {
                    let rados = backend.rados.as_ref().ok_or_else(|| {
                        ConfigError::Validation(
                            "backend.type = 'rados' requires a [backend.rados] section".into(),
                        )
                    })?;
                    if rados.pool.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.rados.pool must not be empty".into(),
                        ));
                    }
                    if rados.user.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.rados.user must not be empty".into(),
                        ));
                    }
                    if rados.conf_path.is_empty() {
                        return Err(ConfigError::Validation(
                            "backend.rados.conf_path must not be empty".into(),
                        ));
                    }
                }
            },
            None => {
                if self.ipfs.api_url.is_empty() {
                    return Err(ConfigError::Validation(
                        "either [backend] or [ipfs] with a non-empty api_url is required".into(),
                    ));
                }
            }
        }
        if self.pinning.rules.is_empty() {
            return Err(ConfigError::Validation(
                "pinning.rules must not be empty; at least one pinning rule is required".into(),
            ));
        }
        if !self.groups.names.is_empty() {
            GroupFilter::new(&self.groups.names)
                .map_err(|e| ConfigError::Validation(e.to_string()))?;
        }
        for peer in &self.peers.peer {
            // DECISION (rbe3.24): TLS peer config requires cert_sha256 when tls=true
            //
            // TLS without a pinned certificate fingerprint prevents passive
            // eavesdropping but does NOT authenticate the peer — any entity
            // with a valid TLS certificate from any CA can impersonate the peer.
            // Requiring cert_sha256 at config time prevents misconfigured deployments
            // where operators believe they have authenticated peering but actually
            // have only encrypted (unauthenticated) connections.
            if peer.tls && peer.cert_sha256.is_none() {
                return Err(ConfigError::Validation(format!(
                    "peers.peer entry '{}': tls = true requires cert_sha256 to be set",
                    peer.addr
                )));
            }
            if let Some(fp) = &peer.cert_sha256 {
                validate_cert_sha256(fp)
                    .map_err(|e| ConfigError::Validation(format!("peer '{}': {e}", peer.addr)))?;
            }
        }
        // Validate GC cron schedule.
        validate_cron_schedule(&self.gc.schedule)
            .map_err(|e| ConfigError::Validation(format!("gc.schedule: {e}")))?;
        if self.gc.max_age_days > 36_500 {
            return Err(ConfigError::Validation(format!(
                "gc.max_age_days ({}) exceeds 36500 (100 years); \
                 values this large overflow the millisecond grace window",
                self.gc.max_age_days
            )));
        }

        // Validate backup cron schedule if set.
        if let Some(sched) = &self.backup.schedule {
            validate_cron_schedule(sched)
                .map_err(|e| ConfigError::Validation(format!("backup.schedule: {e}")))?;
            if self.backup.dest_dir.is_none() {
                return Err(ConfigError::Validation(
                    "backup.schedule requires backup.dest_dir to be set".into(),
                ));
            }
        }

        // Validate external pinning service entries.
        let mut seen_service_names: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for svc in &self.pinning.external_services {
            if svc.name.is_empty() {
                return Err(ConfigError::Validation(
                    "pinning.external_services: service name must not be empty".into(),
                ));
            }
            if !seen_service_names.insert(svc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services: duplicate service name '{}'",
                    svc.name
                )));
            }
            // DECISION (rbe3.26): external pinning endpoints must use HTTPS
            //
            // Sending article CIDs to a remote pinning service over plain HTTP
            // exposes the CID list (metadata: which articles exist on this server)
            // and the bearer token to passive network observers.  Both are
            // sensitive: the CID list reveals the server's content, and the bearer
            // token grants write access to the pinning service.  Enforcing HTTPS
            // at config load time prevents accidental misconfiguration.
            if !svc.endpoint.starts_with("https://") {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': endpoint must use HTTPS, got '{}'",
                    svc.name, svc.endpoint
                )));
            }
            if svc.connect_timeout_secs == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': connect_timeout_secs must be ≥ 1",
                    svc.name
                )));
            }
            if svc.request_timeout_secs == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': request_timeout_secs must be ≥ 1",
                    svc.name
                )));
            }
            if svc.max_attempts == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': max_attempts must be ≥ 1",
                    svc.name
                )));
            }
            if !svc.groups.is_empty() {
                GroupFilter::new(&svc.groups).map_err(|e| {
                    ConfigError::Validation(format!(
                        "external pin service '{}' groups: {}",
                        svc.name, e
                    ))
                })?;
            }
        }

        // DECISION (rbe3.28): signing key readability check at startup, not request time
        //
        // A missing or unreadable signing key at article-processing time causes
        // silent article loss (the pipeline returns an error and the article is
        // dropped).  Checking at config validation converts that silent runtime
        // failure into a clear startup error caught before any traffic is processed.
        // Better to catch this at startup than discover it when an article arrives.
        if let Some(ref path) = self.operator.signing_key_path {
            std::fs::metadata(path).map_err(|e| {
                ConfigError::Validation(format!(
                    "operator.signing_key_path '{path}' is not accessible: {e}"
                ))
            })?;
        }

        // Validate trusted_peers key format at config load time so a typo is
        // caught immediately rather than silently disabling peering auth.
        for entry in &self.peering.trusted_peers {
            crate::peering::auth::parse_trusted_peer_key(entry).map_err(|e| {
                ConfigError::Validation(format!(
                    "peering.trusted_peers: invalid key entry {entry:?}: {e}"
                ))
            })?;
        }

        Ok(())
    }
}

/// Validates a [`PinPolicy`] at startup, returning an error if the policy is
/// malformed. This is a thin wrapper around [`PinPolicy::validate`] so that
/// startup code can call a single named function.
pub fn validate_retention_policy(policy: &PinPolicy) -> Result<(), PolicyValidationError> {
    policy.validate()
}

/// Validate admin configuration.
///
/// Returns `Err` if `addr` is non-loopback and no `bearer_token` is set —
/// an unauthenticated admin endpoint on a reachable interface is a security
/// footgun that the server must not start with (fail-closed).
/// Returns `Ok(())` if the configuration is safe.
///
/// # DECISION (rbe3.23): fail-closed admin endpoint
///
/// The default admin addr (`127.0.0.1:9090`) is loopback-only and needs no
/// token.  If an operator binds to `0.0.0.0` or a specific network interface
/// without a bearer token, the check returns an error at startup rather than
/// silently exposing an unauthenticated admin API.  Fail-closed means the safe
/// default requires no configuration, and the unsafe configuration requires
/// explicit opt-in (the operator must set both a non-loopback addr AND a token).
/// Do NOT weaken this to a warning; an unauthenticated admin endpoint on a
/// network interface is a critical vulnerability, not a configuration warning.
pub fn check_admin_addr(admin: &AdminConfig) -> Result<(), String> {
    if !is_loopback_addr(&admin.addr) && admin.bearer_token.is_none() {
        Err(format!(
            "admin endpoint at '{}' is on a non-loopback interface but \
             bearer_token is not configured — refusing to start an \
             unauthenticated admin server",
            admin.addr
        ))
    } else {
        Ok(())
    }
}

/// Validates that a `cert_sha256` fingerprint string is 32 colon-separated
/// lowercase hex bytes (the SHA-256 fingerprint of a DER certificate).
///
/// Expected format: `"aa:bb:cc:..."` — exactly 32 two-character lowercase hex
/// groups separated by `:`, e.g. the 95-character string produced by
/// `openssl x509 -fingerprint -sha256`.
fn validate_cert_sha256(s: &str) -> Result<(), String> {
    let groups: Vec<&str> = s.split(':').collect();
    if groups.len() != 32 {
        return Err(format!(
            "cert_sha256 must be 32 colon-separated lowercase hex bytes \
             (e.g. 'aa:bb:cc:...'), got {} groups in '{s}'",
            groups.len()
        ));
    }
    for group in &groups {
        if group.len() != 2 {
            return Err(format!(
                "cert_sha256 must be 32 colon-separated lowercase hex bytes \
                 (e.g. 'aa:bb:cc:...'), byte group '{group}' is not 2 characters"
            ));
        }
        for ch in group.chars() {
            if !matches!(ch, '0'..='9' | 'a'..='f') {
                return Err(format!(
                    "cert_sha256 must be 32 colon-separated lowercase hex bytes \
                     (e.g. 'aa:bb:cc:...'), invalid character '{ch}' in '{s}'"
                ));
            }
        }
    }
    Ok(())
}

/// Validates that a cron schedule string has 5 or 6 space-separated non-empty
/// fields (the standard cron field count: minute hour dom month dow, with an
/// optional seconds field prepended by some schedulers).
///
/// This is a structural check only — it catches obviously wrong values such as
/// an empty string or free prose.  Full semantic validation (field ranges, step
/// syntax, etc.) is deferred to the runtime scheduler.
fn validate_cron_schedule(s: &str) -> Result<(), String> {
    let fields: Vec<&str> = s.split_whitespace().collect();
    if fields.len() < 5 || fields.len() > 6 {
        return Err(format!(
            "invalid cron expression: '{s}' \
             (expected 5 or 6 space-separated fields, got {})",
            fields.len()
        ));
    }
    Ok(())
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

    const VALID_TOML: &str = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = ["192.0.2.1:119", "192.0.2.2:119"]

[groups]
names = ["comp.lang.rust", "alt.test"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;

    #[test]
    fn parse_valid_config() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "0.0.0.0:119");
        assert_eq!(cfg.peers.addresses.len(), 2);
        assert_eq!(cfg.groups.names, vec!["comp.lang.rust", "alt.test"]);
        assert_eq!(cfg.ipfs.api_url, "http://127.0.0.1:5001");
        assert_eq!(cfg.pinning.rules, vec!["pin-all"]);
        assert_eq!(cfg.gc.schedule, "0 3 * * *");
        assert_eq!(cfg.gc.max_age_days, 30);
    }

    #[test]
    fn missing_listen_section_is_parse_error() {
        let toml = r#"
[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn empty_pinning_rules_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = []

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    /// Uppercase patterns in groups.names are accepted: WildmatPattern::parse
    /// normalises to lowercase before the charset check, so "Comp.Lang.Rust"
    /// is stored as "comp.lang.rust" and is equivalent.
    #[test]
    fn group_name_uppercase_accepted_after_normalisation() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["Comp.Lang.Rust"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        Config::from_file(f.path())
            .expect("uppercase group pattern must be accepted after normalisation");
    }

    #[test]
    fn invalid_group_name_empty_component() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["comp..rust"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn io_error_on_missing_file() {
        let err =
            Config::from_file(Path::new("/nonexistent/path/config.toml")).expect_err("should fail");
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
            addr: "0.0.0.0:9090".to_string(),
            bearer_token: None,
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
            addr: "0.0.0.0:9090".to_string(),
            bearer_token: Some("secret".to_string()),
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

    /// New structured [[peers.peer]] tables parse correctly alongside
    /// the legacy addresses list.
    #[test]
    fn structured_peer_table_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = ["192.0.2.1:119"]

[[peers.peer]]
addr = "192.0.2.2:119"
tls = true
cert_sha256 = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

[[peers.peer]]
addr = "192.0.2.3:119"

[groups]
names = ["comp.test"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.peers.addresses.len(), 1);
        assert_eq!(cfg.peers.peer.len(), 2);
        let tls_peer = &cfg.peers.peer[0];
        assert_eq!(tls_peer.addr, "192.0.2.2:119");
        assert!(tls_peer.tls);
        assert_eq!(
            tls_peer.cert_sha256.as_deref(),
            Some("aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
        );
        let plain_peer = &cfg.peers.peer[1];
        assert_eq!(plain_peer.addr, "192.0.2.3:119");
        assert!(!plain_peer.tls);
    }

    /// tls = true without cert_sha256 must fail validation.
    #[test]
    fn tls_without_cert_sha256_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[[peers.peer]]
addr = "192.0.2.10:119"
tls = true

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// A cert_sha256 with wrong byte count (not 32) must fail validation.
    #[test]
    fn cert_sha256_wrong_byte_count_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[[peers.peer]]
addr = "192.0.2.10:119"
tls = true
cert_sha256 = "aa:bb:cc"

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("short fingerprint must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        if let ConfigError::Validation(msg) = err {
            assert!(
                msg.contains("cert_sha256"),
                "error must mention cert_sha256, got: {msg}"
            );
        }
    }

    /// A cert_sha256 with uppercase hex must fail validation.
    #[test]
    fn cert_sha256_uppercase_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[[peers.peer]]
addr = "192.0.2.10:119"
tls = false
cert_sha256 = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("uppercase fingerprint must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        if let ConfigError::Validation(msg) = err {
            assert!(
                msg.contains("cert_sha256"),
                "error must mention cert_sha256, got: {msg}"
            );
        }
    }

    /// A valid 32-byte lowercase cert_sha256 without tls=true must pass validation.
    #[test]
    fn cert_sha256_valid_format_passes_validation() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[[peers.peer]]
addr = "192.0.2.10:119"
tls = false
cert_sha256 = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        Config::from_file(f.path()).expect("valid 32-byte lowercase fingerprint must pass");
    }

    /// An invalid cron expression (wrong field count) must fail validation.
    #[test]
    fn gc_schedule_invalid_cron_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "not-a-cron"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("invalid cron must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        if let ConfigError::Validation(msg) = err {
            assert!(
                msg.contains("gc.schedule"),
                "error must mention gc.schedule, got: {msg}"
            );
        }
    }

    /// An empty gc.schedule must fail validation.
    #[test]
    fn gc_schedule_empty_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = ""
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty schedule must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// A valid 6-field cron schedule (with seconds prefix) must pass validation.
    #[test]
    fn gc_schedule_six_field_cron_passes_validation() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        Config::from_file(f.path()).expect("6-field cron schedule must pass validation");
    }

    #[test]
    fn external_pin_service_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "secret-token"
groups = ["comp.*"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.pinning.external_services.len(), 1);
        let svc = &cfg.pinning.external_services[0];
        assert_eq!(svc.name, "pinata");
        assert_eq!(svc.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(svc.groups, vec!["comp.*"]);
        assert_eq!(svc.connect_timeout_secs, 10);
        assert_eq!(svc.request_timeout_secs, 30);
        assert_eq!(svc.max_attempts, 5);
        // api_key must be redacted in Debug output
        assert!(!format!("{:?}", svc.api_key).contains("secret-token"));
    }

    #[test]
    fn external_pin_service_http_endpoint_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "insecure"
endpoint = "http://api.pinata.cloud/psa"
api_key = "token"

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("HTTP endpoint should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn external_pin_service_duplicate_name_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "token-1"

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.web3.storage/pins"
api_key = "token-2"

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("duplicate service name should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn external_pin_service_zero_timeout_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "token"
connect_timeout_secs = 0

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("zero timeout should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] section with type = "kubo" parses and validation passes.
    #[test]
    fn backend_kubo_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "kubo"

[backend.kubo]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("backend.kubo config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be present");
        assert_eq!(backend.backend_type, BackendType::Kubo);
        let kubo = backend.kubo.as_ref().expect("backend.kubo must be present");
        assert_eq!(kubo.api_url, "http://127.0.0.1:5001");
        // kubo_api_url() returns the backend.kubo url.
        assert_eq!(cfg.kubo_api_url(), Some("http://127.0.0.1:5001"));
    }

    /// [backend] with type = "kubo" but no [backend.kubo] subsection is rejected.
    #[test]
    fn backend_kubo_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "kubo"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.kubo must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] section with type = "lmdb" and a [backend.lmdb] subsection parses.
    #[test]
    fn backend_lmdb_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test-lmdb"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("backend.lmdb config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be present");
        assert_eq!(backend.backend_type, BackendType::Lmdb);
        let lmdb = backend.lmdb.as_ref().expect("backend.lmdb must be present");
        assert_eq!(lmdb.path, "/tmp/test-lmdb");
        assert_eq!(lmdb.map_size_gb, 1024, "default map_size_gb must be 1024");
        // No Kubo connectivity check needed for LMDB.
        assert_eq!(cfg.kubo_api_url(), None);
    }

    /// [backend] with type = "lmdb" but no [backend.lmdb] subsection is rejected.
    #[test]
    fn backend_lmdb_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.lmdb must fail");
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "s3"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "s3"

[backend.s3]
bucket = "stoa-articles"
region = "us-east-1"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "s3"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "s3"

[backend.s3]
bucket = ""
region = "us-east-1"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[backend.azure]
account = "myaccount"
container = "stoa-articles"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[backend.azure]
account = ""
container = "stoa-articles"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "gcs"

[backend.gcs]
bucket = "stoa-articles"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "gcs"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true
endpoint = "http://127.0.0.1:10000"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "gcs"

[backend.gcs]
bucket = "stoa-articles"
service_account_path = "/etc/sa.json"
service_account_key = "{}"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = ""

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = "http://dav.example.com/stoa/blocks"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = "http://127.0.0.1:8080/stoa/blocks"
allow_http = true

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rocks_db"

[backend.rocksdb]
path = "/var/lib/stoa/rocksdb"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rocks_db"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rocks_db"

[backend.rocksdb]
path = ""

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty path must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "rados" and a [backend.rados] section parses and validates.
    #[test]
    fn backend_rados_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rados"

[backend.rados]
pool = "stoa_blocks"
user = "stoa"
conf_path = "/etc/ceph/ceph.conf"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("valid rados config must parse");
        let backend = cfg.backend.expect("backend must be present");
        assert!(matches!(backend.backend_type, BackendType::Rados));
        let rados = backend.rados.expect("rados section must be present");
        assert_eq!(rados.pool, "stoa_blocks");
        assert_eq!(rados.user, "stoa");
        assert_eq!(rados.conf_path, "/etc/ceph/ceph.conf");
    }

    /// [backend] with type = "rados" but no [backend.rados] section is rejected.
    #[test]
    fn backend_rados_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rados"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing rados section must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.rados] with an empty pool is rejected.
    #[test]
    fn backend_rados_empty_pool_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "rados"

[backend.rados]
pool = ""
user = "stoa"
conf_path = "/etc/ceph/ceph.conf"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("empty pool must fail validation");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    /// [backend.webdav] with a trailing slash in url is rejected.
    #[test]
    fn backend_webdav_trailing_slash_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks/"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "web_dav"

[backend.webdav]
url = "https://dav.example.com/stoa/blocks"
username = "alice"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "filesystem"

[backend.filesystem]
path = "/tmp/stoa-blocks"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "filesystem"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("filesystem without subsection must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "sqlite" and a [backend.sqlite] section parses.
    #[test]
    fn backend_sqlite_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/stoa-blocks.db"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "sqlite"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("sqlite without subsection must fail validation");
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
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test"
map_size_gb = 0

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("map_size_gb = 0 must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// Wildmat patterns (with * and ?) are accepted in groups.names.
    #[test]
    fn wildmat_pattern_in_groups_names_is_valid() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["comp.*", "!comp.lang.fortran", "alt.?est"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        Config::from_file(f.path()).expect("wildmat patterns must be valid");
    }

    /// A groups.names list consisting entirely of negated patterns is rejected.
    #[test]
    fn all_negation_groups_names_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["!comp.lang.rust", "!alt.test"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("all-negation filter must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
        if let ConfigError::Validation(msg) = err {
            assert!(
                msg.contains("non-negated"),
                "error message must mention non-negated pattern, got: {msg}"
            );
        }
    }

    /// Missing both [backend] and [ipfs] is a validation error.
    #[test]
    fn missing_both_backend_and_ipfs_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing ipfs and backend must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    // ── GroupFilter wildmat semantics tests (RFC 3977 §4.1 oracle) ────────────

    /// RFC 3977 §4.1: `?` matches exactly one character.
    #[test]
    fn group_filter_question_mark_matches_one_char() {
        let f = GroupFilter::new(&["comp.lang.?"]).unwrap();
        assert!(
            !f.accepts("comp.lang.rust"),
            "comp.lang.? must not match comp.lang.rust (4 chars, not 1)"
        );
        assert!(
            f.accepts("comp.lang.c"),
            "comp.lang.? must match comp.lang.c (exactly 1 suffix char)"
        );
    }

    /// RFC 3977 §4.1: `?` matches exactly one character.
    #[test]
    fn group_filter_question_mark_single_char_suffix() {
        let f = GroupFilter::new(&["alt.?"]).unwrap();
        assert!(f.accepts("alt.x"), "alt.? must match alt.x");
        assert!(
            !f.accepts("alt.xy"),
            "alt.? must not match alt.xy (2 chars)"
        );
    }

    /// RFC 3977 §4.1: `*` matches any sequence including dots, even mid-pattern.
    #[test]
    fn group_filter_mid_string_star_matches() {
        let f = GroupFilter::new(&["comp.*.rust"]).unwrap();
        assert!(
            f.accepts("comp.lang.rust"),
            "comp.*.rust must match comp.lang.rust"
        );
        assert!(
            !f.accepts("comp.lang.python"),
            "comp.*.rust must not match comp.lang.python"
        );
    }

    /// RFC 3977 §4.1: `!` prefix negates; first-match-wins.
    #[test]
    fn group_filter_negation_excludes_before_positive() {
        let f = GroupFilter::new(&["!alt.binaries.*", "alt.*"]).unwrap();
        assert!(
            !f.accepts("alt.binaries.pictures"),
            "!alt.binaries.* must reject alt.binaries.pictures before alt.* fires"
        );
        assert!(
            f.accepts("alt.test"),
            "alt.* must accept alt.test (negation pattern does not fire)"
        );
    }

    /// RFC 3977 §4.1: comparison is case-insensitive (uppercase name).
    #[test]
    fn group_filter_case_insensitive_name_matches_lowercase_pattern() {
        let f = GroupFilter::new(&["comp.*"]).unwrap();
        assert!(
            f.accepts("COMP.LANG.RUST"),
            "comp.* must match COMP.LANG.RUST (case-insensitive per RFC 3977 §4.1)"
        );
    }

    /// RFC 3977 §4.1: comparison is case-insensitive (uppercase pattern).
    #[test]
    fn group_filter_case_insensitive_pattern_matches_lowercase_name() {
        let f = GroupFilter::new(&["COMP.*"]).unwrap();
        assert!(
            f.accepts("comp.lang.rust"),
            "COMP.* must match comp.lang.rust (case-insensitive)"
        );
    }

    /// Empty groups list in external pin service must validate successfully
    /// (accept-all case, no GroupFilter constructed).
    #[test]
    fn external_pin_service_empty_groups_accepts_all() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "secretx://env/PINATA_TOKEN"

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("empty groups must be valid (accept all)");
        let svc = &cfg.pinning.external_services[0];
        assert!(
            svc.groups.is_empty(),
            "groups must be empty to trigger accept-all path"
        );
    }

    /// Invalid wildmat character in ExternalPinServiceConfig::groups must
    /// be rejected at config validation time.
    #[test]
    fn external_pin_service_invalid_group_pattern_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "secretx://env/PINATA_TOKEN"
groups = ["comp.@invalid"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("invalid pattern character must fail config validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// All-negation groups in external pin service must be rejected.
    #[test]
    fn external_pin_service_all_negation_groups_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "secretx://env/PINATA_TOKEN"
groups = ["!comp.*", "!alt.*"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("all-negation groups in external pin service must fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// RFC 3977 §4.1: first-match-wins, positive before negation.
    #[test]
    fn group_filter_first_match_wins_positive_before_negation() {
        let f = GroupFilter::new(&["comp.*", "!comp.lang.*"]).unwrap();
        assert!(
            f.accepts("comp.lang.rust"),
            "comp.* fires before !comp.lang.* — must accept comp.lang.rust"
        );
    }

    /// RFC 3977 §4.1: first-match-wins, negation before positive.
    #[test]
    fn group_filter_first_match_wins_negation_before_positive() {
        let f = GroupFilter::new(&["!comp.lang.*", "comp.*"]).unwrap();
        assert!(
            !f.accepts("comp.lang.rust"),
            "!comp.lang.* fires before comp.* — must reject comp.lang.rust"
        );
    }

    /// A valid `ed25519:<hex>` trusted_peers entry must pass config validation.
    #[test]
    fn trusted_peers_valid_key_passes_validation() {
        use rand_core::OsRng;
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let hex = hex::encode(key.verifying_key().to_bytes());
        let toml = format!(
            r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30

[peering]
trusted_peers = ["ed25519:{hex}"]
"#
        );
        let f = write_toml(&toml);
        Config::from_file(f.path()).expect("valid ed25519 hex key must pass config validation");
    }

    /// A malformed trusted_peers entry (bad prefix) must fail config validation.
    #[test]
    fn trusted_peers_bad_prefix_fails_validation() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30

[peering]
trusted_peers = ["rsa:deadbeef"]
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("bad key prefix must fail config validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// A trusted_peers entry with invalid hex must fail config validation.
    #[test]
    fn trusted_peers_invalid_hex_fails_validation() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30

[peering]
trusted_peers = ["ed25519:notvalidhex!!"]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("invalid hex must fail config validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// use_emulator = true on a non-loopback listen address is a fatal error.
    #[test]
    fn test_azure_emulator_nonloopback_is_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
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

[peers]
addresses = []

[groups]
names = []

[backend]
type = "azure"

[backend.azure]
account = "devstoreaccount1"
container = "stoa-articles"
use_emulator = true

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        Config::from_file(f.path()).expect("use_emulator=true on loopback must be accepted");
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

    // ── WebDAV allow_http + credentials guard tests ───────────────────────────

    const TRANSIT_WEBDAV_PREFIX: &str = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30

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
            TRANSIT_WEBDAV_PREFIX
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
            TRANSIT_WEBDAV_PREFIX
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
            TRANSIT_WEBDAV_PREFIX
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
            TRANSIT_WEBDAV_PREFIX
        );
        let f = write_toml(&toml);
        Config::from_file(f.path())
            .expect("allow_http + credentials on localhost must be accepted");
    }
}
