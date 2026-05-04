use serde::Deserialize;
use std::path::Path;

pub use stoa_smtp::config::{MtaStsConfig, MtaStsDomainConfig, MtaStsMode, SmtpRelayPeerConfig};

pub use stoa_auth::{AuthConfig, UserCredential};

// Config fields are read from TOML; server logic will consume them as epics are implemented.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub activitypub: ActivityPubConfig,
    /// MTA-STS policy configuration (RFC 8461).
    #[serde(default)]
    pub mta_sts: MtaStsConfig,
}

fn default_base_url() -> String {
    "http://localhost".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub addr: String,
    /// The external base URL advertised in JMAP session responses,
    /// e.g. `https://mail.example.com`. Defaults to `http://localhost`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

fn default_database_url() -> String {
    "sqlite:///var/lib/stoa/mail/mail.db".to_string()
}

fn default_block_store_path() -> String {
    "/var/lib/stoa/mail/blocks.db".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
    /// Path to the SQLite block store for IPFS-style content-addressed storage.
    /// Must match the `[backend.sqlite] path` used by `stoa-reader` so both
    /// processes share the same block store.
    #[serde(default = "default_block_store_path")]
    pub block_store_path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            block_store_path: default_block_store_path(),
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
    /// Log level filter (e.g. "info", "debug", "stoa_mail=debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default)]
    pub format: LogFormat,
    /// Emit a WARN log for JMAP method calls slower than this many milliseconds.
    /// 0 disables slow-request WARN events; the histogram is always recorded.
    /// Default: 1000 ms.
    #[serde(default = "default_slow_jmap_threshold_ms")]
    pub slow_jmap_threshold_ms: u64,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_slow_jmap_threshold_ms() -> u64 {
    1000
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
            slow_jmap_threshold_ms: default_slow_jmap_threshold_ms(),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Enable CORS headers. Default: false (CORS disabled).
    pub enabled: bool,
    /// Allowed origins. Use ["*"] for permissive. Default: empty (deny all cross-origin).
    pub allowed_origins: Vec<String>,
}

fn default_smtp_relay_queue_dir() -> String {
    "/var/lib/stoa/mail/smtp-relay-queue".to_string()
}

fn default_smtp_relay_retry_secs() -> u64 {
    60
}

fn default_smtp_peer_down_secs() -> u64 {
    300
}

/// ActivityPub federation configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ActivityPubConfig {
    /// Enable the ActivityPub federation endpoints (`/.well-known/webfinger`,
    /// `/ap/groups/{name}`, etc.).  Default: `false`.
    pub enabled: bool,
    /// Verify HTTP Signatures on inbound `Create{Note}` activities.
    /// Default: `true`.  Set to `false` for development/testing.
    pub verify_http_signatures: bool,
}

impl Default for ActivityPubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_http_signatures: true,
        }
    }
}

/// Configuration for outbound SMTP relay delivery from the JMAP Email/set create path.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct DeliveryConfig {
    /// Outbound SMTP relay peers. If empty, no SMTP relay delivery is performed.
    pub smtp_relay_peers: Vec<SmtpRelayPeerConfig>,
    /// Directory for queued outbound SMTP relay messages. Created on startup if absent.
    #[serde(default = "default_smtp_relay_queue_dir")]
    pub smtp_relay_queue_dir: String,
    /// Seconds between relay queue drain scans. Defaults to 60.
    #[serde(default = "default_smtp_relay_retry_secs")]
    pub smtp_relay_retry_secs: u64,
    /// Seconds a peer stays in the "down" state after failure before retry. Defaults to 300.
    #[serde(default = "default_smtp_peer_down_secs")]
    pub smtp_peer_down_secs: u64,
}

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

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation(
                "listen.addr must not be empty".into(),
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
        if self.database.url.is_empty() {
            return Err(ConfigError::Validation(
                "database.url must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use stoa_core::util::is_loopback_addr;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "127.0.0.1:8080");
        assert_eq!(cfg.database.url, "sqlite:///var/lib/stoa/mail/mail.db");
        assert!(!cfg.auth.required);
        assert!(cfg.tls.cert_path.is_none());
        assert!(cfg.tls.key_path.is_none());
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.log.format, LogFormat::Text);
        assert_eq!(cfg.listen.base_url, "http://localhost");
    }

    #[test]
    fn parse_explicit_base_url() {
        let toml = r#"
[listen]
addr = "0.0.0.0:443"
base_url = "https://mail.example.com"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.base_url, "https://mail.example.com");
    }

    #[test]
    fn tls_both_or_neither() {
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/jmap.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn missing_listen_is_parse_error() {
        let toml = r#"
[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn empty_listen_addr_is_validation_error() {
        let toml = r#"
[listen]
addr = ""

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn empty_database_path_is_validation_error() {
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = ""

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn tls_both_set_is_valid() {
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/jmap.pem"
key_path = "/etc/ssl/private/jmap.key"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("both TLS fields is valid");
        assert_eq!(
            cfg.tls.cert_path.as_deref(),
            Some("/etc/ssl/certs/jmap.pem")
        );
        assert_eq!(
            cfg.tls.key_path.as_deref(),
            Some("/etc/ssl/private/jmap.key")
        );
    }

    #[test]
    fn io_error_on_missing_file() {
        let err =
            Config::from_file(Path::new("/nonexistent/path/mail.toml")).expect_err("should fail");
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn default_database_path_applied() {
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.database.url, "sqlite:///var/lib/stoa/mail/mail.db");
    }

    // --- guard condition tests ---

    #[test]
    fn test_mail_dev_mode_guard_condition_non_loopback_triggers() {
        // dev_mode=true + non-loopback → guard fires (condition is true)
        let toml = r#"
[listen]
addr = "0.0.0.0:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.auth.is_dev_mode(), "auth should be in dev mode");
        assert!(
            !is_loopback_addr(&cfg.listen.addr),
            "0.0.0.0 must not be loopback"
        );
        // Guard condition: dev_mode && !loopback → should abort
        assert!(cfg.auth.is_dev_mode() && !is_loopback_addr(&cfg.listen.addr));
    }

    #[test]
    fn test_mail_dev_mode_guard_condition_loopback_is_safe() {
        // dev_mode=true + loopback → guard does NOT fire (condition is false)
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.auth.is_dev_mode(), "auth should be in dev mode");
        assert!(
            is_loopback_addr(&cfg.listen.addr),
            "127.0.0.1 must be loopback"
        );
        // Guard condition: dev_mode && !loopback → false (safe)
        assert!(!(cfg.auth.is_dev_mode() && !is_loopback_addr(&cfg.listen.addr)));
    }

    #[test]
    fn test_mail_dev_mode_guard_condition_auth_required_is_safe() {
        // auth.required=true + non-loopback → guard does NOT fire
        let toml = r#"
[listen]
addr = "0.0.0.0:443"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = true

[[auth.users]]
username = "alice"
password = "$2b$12$KIXkB1XeBbcGZFxVf.DaGOd2sFHpLsmz/5oRCRY2z.ahE6Dc/l92S"

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(
            !cfg.auth.is_dev_mode(),
            "auth with required=true and users is not dev mode"
        );
        // Guard condition: dev_mode && !loopback → false (safe, auth is required)
        assert!(!(cfg.auth.is_dev_mode() && !is_loopback_addr(&cfg.listen.addr)));
    }

    #[test]
    fn test_activitypub_sig_guard_condition_non_loopback_triggers() {
        // activitypub.enabled + !verify_http_signatures + non-loopback → guard fires
        let toml = r#"
[listen]
addr = "0.0.0.0:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]

[activitypub]
enabled = true
verify_http_signatures = false
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.activitypub.enabled);
        assert!(!cfg.activitypub.verify_http_signatures);
        assert!(!is_loopback_addr(&cfg.listen.addr));
        // Guard condition: enabled && !verify && !loopback → should abort
        assert!(
            cfg.activitypub.enabled
                && !cfg.activitypub.verify_http_signatures
                && !is_loopback_addr(&cfg.listen.addr)
        );
    }

    #[test]
    fn test_activitypub_sig_guard_condition_loopback_is_safe() {
        // activitypub.enabled + !verify_http_signatures + loopback → guard does NOT fire
        let toml = r#"
[listen]
addr = "127.0.0.1:8080"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]

[activitypub]
enabled = true
verify_http_signatures = false
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.activitypub.enabled);
        assert!(!cfg.activitypub.verify_http_signatures);
        assert!(is_loopback_addr(&cfg.listen.addr));
        // Guard fires (enabled && !verify) but loopback branch → warn only, no exit
        assert!(cfg.activitypub.enabled && !cfg.activitypub.verify_http_signatures);
        assert!(is_loopback_addr(&cfg.listen.addr));
    }

    #[test]
    fn test_activitypub_sig_guard_condition_verify_true_is_safe() {
        // activitypub.enabled + verify_http_signatures=true → guard does NOT fire
        let toml = r#"
[listen]
addr = "0.0.0.0:443"

[database]
url = "sqlite:///var/lib/stoa/mail/mail.db"

[auth]
required = false

[tls]

[activitypub]
enabled = true
verify_http_signatures = true
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.activitypub.enabled);
        assert!(cfg.activitypub.verify_http_signatures);
        // Guard condition: enabled && !verify → false (verify is on)
        assert!(!(cfg.activitypub.enabled && !cfg.activitypub.verify_http_signatures));
    }
}
