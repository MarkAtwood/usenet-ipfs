use serde::Deserialize;
use std::path::Path;

use crate::config::{
    BackendConfig, ConfigError, DatabaseConfig, GroupsConfig, IpfsConfig, LogConfig, OperatorConfig,
};
use crate::peering::pipeline::StoreBuildResult;

/// Configuration for `stoa-rnews`.
///
/// Unlike the full transit [`Config`](crate::config::Config), this struct does
/// not require `[listen]`, `[gc]`, or `[pinning]` sections.  It is the minimum
/// configuration needed to run the rnews reader front-end.
#[derive(Debug, Deserialize)]
pub struct RnewsConfig {
    /// Database connection parameters.  Defaults to SQLite files in the
    /// current directory when the section is absent.
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Pluggable block-store backend.  When present, takes precedence over
    /// `[ipfs]`.  At least one of `[backend]` or `[ipfs]` with a non-empty
    /// `api_url` must be configured — validation enforces this.
    #[serde(default)]
    pub backend: Option<BackendConfig>,

    /// Legacy Kubo connection settings.  Retained for backward compatibility;
    /// new deployments should use `[backend]` instead.  Optional fallback when
    /// `[backend]` is absent.
    #[serde(default)]
    pub ipfs: Option<IpfsConfig>,

    /// Newsgroup filter.  `None` (section absent) means accept all groups.
    #[serde(default)]
    pub groups: Option<GroupsConfig>,

    /// Operator identity (signing key).  Defaults to an ephemeral key when
    /// the section is absent — suitable for development only.
    #[serde(default)]
    pub operator: OperatorConfig,

    /// Log output configuration.
    #[serde(default)]
    pub log: LogConfig,
}

impl RnewsConfig {
    /// Load and validate an `RnewsConfig` from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Self =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    ///
    /// Returns an error when neither `[backend]` nor `[ipfs]` with a non-empty
    /// `api_url` is present — the rnews reader cannot reach any block store
    /// without at least one of these.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let has_backend = self.backend.is_some();
        let has_ipfs_url = self
            .ipfs
            .as_ref()
            .map(|i| !i.api_url.is_empty())
            .unwrap_or(false);

        if !has_backend && !has_ipfs_url {
            return Err(ConfigError::Validation(
                "must have either [backend] or [ipfs] with a url".into(),
            ));
        }

        Ok(())
    }
}

/// Build the IPFS block store from an [`RnewsConfig`].
///
/// Delegates to [`crate::peering::pipeline::build_store_from_parts`], which is
/// the single canonical implementation shared with `stoa-transit`.  Backend
/// precedence: `[backend]` wins over legacy `[ipfs]`.
pub async fn build_store_for_rnews(config: &RnewsConfig) -> Result<StoreBuildResult, String> {
    let default_ipfs = IpfsConfig::default();
    let ipfs_fallback = config.ipfs.as_ref().unwrap_or(&default_ipfs);
    crate::peering::pipeline::build_store_from_parts(config.backend.as_ref(), ipfs_fallback).await
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
    fn test_rnews_config_minimal_valid() {
        let toml = r#"
[database]
url = "sqlite:///tmp/transit.db"

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/test.db"

[operator]
signing_key_path = "/tmp/key"
"#;
        let f = write_toml(toml);
        let result = RnewsConfig::from_file(f.path());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_rnews_config_no_listen_required() {
        // This TOML has no [listen] section — that must be fine for RnewsConfig.
        let toml = r#"
[database]
url = "sqlite:///tmp/transit.db"

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/test.db"

[operator]
signing_key_path = "/tmp/key"
"#;
        let f = write_toml(toml);
        let result = RnewsConfig::from_file(f.path());
        assert!(
            result.is_ok(),
            "RnewsConfig must not require [listen]; got {result:?}"
        );
    }

    #[test]
    fn test_rnews_config_fails_without_storage() {
        // No [backend] and no [ipfs] url — validation must reject this.
        let toml = r#"
[database]
url = "sqlite:///tmp/transit.db"

[operator]
signing_key_path = "/tmp/key"
"#;
        let f = write_toml(toml);
        let result = RnewsConfig::from_file(f.path());
        assert!(
            matches!(result, Err(ConfigError::Validation(_))),
            "expected Validation error, got {result:?}"
        );
    }
}
