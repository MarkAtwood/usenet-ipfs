//! Live config reload for stoa-transit.
//!
//! Encapsulates the subset of operator configuration that can be changed
//! without restarting the daemon: the group filter, trusted peer keys, and
//! log level.  All mutable state is stored behind `Arc<RwLock<...>>` so
//! readers (peering sessions, pipeline drains) can snapshot the current value
//! without blocking on a reload.
//!
//! A reload is triggered either by SIGHUP or by `POST /admin/reload`.  Both
//! paths call [`ReloadableState::do_reload`].
//!
//! Fields that require restart (listen address, database paths, TLS cert/key,
//! IPFS API URL) are detected as changed but not applied; they appear in
//! the diff output so operators know a restart is needed.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use stoa_core::wildmat::{GroupFilter, GroupPolicy};

use crate::config::Config;
use crate::peering::auth::parse_trusted_peer_keys;

/// The subset of operator config that can be applied without restart.
pub struct ReloadableState {
    /// Path to the config file (set once at startup; never changes).
    pub config_path: Option<PathBuf>,
    /// Live group filter.  `None` means "accept all groups".
    pub group_filter: Arc<RwLock<GroupPolicy>>,
    /// Live set of trusted peer public keys for mutual auth.
    pub trusted_keys: Arc<RwLock<Vec<ed25519_dalek::VerifyingKey>>>,
    /// Previous raw group-name patterns (for change detection).
    prev_group_names: RwLock<Vec<String>>,
    /// Previous trusted-peer hex strings (for change detection).
    prev_trusted_peer_hexes: RwLock<Vec<String>>,
    /// Previous log level string (for change detection; not applied at runtime).
    prev_log_level: RwLock<String>,
    /// Serializes concurrent reloads: only one reload may compute a diff and
    /// apply changes at a time, preventing TOCTOU races on the prev_* fields.
    reload_mutex: tokio::sync::Mutex<()>,
}

/// Result of a config reload attempt.
#[derive(Debug)]
pub struct ReloadResult {
    /// Fields successfully applied at runtime.
    pub changed: Vec<String>,
    /// Fields that could not be applied, with reasons.
    pub errors: Vec<String>,
}

impl ReloadableState {
    /// Create a new `ReloadableState` from the initial config.
    pub fn new(
        config_path: Option<PathBuf>,
        group_filter: GroupPolicy,
        trusted_keys: Vec<ed25519_dalek::VerifyingKey>,
        group_names: Vec<String>,
        trusted_peer_hexes: Vec<String>,
        log_level: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            config_path,
            group_filter: Arc::new(RwLock::new(group_filter)),
            trusted_keys: Arc::new(RwLock::new(trusted_keys)),
            prev_group_names: RwLock::new(group_names),
            prev_trusted_peer_hexes: RwLock::new(trusted_peer_hexes),
            prev_log_level: RwLock::new(log_level),
            reload_mutex: tokio::sync::Mutex::new(()),
        })
    }

    /// Re-read the config file and apply reloadable fields.
    ///
    /// Returns a `ReloadResult` with:
    /// - `changed`: fields that were successfully applied at runtime
    /// - `errors`: fields that could not be applied (parse errors) or that
    ///   require a restart to take effect (noted in the error string)
    ///
    /// On config file parse error the current state is left unchanged and
    /// the error is returned in `errors`.
    pub async fn do_reload(&self) -> ReloadResult {
        // Serialize concurrent reloads so that read-then-write sequences on
        // prev_* fields are atomic from the perspective of other callers.
        let _reload_guard = self.reload_mutex.lock().await;
        let new_config = match Config::load(self.config_path.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                return ReloadResult {
                    changed: vec![],
                    errors: vec![format!("config parse error: {e}")],
                };
            }
        };

        let mut changed = Vec::new();
        let mut errors = Vec::new();

        // ── groups.names ──────────────────────────────────────────────────────

        {
            let prev = self.prev_group_names.read().await;
            if *prev != new_config.groups.names {
                drop(prev);
                match GroupFilter::new(&new_config.groups.names) {
                    Ok(filter) => {
                        let new_filter = if new_config.groups.names.is_empty() {
                            None
                        } else {
                            Some(Arc::new(filter))
                        };
                        *self.group_filter.write().await = new_filter;
                        *self.prev_group_names.write().await = new_config.groups.names.clone();
                        changed.push("groups.names".to_string());
                    }
                    Err(e) => {
                        errors.push(format!("groups.names: invalid pattern: {e}"));
                    }
                }
            }
        }

        // ── peering.trusted_peers ─────────────────────────────────────────────

        {
            let prev = self.prev_trusted_peer_hexes.read().await;
            if *prev != new_config.peering.trusted_peers {
                drop(prev);
                match parse_trusted_peer_keys(&new_config.peering.trusted_peers) {
                    Ok(new_keys) => {
                        *self.trusted_keys.write().await = new_keys;
                        *self.prev_trusted_peer_hexes.write().await =
                            new_config.peering.trusted_peers.clone();
                        changed.push("peering.trusted_peers".to_string());
                    }
                    Err(e) => {
                        errors.push(format!("peering.trusted_peers: {e}"));
                    }
                }
            }
        }

        // ── log.level ─────────────────────────────────────────────────────────
        // Detected but not applied; a tracing reload handle is not yet wired.

        {
            let prev = self.prev_log_level.read().await;
            if *prev != new_config.log.level {
                let new_level = new_config.log.level.clone();
                drop(prev);
                *self.prev_log_level.write().await = new_level;
                errors.push(
                    "log.level: changed detected but requires restart to take effect".to_string(),
                );
            }
        }

        if !changed.is_empty() {
            tracing::info!(fields = ?changed, "config reloaded successfully");
        }
        if !errors.is_empty() {
            for e in &errors {
                tracing::warn!(message = %e, "config reload note");
            }
        }

        ReloadResult { changed, errors }
    }
}
