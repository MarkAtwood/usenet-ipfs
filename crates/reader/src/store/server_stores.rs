//! Shared server-side storage handles for the NNTP POST pipeline and article
//! retrieval.
//!
//! `ServerStores` is constructed once at server startup and shared (via `Arc`)
//! across all sessions. It holds the in-process IPFS block store, the
//! message-id map, the group log, the article number store, the HLC clock,
//! and the operator signing key.

use std::sync::Arc;

use tokio::sync::Mutex;

use stoa_core::audit::{build_audit_logger, AuditLogger};
use stoa_core::group_log::SqliteLogStorage;
use stoa_core::hlc::HlcClock;
use stoa_core::msgid_map::MsgIdMap;
use stoa_core::signing::{generate_signing_key, hlc_node_id, SigningKey};

use crate::auth_limiter::{AuthFailureTracker, DEFAULT_MAX_ENTRIES};

use mail_auth::MessageAuthenticator;
use stoa_auth::{OidcStore, TrustedIssuerStore};
use stoa_smtp::SmtpRelayQueue;
use stoa_verify::VerificationStore;

use crate::post::ipfs_write::{IpfsBlockStore, MemIpfsStore};
use crate::search::TantivySearchIndex;
use crate::store::article_numbers::ArticleNumberStore;
use crate::store::overview::OverviewStore;
use stoa_auth::ClientCertStore;
use stoa_auth::CredentialStore;

/// All storage handles needed by the POST pipeline and article retrieval.
///
/// Constructed once at startup and cloned (`Arc`) into each session task.
pub struct ServerStores {
    pub ipfs_store: Arc<dyn IpfsBlockStore>,
    pub msgid_map: Arc<MsgIdMap>,
    pub log_storage: Arc<SqliteLogStorage>,
    pub article_numbers: Arc<ArticleNumberStore>,
    pub overview_store: Arc<OverviewStore>,
    pub credential_store: Arc<CredentialStore>,
    /// Client certificate fingerprint → username store for TLS cert-based auth.
    pub client_cert_store: Arc<ClientCertStore>,
    /// Trusted CA issuer store for issuer-chain certificate auth.
    ///
    /// Consulted after fingerprint-based auth fails: if the leaf cert was
    /// signed by a configured CA and the CN matches the requested username,
    /// the session is authenticated without a password.
    pub trusted_issuer_store: Arc<TrustedIssuerStore>,
    /// HLC clock — shared across sessions, protected by a mutex.
    pub clock: Arc<Mutex<HlcClock>>,
    /// Operator signing key — ephemeral in-process key (no PEM file required).
    pub signing_key: Arc<SigningKey>,
    /// Full-text search index (Tantivy-backed). None when search is disabled.
    pub search_index: Option<Arc<TantivySearchIndex>>,
    /// Outbound SMTP relay queue. None when smtp_relay is not configured.
    pub smtp_relay_queue: Option<Arc<SmtpRelayQueue>>,
    /// Article signature verification store (article_verifications + seen_keys).
    pub verification_store: Arc<VerificationStore>,
    /// DKIM verifier backed by system DNS resolver.
    pub dkim_authenticator: Arc<MessageAuthenticator>,
    /// Hostname injected into the Path: header of POST articles (RFC 5536 §3.1).
    pub path_hostname: String,
    /// Email address for the `mail-complaints-to` field in `Injection-Info:`
    /// (RFC 5536 §3.2.9).  `None` when not configured.
    pub mail_complaints_to: Option<String>,
    /// Maximum allowed clock skew (seconds) between the article `Date:` and
    /// server time before `Injection-Date:` is added (RFC 5536 §3.2.3).
    /// `None` disables `Injection-Date:` injection entirely.
    pub max_clock_skew_secs: Option<u64>,
    /// Async audit logger. None only in unit-test stores created by new_mem().
    pub audit_logger: Option<Arc<dyn AuditLogger>>,
    /// Per-IP authentication failure tracker for fail2ban-compatible lockout events.
    pub auth_failure_tracker: Arc<tokio::sync::Mutex<AuthFailureTracker>>,
    /// OIDC JWT validator for SASL OAUTHBEARER (RFC 7628).
    /// `None` when no `[[auth.oidc_providers]]` entries are configured.
    pub oidc_store: Option<Arc<OidcStore>>,
}

impl ServerStores {
    /// Construct a `ServerStores` backed by a `KuboBlockStore` (Kubo HTTP RPC)
    /// with optional local FS cache, credential store from config, and on-disk
    /// SQLite databases with WAL mode.
    ///
    /// Database parent directories are created at startup if they do not exist.
    pub async fn new_with_ipfs(config: &crate::config::Config) -> Result<Self, String> {
        // Create local block cache directory if configured.
        let cache_path = config
            .backend
            .as_ref()
            .and_then(|b| b.kubo.as_ref())
            .and_then(|k| k.cache_path.as_deref())
            .or(config.ipfs.cache_path.as_deref());
        if let Some(dir) = cache_path {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| format!("failed to create IPFS cache dir '{dir}': {e}"))?;
        }
        let ipfs_store = crate::post::ipfs_write::build_block_store(config).await?;

        // Ensure database parent directories exist for SQLite URLs before opening pools.
        for url in [
            &config.database.reader_url,
            &config.database.core_url,
            &config.database.verify_url,
        ] {
            if let Some(path_str) = url.strip_prefix("sqlite://") {
                let p = std::path::Path::new(path_str);
                if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        format!(
                            "cannot create database directory '{}': {e}",
                            parent.display()
                        )
                    })?;
                }
            }
        }

        let reader_pool =
            make_disk_pool_with_reader_migrations(&config.database.reader_url).await?;
        let core_pool = make_disk_pool_with_core_migrations(&config.database.core_url).await?;
        let log_pool = core_pool.clone();
        let audit_logger = build_audit_logger(&config.audit, &core_pool)
            .map_err(|e| format!("audit logger init failed: {e}"))?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // infallible: system clock is always after UNIX_EPOCH on any supported platform
            .unwrap()
            .as_millis() as u64;

        let signing_key =
            load_or_generate_signing_key(config.operator.signing_key_path.as_deref()).await?;
        let node_id = hlc_node_id(&signing_key);

        let trusted_issuer_store = TrustedIssuerStore::from_config(&config.auth.trusted_issuers)?;

        let smtp_relay_queue = build_smtp_relay_queue(&config.smtp_relay, &config.path_hostname)
            .await
            .map_err(|e| format!("smtp relay queue init failed: {e}"))?;

        let verify_pool =
            make_disk_pool_with_verify_migrations(&config.database.verify_url).await?;
        let dkim_authenticator = MessageAuthenticator::new_cloudflare_tls()
            .map_err(|e| format!("DKIM authenticator init failed: {e}"))?;

        let oidc_store = if config.auth.oidc_providers.is_empty() {
            None
        } else {
            Some(Arc::new(OidcStore::new(config.auth.oidc_providers.clone())))
        };

        Ok(Self {
            ipfs_store,
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(SqliteLogStorage::new(log_pool)),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(
                stoa_auth::build_credential_store(
                    &config.auth.users,
                    config.auth.credential_file.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?,
            ),
            client_cert_store: Arc::new(ClientCertStore::from_config(&config.auth.client_certs)),
            trusted_issuer_store: Arc::new(trusted_issuer_store),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
            search_index: TantivySearchIndex::open(&config.search)
                .map_err(|e| format!("search index init failed: {e}"))?
                .map(Arc::new),
            smtp_relay_queue,
            verification_store: Arc::new(VerificationStore::new(verify_pool)),
            dkim_authenticator: Arc::new(dkim_authenticator),
            path_hostname: config.path_hostname.clone(),
            mail_complaints_to: config.operator.mail_complaints_to.clone(),
            max_clock_skew_secs: config.limits.max_clock_skew_secs,
            audit_logger: Some(audit_logger),
            auth_failure_tracker: Arc::new(tokio::sync::Mutex::new(AuthFailureTracker::new(
                10,
                std::time::Duration::from_secs(60),
                DEFAULT_MAX_ENTRIES,
            ))),
            oidc_store,
        })
    }

    /// Construct an ephemeral `ServerStores` backed entirely by in-memory
    /// stores and in-memory SQLite databases.
    ///
    /// The reader-crate migrations (article_numbers) and core-crate migrations
    /// (msgid_map) use overlapping version numbers, so they run against
    /// separate pools.
    pub async fn new_mem() -> Self {
        Self::new_mem_impl(true).await
    }

    /// Identical to `new_mem` but with `search_index: None`, for testing
    /// the 503 code path when search is disabled.
    #[cfg(test)]
    pub async fn new_mem_no_search() -> Self {
        Self::new_mem_impl(false).await
    }

    async fn new_mem_impl(with_search: bool) -> Self {
        let reader_pool = make_pool_with_reader_migrations().await;
        let core_pool = make_pool_with_core_migrations().await;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // infallible: system clock is always after UNIX_EPOCH on any supported platform
            .unwrap()
            .as_millis() as u64;

        // Generate a fresh random key per test instance; derive node ID from it.
        let signing_key = generate_signing_key();
        let node_id = hlc_node_id(&signing_key);

        let log_pool = core_pool.clone();
        let verify_pool = make_pool_with_verify_migrations().await;
        Self {
            ipfs_store: Arc::new(MemIpfsStore::new()),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(SqliteLogStorage::new(log_pool)),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(CredentialStore::empty()),
            client_cert_store: Arc::new(ClientCertStore::empty()),
            trusted_issuer_store: Arc::new(TrustedIssuerStore::empty()),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
            search_index: if with_search {
                let cfg = crate::config::SearchConfig::default();
                Some(Arc::new(
                    TantivySearchIndex::open_in_memory(&cfg)
                        .expect("in-memory tantivy index cannot fail"),
                ))
            } else {
                None
            },
            smtp_relay_queue: None,
            verification_store: Arc::new(VerificationStore::new(verify_pool)),
            dkim_authenticator: Arc::new(
                MessageAuthenticator::new_cloudflare_tls()
                    .or_else(|_| MessageAuthenticator::new_system_conf())
                    .expect("DKIM authenticator init failed"),
            ),
            path_hostname: "localhost".to_owned(),
            mail_complaints_to: None,
            max_clock_skew_secs: None,
            audit_logger: None,
            auth_failure_tracker: Arc::new(tokio::sync::Mutex::new(AuthFailureTracker::new(
                10,
                std::time::Duration::from_secs(60),
                DEFAULT_MAX_ENTRIES,
            ))),
            oidc_store: None,
        }
    }
}

/// Create a named in-memory AnyPool with reader-crate migrations.
///
/// Uses SQLite shared-cache named in-memory databases so that the migration
/// pool and the app pool share the same database.  The app pool is opened
/// first so the named database stays alive across the migration step.
///
/// A per-call sequence number ensures each invocation gets a distinct
/// in-memory database even when `new_mem()` is called concurrently.
async fn make_pool_with_reader_migrations() -> sqlx::AnyPool {
    static DB_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // `sqlite:file:...` (single colon, no `//`) is the correct URI form for
    // named shared-cache in-memory databases understood by the AnyPool driver.
    let url = format!("sqlite:file:reader_stores_{n}?mode=memory&cache=shared");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("reader pool");
    crate::migrations::run_migrations(&url)
        .await
        .expect("reader migrations");
    pool
}

/// Create a named in-memory AnyPool with verify-crate migrations.
async fn make_pool_with_verify_migrations() -> sqlx::AnyPool {
    static DB_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let url = format!("sqlite:file:verify_stores_{n}?mode=memory&cache=shared");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("verify pool");
    stoa_verify::run_migrations(&url)
        .await
        .expect("verify migrations");
    pool
}

/// Create a named in-memory AnyPool with core-crate migrations.
async fn make_pool_with_core_migrations() -> sqlx::AnyPool {
    static DB_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let url = format!("sqlite:file:core_stores_{n}?mode=memory&cache=shared");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("core pool");
    stoa_core::migrations::run_migrations(&url)
        .await
        .expect("core migrations");
    pool
}

/// Open an AnyPool backed by the given URL with reader-crate migrations.
async fn make_disk_pool_with_reader_migrations(url: &str) -> Result<sqlx::AnyPool, String> {
    crate::migrations::run_migrations(url)
        .await
        .map_err(|e| format!("reader database migration failed: {e}"))?;
    stoa_core::db_pool::try_open_any_pool(url, 8)
        .await
        .map_err(|e| format!("failed to open reader database '{url}': {e}"))
}

/// Open an AnyPool backed by the given URL with core-crate migrations.
async fn make_disk_pool_with_core_migrations(url: &str) -> Result<sqlx::AnyPool, String> {
    stoa_core::migrations::run_migrations(url)
        .await
        .map_err(|e| format!("core database migration failed: {e}"))?;
    stoa_core::db_pool::try_open_any_pool(url, 8)
        .await
        .map_err(|e| format!("failed to open core database '{url}': {e}"))
}

/// Open an AnyPool backed by the given URL with verify-crate migrations.
async fn make_disk_pool_with_verify_migrations(url: &str) -> Result<sqlx::AnyPool, String> {
    stoa_verify::run_migrations(url)
        .await
        .map_err(|e| format!("verify database migration failed: {e}"))?;
    stoa_core::db_pool::try_open_any_pool(url, 8)
        .await
        .map_err(|e| format!("failed to open verify database '{url}': {e}"))
}

/// Load a 32-byte Ed25519 signing key from the given file path or secretx URI,
/// or generate a fresh random key if no path is configured.
///
/// If `path` is `None`, a random ephemeral key is generated and a warning is
/// emitted.  This is acceptable for development but insecure for production
/// because the signing key changes on every restart.
///
/// `path` may be either a filesystem path (read as a 32-byte binary file) or
/// a `secretx:` URI whose resolved bytes are used directly.
async fn load_or_generate_signing_key(path: Option<&str>) -> Result<SigningKey, String> {
    match path {
        Some(p) if p.starts_with("secretx:") => {
            let store = secretx::from_uri(p)
                .map_err(|e| format!("operator.signing_key_path: invalid secretx URI: {e}"))?;
            let secret = store
                .get()
                .await
                .map_err(|e| format!("operator.signing_key_path: secretx retrieval failed: {e}"))?;
            stoa_core::signing::load_signing_key_from_bytes(secret.as_bytes())
                .map_err(|e| e.to_string())
        }
        Some(p) => {
            stoa_core::signing::load_signing_key(std::path::Path::new(p)).map_err(|e| e.to_string())
        }
        None => {
            let key = generate_signing_key();
            tracing::warn!(
                "no operator.signing_key_path configured — \
                 using an ephemeral signing key that changes on every restart; \
                 set [operator] signing_key_path in config for a stable production key"
            );
            Ok(key)
        }
    }
}

/// Construct a `SmtpRelayQueue` from the reader's `[smtp_relay]` config section.
///
/// Returns `None` when `queue_dir` is absent or `peers` is empty — both
/// conditions disable relay.  Returns `Err` only if the queue directory
/// cannot be created or the DKIM key is malformed.
async fn build_smtp_relay_queue(
    cfg: &crate::config::SmtpRelayConfig,
    local_hostname: &str,
) -> Result<Option<Arc<SmtpRelayQueue>>, String> {
    let queue_dir = match cfg.queue_dir.as_deref() {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(None),
    };
    if cfg.peers.is_empty() {
        return Ok(None);
    }
    let down_backoff = std::time::Duration::from_secs(cfg.peer_down_secs);

    let dkim_signer = if let Some(dcfg) = &cfg.dkim {
        use base64::Engine as _;
        use zeroize::Zeroize as _;
        let resolved_seed = stoa_core::secret::resolve_secret_uri(
            Some(dcfg.key_seed_b64.clone()),
            "smtp_relay.dkim.key_seed_b64",
        )
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "smtp_relay.dkim.key_seed_b64: resolved to empty".to_string())?;
        let mut seed = base64::engine::general_purpose::STANDARD
            .decode(&resolved_seed)
            .map_err(|e| format!("smtp_relay.dkim.key_seed_b64: invalid base64: {e}"))?;
        let pubkey = base64::engine::general_purpose::STANDARD
            .decode(&dcfg.public_key_b64)
            .map_err(|e| format!("smtp_relay.dkim.public_key_b64: invalid base64: {e}"))?;
        let ed_key =
            mail_auth::common::crypto::Ed25519Key::from_seed_and_public_key(&seed, &pubkey)
                .map_err(|e| format!("smtp_relay.dkim: failed to construct Ed25519 key: {e}"))?;
        seed.zeroize();
        tracing::info!(
            domain = %dcfg.domain,
            selector = %dcfg.selector,
            "smtp relay DKIM signing enabled"
        );
        Some(stoa_smtp::config::build_dkim_signer_arc(dcfg, ed_key))
    } else {
        None
    };

    let mta_sts_enforcer = if cfg.mta_sts_enabled {
        match stoa_smtp::MtaStsEnforcer::new(
            cfg.mta_sts_fetch_timeout_ms,
            cfg.mta_sts_max_policy_body_bytes,
        ) {
            Ok(e) => {
                tracing::info!("MTA-STS outbound enforcement enabled");
                // NOTE: e.tlsrpt_recorder() is intentionally not retrieved here.
                // The TlsrptRecorder accumulates per-domain TLS failure data for
                // RFC 8460 reporting, but the report generation and submission path
                // (periodic SMTP/HTTPS reports to domain owners) is not yet
                // implemented.  Tracked in stoa-2xeks.29.1.
                Some(Arc::new(e))
            }
            Err(e) => {
                tracing::warn!("MTA-STS enforcer init failed: {e}; MTA-STS disabled");
                None
            }
        }
    } else {
        None
    };

    let queue = SmtpRelayQueue::new(
        queue_dir,
        cfg.peers.clone(),
        down_backoff,
        dkim_signer,
        local_hostname,
        mta_sts_enforcer,
    )
    .map_err(|e| e.to_string())?;
    Ok(Some(queue))
}
