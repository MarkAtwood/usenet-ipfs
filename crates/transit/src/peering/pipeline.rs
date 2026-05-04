//! Store-and-forward pipeline for the transit daemon.
//!
//! After an article passes `check_ingest`, `run_pipeline` writes it to IPFS,
//! records the Message-ID → CID mapping, and appends to each group log.

/// Typed error returned by [`run_pipeline`].
///
/// The variant encodes whether the failure is permanent (article is defective;
/// do not retry) or transient (infrastructure error; may succeed on retry).
/// Callers must match on the variant — never on the inner message string.
#[derive(Debug)]
pub enum PipelineError {
    /// Permanent failure: the article is defective and retrying cannot help
    /// (e.g. missing `Message-ID`, signature self-check failure).
    Permanent(String),
    /// Transient failure: infrastructure is unavailable; may succeed on retry
    /// (e.g. IPFS write failed, database error).
    Transient(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Permanent(m) => write!(f, "permanent: {m}"),
            PipelineError::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

impl std::error::Error for PipelineError {}

use super::lmdb_store::LmdbStore;
use async_trait::async_trait;
use cid::Cid;
use mail_auth::MessageAuthenticator;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::AnyPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use stoa_core::{
    article::GroupName,
    canonical::log_entry_canonical_bytes,
    group_log::{
        append::append as crdt_append, storage::LogStorage, types::LogEntry,
        verify::verify_signature,
    },
    hlc::HlcTimestamp,
    msgid_map::MsgIdMap,
    signing::{sign, SigningKey},
    wildmat::GroupPolicy,
};
use stoa_verify::VerificationStore;

// ── IPFS abstraction ──────────────────────────────────────────────────────────

/// Error returned by [`IpfsStore`] methods.
#[non_exhaustive]
#[derive(Debug)]
pub enum IpfsError {
    WriteFailed(String),
    ReadFailed(String),
}

impl std::fmt::Display for IpfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsError::WriteFailed(m) => write!(f, "IPFS write failed: {m}"),
            IpfsError::ReadFailed(m) => write!(f, "IPFS read failed: {m}"),
        }
    }
}

impl std::error::Error for IpfsError {}

/// Abstraction over IPFS raw block storage.
///
/// The trait is object-safe and mockable; production code uses [`KuboStore`]
/// backed by a Kubo daemon; tests use [`MemIpfsStore`].
#[async_trait]
pub trait IpfsStore: Send + Sync {
    /// Write `data` to IPFS. Returns the CID of the stored block.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError>;

    /// Fetch the raw block bytes for `cid`.
    ///
    /// Returns `None` if the block is not locally available (not pinned,
    /// not yet retrieved from the network). Returns `Err` on I/O or
    /// internal errors.
    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError>;

    /// Mark `cid` for deletion.
    ///
    /// The default implementation signals that deletion is deferred — callers
    /// must not assume the block is gone until `get_raw` returns `None`.
    /// Override to provide backend-specific behaviour (e.g. Kubo `pin/rm`).
    async fn delete(&self, _cid: &Cid) -> Result<stoa_core::ipfs::DeletionOutcome, IpfsError> {
        Ok(stoa_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ── In-memory IPFS store for tests ───────────────────────────────────────────

/// In-memory IPFS block store for tests.
pub struct MemIpfsStore {
    blocks: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemIpfsStore {
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemIpfsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpfsStore for MemIpfsStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        // Raw codec (0x55) — article bytes are opaque blobs at the block layer.
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cid.to_string(), data.to_vec());
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        Ok(self
            .blocks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&cid.to_string())
            .cloned())
    }
}

// ── Production Kubo store ─────────────────────────────────────────────────────

/// IPFS block store backed by a Kubo daemon via its HTTP RPC API.
///
/// Requires a running Kubo node reachable at the configured `api_url`.
/// `KuboStore` is cheaply cloneable — the underlying `CircuitBreakerKuboClient`
/// holds only a `reqwest::Client` (connection-pooled), the API URL string, and
/// a shared circuit-breaker state.
pub struct KuboStore {
    client: stoa_core::ipfs::CircuitBreakerKuboClient,
}

impl KuboStore {
    /// Create a store targeting the Kubo daemon at `api_url`
    /// (e.g. `"http://127.0.0.1:5001"`).
    ///
    /// The Kubo client is wrapped in a circuit breaker with default thresholds
    /// (5 failures in 10 s → open; probe after 30 s).  State transitions are
    /// reported to the `kubo_circuit_breaker_*` Prometheus metrics.
    pub fn new(api_url: &str) -> Self {
        let client = stoa_core::ipfs::CircuitBreakerKuboClient::new(
            api_url,
            stoa_core::circuit_breaker::CircuitBreakerConfig::default(),
        )
        .with_state_change_callback(|old, new| {
            use stoa_core::circuit_breaker::CbState;
            let state_int: i64 = match new {
                CbState::Closed => 0,
                CbState::HalfOpen => 1,
                CbState::Open => 2,
            };
            crate::metrics::KUBO_CIRCUIT_BREAKER_STATE.set(state_int);
            let old_s = old.to_string();
            let new_s = new.to_string();
            crate::metrics::KUBO_CIRCUIT_BREAKER_TRANSITIONS_TOTAL
                .with_label_values(&[&old_s, &new_s])
                .inc();
        });
        Self { client }
    }

    /// Return a clone of the underlying Kubo HTTP client (bypasses the circuit
    /// breaker).  Used by the IPNS publisher, which has its own rate limiter
    /// and advisory-lock guard.
    pub fn kubo_client(&self) -> stoa_core::ipfs::KuboHttpClient {
        self.client.inner().clone()
    }
}

#[async_trait]
impl IpfsStore for KuboStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        self.client
            .block_put(data, 0x55)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        self.client
            .block_get(cid)
            .await
            .map_err(|e| IpfsError::ReadFailed(e.to_string()))
    }

    /// Unpin `cid` from Kubo. The block remains readable until `ipfs repo gc` runs.
    async fn delete(&self, cid: &Cid) -> Result<stoa_core::ipfs::DeletionOutcome, IpfsError> {
        self.client
            .pin_rm(cid)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        Ok(stoa_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ── Store factory ─────────────────────────────────────────────────────────────

/// Result of [`build_store`]: the constructed store and an optional Kubo client
/// for IPNS publishing (present only when the backend is Kubo).
pub struct StoreBuildResult {
    pub store: Arc<dyn IpfsStore>,
    /// Kubo HTTP client for IPNS publishing. `None` for non-Kubo backends.
    pub kubo_client: Option<stoa_core::ipfs::KuboHttpClient>,
}

/// Construct the IPFS block store from backend and ipfs configuration.
///
/// Prefers `backend` when `Some`; falls back to the legacy `ipfs_fallback`
/// URL for backward compatibility.
///
/// This is the canonical implementation shared by both `stoa-transit` (via
/// [`build_store`]) and `stoa-rnews` (via [`crate::rnews_config::build_store_for_rnews`]).
/// Add new backend arms here; callers get them automatically.
pub async fn build_store_from_parts(
    backend: Option<&crate::config::BackendConfig>,
    ipfs_fallback: &crate::config::IpfsConfig,
) -> Result<StoreBuildResult, String> {
    if let Some(backend) = backend {
        use crate::config::BackendType;
        match backend.backend_type {
            BackendType::Kubo => {
                let kubo_cfg = backend
                    .kubo
                    .as_ref()
                    .ok_or("backend.type = 'kubo' requires a [backend.kubo] section")?;
                let store = KuboStore::new(&kubo_cfg.api_url);
                let client = store.kubo_client();
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: Some(client),
                })
            }
            BackendType::S3 => {
                let s3_cfg = backend
                    .s3
                    .as_ref()
                    .ok_or("backend.type = 's3' requires a [backend.s3] section")?;
                let store = super::s3_store::S3Store::new(s3_cfg)
                    .await
                    .map_err(|e| format!("S3 store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::Azure => {
                let azure_cfg = backend
                    .azure
                    .as_ref()
                    .ok_or("backend.type = 'azure' requires a [backend.azure] section")?;
                let store = super::azure_store::AzureStore::new(azure_cfg)
                    .await
                    .map_err(|e| format!("Azure store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::Gcs => {
                let gcs_cfg = backend
                    .gcs
                    .as_ref()
                    .ok_or("backend.type = 'gcs' requires a [backend.gcs] section")?;
                let store = super::gcs_store::GcsStore::new(gcs_cfg)
                    .await
                    .map_err(|e| format!("GCS store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::Sqlite => {
                let sqlite_cfg = backend
                    .sqlite
                    .as_ref()
                    .ok_or("backend.type = 'sqlite' requires a [backend.sqlite] section")?;
                let store =
                    super::sqlite_store::SqliteStore::open(std::path::Path::new(&sqlite_cfg.path))
                        .await
                        .map_err(|e| format!("sqlite store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::Filesystem => {
                let fs_cfg = backend
                    .filesystem
                    .as_ref()
                    .ok_or("backend.type = 'filesystem' requires a [backend.filesystem] section")?;
                let store = super::fs_store::FsStore::open(
                    std::path::Path::new(&fs_cfg.path),
                    fs_cfg.max_bytes,
                )
                .map_err(|e| format!("filesystem store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::Lmdb => {
                let lmdb_cfg = backend
                    .lmdb
                    .as_ref()
                    .ok_or("backend.type = 'lmdb' requires a [backend.lmdb] section")?;
                let store =
                    LmdbStore::open(std::path::Path::new(&lmdb_cfg.path), lmdb_cfg.map_size_gb)
                        .map_err(|e| format!("LMDB store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::WebDav => {
                let webdav_cfg = backend
                    .webdav
                    .as_ref()
                    .ok_or("backend.type = 'web_dav' requires a [backend.webdav] section")?;
                let store = super::webdav_store::WebDavStore::new(webdav_cfg)
                    .await
                    .map_err(|e| format!("WebDAV store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::RocksDb => {
                let rocks_cfg = backend
                    .rocksdb
                    .as_ref()
                    .ok_or("backend.type = 'rocks_db' requires a [backend.rocksdb] section")?;
                let store = super::rocks_store::RocksStore::open(
                    std::path::Path::new(&rocks_cfg.path),
                    rocks_cfg.cache_size_mb,
                )
                .map_err(|e| format!("RocksDB store init failed: {e}"))?;
                Ok(StoreBuildResult {
                    store: Arc::new(store),
                    kubo_client: None,
                })
            }
            BackendType::PgBlob => Err("backend.type = 'pg_blob' is not supported; \
                     use the SQLite or filesystem backend for embedded storage, \
                     or S3 for cloud storage"
                .into()),
            BackendType::GitSha256 => Err("backend.type = 'git_sha256' is not supported; \
                     git object store is a reader-only backend"
                .into()),
            BackendType::Rados => {
                #[cfg(not(feature = "rados"))]
                return Err(
                    "backend.type = 'rados' requires the 'rados' Cargo feature; \
                     rebuild with --features rados (requires librados-dev)"
                        .into(),
                );
                #[cfg(feature = "rados")]
                {
                    let rados_cfg = backend
                        .rados
                        .as_ref()
                        .ok_or("backend.type = 'rados' requires a [backend.rados] section")?;
                    let store = super::rados_store::RadosStore::open(rados_cfg)
                        .map_err(|e| format!("RADOS store init failed: {e}"))?;
                    Ok(StoreBuildResult {
                        store: Arc::new(store),
                        kubo_client: None,
                    })
                }
            }
        }
    } else {
        // Backward-compat: use legacy [ipfs] section.
        let store = KuboStore::new(&ipfs_fallback.api_url);
        let client = store.kubo_client();
        Ok(StoreBuildResult {
            store: Arc::new(store),
            kubo_client: Some(client),
        })
    }
}

/// Construct the IPFS block store from a full [`crate::config::Config`].
///
/// Thin wrapper around [`build_store_from_parts`].  Prefers `config.backend`
/// when present; falls back to the legacy `config.ipfs` section.
pub async fn build_store(config: &crate::config::Config) -> Result<StoreBuildResult, String> {
    build_store_from_parts(config.backend.as_ref(), &config.ipfs).await
}

// ── Pipeline context and result types ────────────────────────────────────────

/// Per-invocation context for `run_pipeline`.
///
/// Groups the parameters that vary per article ingestion event, keeping the
/// pipeline function signature under the clippy argument-count limit.
pub struct PipelineCtx<'a> {
    /// HLC timestamp to stamp the log entry with.
    pub timestamp: HlcTimestamp,
    /// Operator Ed25519 signing key. Log entry signatures are computed inside
    /// the pipeline after the article CID is known.
    pub operator_signing_key: Arc<SigningKey>,
    /// Local FQDN prepended to the `Path:` header (Son-of-RFC-1036 §3.3).
    pub local_hostname: &'a str,
    /// Verification store. `None` disables signature recording.
    pub verify_store: Option<&'a VerificationStore>,
    /// Trusted verifying keys for `X-Stoa-Sig` checks.
    pub trusted_keys: Arc<[ed25519_dalek::VerifyingKey]>,
    /// DKIM authenticator. `None` disables DKIM checks.
    pub dkim_auth: Option<&'a MessageAuthenticator>,
    /// Group filter. `None` accepts all groups (default-permit).
    pub group_filter: GroupPolicy,
}

/// Result of running the store-and-forward pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    /// CID of the stored article block.
    pub cid: Cid,
    /// Groups the article was appended to (successfully validated group names).
    pub groups: Vec<String>,
}

/// Counters produced by a single pipeline run.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub articles_ingested_total: u64,
    pub ipfs_write_latency_ms: u64,
}

// ── Verification helper ───────────────────────────────────────────────────────

/// Verify article signatures (best-effort; never blocks ingestion).
///
/// Runs X-Stoa-Sig verification against `trusted_keys` (pass an
/// empty slice to record `NoKey` when the header is present, or receive no
/// result when it is absent).  Runs DKIM verification when `dkim_auth` is
/// `Some`.  Records all results via `store`.  Any failure is logged and
/// silently dropped — verification is non-fatal.
pub async fn verify_article(
    article_bytes: &[u8],
    cid: &Cid,
    store: &VerificationStore,
    trusted_keys: &[ed25519_dalek::VerifyingKey],
    dkim_auth: Option<&MessageAuthenticator>,
) {
    use stoa_verify::dkim::verify_dkim_headers;
    use stoa_verify::x_sig::verify_x_sig;

    let x_sig_results = verify_x_sig(trusted_keys, article_bytes);
    let dkim_results = if let Some(auth) = dkim_auth {
        verify_dkim_headers(auth, article_bytes).await
    } else {
        vec![]
    };
    let all_verifications: Vec<_> = x_sig_results.into_iter().chain(dkim_results).collect();
    let verified_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    if let Err(e) = store
        .record_verifications(cid, &all_verifications, verified_at_ms)
        .await
    {
        tracing::warn!(cid = %cid, error = %e, "verification record failed");
    }
    let pass_count = all_verifications
        .iter()
        .filter(|v| v.result.is_pass())
        .count();
    tracing::info!(
        cid = %cid,
        checks = all_verifications.len(),
        passed = pass_count,
        "article verification complete"
    );
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Run the store-and-forward pipeline for a single article.
///
/// Steps:
/// 1. Write article bytes to IPFS → CID.
/// 2. Insert Message-ID → CID in `msgid_map`.
/// 3. Append a [`LogEntry`] to each group named in `Newsgroups:`.
///
/// Returns `Err` immediately if the IPFS write or articles table insert fails.
/// Log-append failures are logged as warnings but do not abort the pipeline.
pub async fn run_pipeline<I, S>(
    article_bytes: &[u8],
    ipfs: &I,
    msgid_map: &MsgIdMap,
    log_storage: &S,
    pool: &AnyPool,
    ctx: PipelineCtx<'_>,
) -> Result<(PipelineResult, PipelineMetrics), PipelineError>
where
    I: IpfsStore + ?Sized,
    S: LogStorage,
{
    use crate::peering::ingestion::prepend_path_header;

    // DECISION (rbe3.30): signature verification over pre-Path-prepend bytes
    //
    // The X-Stoa-Sig is computed by the originating peer over the article
    // as transmitted, before any transit hop prepends its hostname to Path:.
    // Verifying over the post-prepend bytes would produce systematic
    // false-negatives for every article that passes through a transit node —
    // the signature would never match.  Snapshot the original bytes BEFORE
    // calling prepend_path_header, then verify using those original bytes.
    // Do NOT move this snapshot below prepend_path_header.
    let original_bytes = article_bytes;

    // 0. Prepend local hostname to Path: header (Son-of-RFC-1036 §3.3).
    let article_bytes_owned = prepend_path_header(article_bytes.to_vec(), ctx.local_hostname);
    let article_bytes = article_bytes_owned.as_slice();

    // 1. Write to IPFS.
    let t0 = Instant::now();
    let cid = ipfs
        .put_raw(article_bytes)
        .await
        .map_err(|e| PipelineError::Transient(format!("IPFS write failed: {e}")))?;
    let elapsed = t0.elapsed();
    crate::metrics::IPFS_WRITE_LATENCY_SECONDS.observe(elapsed.as_secs_f64());
    let ipfs_write_latency_ms = elapsed.as_millis() as u64;

    // 1b. Verify article signatures against the original received bytes.
    //
    // DESIGN NOTE (rbe3.46): `cid` is the CID of the post-Path-modified bytes
    // (the block written to IPFS above).  Verification runs over
    // `original_bytes` (pre-Path-modification) because the originating peer
    // signed the article before this transit hop prepended its hostname.
    //
    // Consequence: the stored result "CID X is verified" cannot be reproduced
    // by fetching block X from IPFS and re-running verification — the block
    // contains the added Path hop that the signer never saw.  This is
    // intentional: X-Stoa-Sig is local provenance tracking only.  The CID
    // serves purely as a stable database key for the pre-computed result;
    // no code path re-derives verification status by re-fetching from IPFS.
    if let Some(store) = ctx.verify_store {
        verify_article(
            original_bytes,
            &cid,
            store,
            &ctx.trusted_keys,
            ctx.dkim_auth,
        )
        .await;
    }

    // 2+3. Parse Message-ID and Newsgroups in a single header scan.
    let (message_id, group_name_strs) = parse_message_id_and_newsgroups(article_bytes)
        .ok_or_else(|| PipelineError::Permanent("missing Message-ID header".to_string()))?;
    match msgid_map.insert(&message_id, &cid).await {
        Ok(()) => {}
        Err(e) => {
            // IPFS block was written but the DB insert failed.  Attempt to
            // delete the block immediately to prevent a permanent storage
            // leak — this block has no pinned_cids row so GC can never find it.
            match ipfs.delete(&cid).await {
                Ok(_) => {
                    tracing::warn!(
                        cid = %cid,
                        msgid = %message_id,
                        err = %e,
                        "msgid_map insert failed; deleted orphaned IPFS block"
                    );
                }
                Err(del_err) => {
                    tracing::error!(
                        cid = %cid,
                        msgid = %message_id,
                        insert_err = %e,
                        delete_err = %del_err,
                        "IPFS block orphaned: msgid_map insert failed and block delete also failed"
                    );
                }
            }
            return Err(PipelineError::Transient(format!(
                "msgid insert failed: {e}"
            )));
        }
    }

    // 3. Append a log entry to each valid group.
    // Each entry is a genesis entry (no parents) signed over canonical bytes:
    // hlc_timestamp (8 BE bytes) || article_cid bytes.
    let pubkey = ctx.operator_signing_key.verifying_key();

    // Pairs of (group_name, entry_id) for successful appends; entry_id is used
    // in tip advertisements so that peers can reconcile via LogEntryId, not
    // the raw article CID.
    let mut appended_groups: Vec<(String, stoa_core::group_log::LogEntryId)> = Vec::new();
    for group_name_str in &group_name_strs {
        let group = match GroupName::new(group_name_str.clone()) {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!("invalid group name in Newsgroups: {group_name_str:?}");
                crate::metrics::ARTICLES_REJECTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str.as_str(), "invalid_group_name"])
                    .inc();
                continue;
            }
        };
        if let Some(ref filter) = ctx.group_filter {
            if !filter.accepts(group_name_str) {
                tracing::debug!(group = %group_name_str, "skipped by group filter");
                continue;
            }
        }
        // Use the current tips as parent CIDs to maintain the Merkle-CRDT
        // parent chain.  Every ingested article links back to the node's
        // current local tips so the DAG is connected, not a forest of
        // isolated genesis entries.
        let tip_ids = match log_storage.list_tips(&group).await {
            Ok(tips) => tips,
            Err(e) => {
                tracing::warn!("list_tips failed for {group_name_str}: {e}");
                crate::metrics::ARTICLES_REJECTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str.as_str(), "log_tip_error"])
                    .inc();
                continue;
            }
        };
        let parent_cids: Vec<Cid> = tip_ids.iter().map(|id| id.to_cid()).collect();
        let canonical = log_entry_canonical_bytes(ctx.timestamp.wall_ms, &cid, &parent_cids);
        let sig = sign(&ctx.operator_signing_key, &canonical);
        let entry = LogEntry {
            hlc_timestamp: ctx.timestamp,
            article_cid: cid,
            operator_signature: sig.to_bytes().to_vec(),
            parent_cids,
        };
        let verified = match verify_signature(entry, &pubkey) {
            Ok(v) => v,
            Err(e) => {
                // Self-check failure is a programming error (wrong key or
                // canonical bytes bug) — abort the article rather than
                // silently skipping groups.
                crate::metrics::ARTICLES_REJECTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str.as_str(), "signature_error"])
                    .inc();
                return Err(PipelineError::Permanent(format!(
                    "log entry signature self-check failed for {group_name_str}: {e}"
                )));
            }
        };
        match crdt_append(log_storage, &group, verified).await {
            Err(e) => {
                tracing::warn!("log append failed for group {group_name_str}: {e}");
                crate::metrics::ARTICLES_REJECTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str.as_str(), "log_append_error"])
                    .inc();
            }
            Ok(entry_id) => {
                crate::metrics::ARTICLES_INGESTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str])
                    .inc();
                appended_groups.push((group_name_str.clone(), entry_id));
            }
        }
    }

    // 3.5. Record in articles table for GC tracking.
    //
    // DECISION (rbe3.32): hard error on articles table insert failure
    //
    // If the IPFS write, msgid_map, and group log all succeed but the articles
    // table insert fails, the block exists in IPFS but is invisible to
    // select_gc_candidates — it will never be collected (orphaned block leak).
    // Unlike log-append failures (which are logged and skipped), this is
    // treated as a pipeline error.  The articles table is the GC ledger; its
    // integrity is non-negotiable.
    //
    // DECISION (rbe3.31): ingested_at_ms from local wall clock, not peer time
    //
    // `ingested_at_ms` MUST be the current wall-clock time (SystemTime::now()),
    // NOT from the article's Date header or ctx.timestamp — those are
    // peer-supplied.  A backdated article (Date: 2001-01-01) would cause the
    // GC grace period to have already expired, allowing the collector to
    // immediately evict an article that was just ingested.  Using the local
    // wall clock ensures that all newly ingested articles are protected for the
    // full grace period regardless of the article timestamp.
    {
        let cid_str = cid.to_string();
        // Store all newsgroups comma-separated so the GC policy can evaluate
        // each group independently (ArticleMeta::group splits on commas).
        // DO UPDATE so a later arrival with additional cross-post groups
        // replaces the stored list rather than silently keeping the first.
        let all_groups = group_name_strs.join(",");
        let ingested_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let byte_count = article_bytes.len() as i64;
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (cid) DO UPDATE SET group_name = excluded.group_name",
        )
        .bind(&cid_str)
        .bind(&all_groups)
        .bind(ingested_at_ms)
        .bind(byte_count)
        .execute(pool)
        .await
        .map_err(|e| {
            PipelineError::Transient(format!(
                "articles table insert failed for CID {cid_str}: {e}"
            ))
        })?;
    }

    let group_names: Vec<String> = appended_groups.into_iter().map(|(name, _)| name).collect();

    Ok((
        PipelineResult {
            cid,
            groups: group_names,
        },
        PipelineMetrics {
            articles_ingested_total: 1,
            ipfs_write_latency_ms,
        },
    ))
}

// ── Header extraction helpers ─────────────────────────────────────────────────

/// Extract the value of a header field from raw article bytes.
///
/// Scans the header section (lines before the first blank line) for
/// `name:` (case-insensitive). Returns the trimmed value, or `None` if
/// not found or the bytes are not valid UTF-8 on that line.
#[cfg(test)]
fn extract_header<'a>(article_bytes: &'a [u8], name: &str) -> Option<&'a str> {
    let needle = format!("{}:", name);

    for line in article_bytes.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }
        let s = std::str::from_utf8(trimmed).ok()?;
        if s.len() >= needle.len() && s[..needle.len()].eq_ignore_ascii_case(&needle) {
            return Some(s[needle.len()..].trim());
        }
    }
    None
}

/// Extract `Message-ID` and `Newsgroups` from article bytes in a single pass.
///
/// Returns `None` if `Message-ID` is absent. `Newsgroups` defaults to an
/// empty list when the header is missing.
///
/// Handles RFC 5322 §2.2.3 header folding: continuation lines that begin
/// with SP or HTAB are appended to the current header value.
fn parse_message_id_and_newsgroups(article_bytes: &[u8]) -> Option<(String, Vec<String>)> {
    let mut message_id: Option<String> = None;
    let mut newsgroups_val: Option<String> = None;

    // Which header is currently being accumulated: 0 = none, 1 = Message-ID,
    // 2 = Newsgroups.
    let mut current: u8 = 0;

    for line in article_bytes.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }

        // RFC 5322 §2.2.3: a line beginning with SP or HTAB is a continuation
        // of the previous header field value.
        if trimmed.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            let Ok(cont) = std::str::from_utf8(trimmed) else {
                current = 0;
                continue;
            };
            match current {
                1 => {
                    if let Some(ref mut v) = message_id {
                        v.push_str(cont.trim());
                    }
                }
                2 => {
                    if let Some(ref mut v) = newsgroups_val {
                        v.push(',');
                        v.push_str(cont.trim());
                    }
                }
                _ => {}
            }
            continue;
        }

        // Not a continuation line — check early-exit before resetting.
        // Only break when both fields are fully accumulated (current == 0 means
        // the previous header needed no further continuation lines, or we just
        // finished one). This prevents breaking after seeing `Message-ID:\r\n`
        // (empty value on the name line) before the folded continuation is read.
        if current == 0 && message_id.is_some() && newsgroups_val.is_some() {
            break;
        }
        current = 0;

        let s = match std::str::from_utf8(trimmed) {
            Ok(s) => s,
            Err(_) => continue,
        };
        const MID: &str = "message-id:";
        const NG: &str = "newsgroups:";
        if message_id.is_none() && s.len() >= MID.len() && s[..MID.len()].eq_ignore_ascii_case(MID)
        {
            message_id = Some(s[MID.len()..].trim().to_owned());
            current = 1;
        } else if newsgroups_val.is_none()
            && s.len() >= NG.len()
            && s[..NG.len()].eq_ignore_ascii_case(NG)
        {
            newsgroups_val = Some(s[NG.len()..].trim().to_owned());
            current = 2;
        }
    }

    let mid = message_id?;
    let groups = newsgroups_val
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    Some((mid, groups))
}

#[cfg(test)]
// Parse the `Newsgroups:` header into a list of group name strings.
fn parse_newsgroups(article_bytes: &[u8]) -> Vec<String> {
    let value = match extract_header(article_bytes, "Newsgroups") {
        Some(v) => v,
        None => return vec![],
    };
    value
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
// Extract the `Message-ID:` value from article bytes.
fn extract_message_id(article_bytes: &[u8]) -> Option<String> {
    extract_header(article_bytes, "Message-ID").map(|s| s.to_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use stoa_core::wildmat::GroupFilter;

    async fn make_transit_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (MsgIdMap::new(pool), tmp)
    }

    fn make_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn make_timestamp() -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 0,
            node_id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    fn make_ctx(key: Arc<SigningKey>, ts: HlcTimestamp) -> PipelineCtx<'static> {
        PipelineCtx {
            timestamp: ts,
            operator_signing_key: key,
            local_hostname: "local.test.example.com",
            verify_store: None,
            trusted_keys: Arc::from(vec![]),
            dkim_auth: None,
            group_filter: None,
        }
    }

    fn make_article(msgid: &str, newsgroups: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: {newsgroups}\r\n\
             Subject: Test Article\r\n\
             \r\n\
             This is the body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn pipeline_success_records_cid() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<test@example.com>", "comp.lang.rust");
        let (transit_pool, _transit_tmp) = make_transit_pool().await;

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(Arc::new(key), make_timestamp()),
        )
        .await;

        assert!(result.is_ok(), "pipeline should succeed: {result:?}");
        let (pr, _metrics) = result.unwrap();
        assert_eq!(pr.groups, vec!["comp.lang.rust"]);

        // CID must be recorded in msgid_map.
        let cid = msgid_map
            .lookup_by_msgid("<test@example.com>")
            .await
            .unwrap();
        assert!(cid.is_some(), "CID must be recorded in msgid_map");
        assert_eq!(cid.unwrap(), pr.cid);
    }

    #[tokio::test]
    async fn pipeline_records_article_in_articles_table() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<articles-table@example.com>", "alt.test");
        let (transit_pool, _transit_tmp) = make_transit_pool().await;

        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let (pr, _metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(Arc::new(key), make_timestamp()),
        )
        .await
        .unwrap();

        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT cid, group_name, ingested_at_ms, byte_count FROM articles WHERE cid = ?",
        )
        .bind(pr.cid.to_string())
        .fetch_optional(&transit_pool)
        .await
        .unwrap();

        let (cid_str, group_name, ingested_at_ms, byte_count) =
            row.expect("articles table must contain the ingested article");

        // byte_count reflects the bytes written to IPFS — after prepend_path_header
        // is applied. Compute the expected size independently.
        let expected_bytes = crate::peering::ingestion::prepend_path_header(
            article.clone(),
            "local.test.example.com",
        );
        assert_eq!(cid_str, pr.cid.to_string());
        assert_eq!(group_name, "alt.test");
        assert!(
            ingested_at_ms >= before_ms && ingested_at_ms <= after_ms,
            "ingested_at_ms {ingested_at_ms} must be within [{before_ms}, {after_ms}]"
        );
        assert_eq!(byte_count as usize, expected_bytes.len());
    }

    #[test]
    fn parse_newsgroups_single() {
        let article = b"Newsgroups: comp.lang.rust\r\n\r\n";
        assert_eq!(parse_newsgroups(article), vec!["comp.lang.rust"]);
    }

    #[test]
    fn parse_newsgroups_multiple() {
        let article = b"Newsgroups: comp.lang.rust,sci.math\r\n\r\n";
        let groups = parse_newsgroups(article);
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"comp.lang.rust".to_string()));
        assert!(groups.contains(&"sci.math".to_string()));
    }

    #[test]
    fn extract_message_id_found() {
        let article = b"Message-ID: <abc@example.com>\r\n\r\n";
        assert_eq!(
            extract_message_id(article),
            Some("<abc@example.com>".to_string())
        );
    }

    #[tokio::test]
    async fn pipeline_missing_message_id_returns_err() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        // Article with no Message-ID header.
        let article = b"From: x@example.com\r\nNewsgroups: alt.test\r\n\r\nBody.\r\n";

        let result = run_pipeline(
            article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(Arc::new(key), make_timestamp()),
        )
        .await;
        assert!(result.is_err(), "missing Message-ID must return Err");
        assert!(
            matches!(result.unwrap_err(), PipelineError::Permanent(_)),
            "missing Message-ID must be a permanent (not transient) failure"
        );
    }

    #[tokio::test]
    async fn pipeline_metrics_latency_set() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<metrics@example.com>", "alt.test");
        let (transit_pool, _transit_tmp) = make_transit_pool().await;

        let (_pr, metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(Arc::new(key), make_timestamp()),
        )
        .await
        .unwrap();
        assert_eq!(metrics.articles_ingested_total, 1);
        // Latency is in ms; MemIpfsStore is effectively instant so it should be very low.
        assert!(
            metrics.ipfs_write_latency_ms < 1000,
            "latency should be sub-second"
        );
    }

    /// Son-of-RFC-1036 §3.3: the pipeline must prepend the local hostname to
    /// the `Path:` header in the bytes written to IPFS.
    #[tokio::test]
    async fn pipeline_prepends_local_hostname_to_path_header() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;

        // Article with an existing Path: from a peer.
        let article = format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: <path-test@example.com>\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Path Test\r\n\
             Path: peer.example.com\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes();

        let (pr, _metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(Arc::new(key), make_timestamp()),
        )
        .await
        .unwrap();

        // Retrieve the stored bytes from MemIpfsStore to verify Path: was patched.
        let stored = ipfs
            .blocks
            .read()
            .unwrap()
            .get(&pr.cid.to_string())
            .cloned()
            .expect("block must be stored in MemIpfsStore");

        let stored_text = String::from_utf8(stored).expect("stored bytes must be valid UTF-8");
        assert!(
            stored_text.contains("Path: local.test.example.com!peer.example.com\r\n"),
            "stored article must have local hostname prepended to Path: header: {stored_text:?}"
        );
        assert!(
            !stored_text.contains("Path: peer.example.com\r\n"),
            "old standalone Path: must not remain in stored article: {stored_text:?}"
        );
    }

    /// Create a temp-file SQLite AnyPool with verify-crate migrations applied.
    async fn make_verify_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_verify::run_migrations(&url)
            .await
            .expect("verify migrations must succeed");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("verify pool must open");
        (pool, tmp)
    }

    /// Append `X-Stoa-Sig` to article headers, signed with `key`.
    ///
    /// Replicates the signing convention from the verify crate's x_sig tests:
    /// the signature is computed over the article bytes (without the sig header),
    /// then the header is inserted just before the blank separator line.
    fn sign_article_bytes(key: &SigningKey, article_bytes: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;

        let sig: ed25519_dalek::Signature = key.sign(article_bytes);
        let sig_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let sig_line = format!("X-Stoa-Sig: {sig_value}\r\n");

        // Find the blank line separating headers from body (\r\n\r\n).
        let body_start = article_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| {
                article_bytes
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|p| p + 2)
            })
            .unwrap_or(article_bytes.len());

        let sep_len =
            if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                2
            } else {
                1
            };
        let insert_at = body_start - sep_len;

        let mut out = Vec::with_capacity(article_bytes.len() + sig_line.len());
        out.extend_from_slice(&article_bytes[..insert_at]);
        out.extend_from_slice(sig_line.as_bytes());
        out.extend_from_slice(&article_bytes[insert_at..]);
        out
    }

    /// An article with a valid `X-Stoa-Sig` header → pipeline must record
    /// an `article_verifications` row with `result = 'pass'`.
    #[tokio::test]
    async fn pipeline_verify_x_sig_records_pass_row() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let (verify_pool, _verify_tmp) = make_verify_pool().await;

        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();

        // Build an unsigned article, then sign it with the known key.
        let unsigned = make_article("<sig-test@example.com>", "alt.test");
        let signed = sign_article_bytes(&signing_key, &unsigned);

        let verify_store = stoa_verify::VerificationStore::new(verify_pool.clone());

        let ctx = PipelineCtx {
            timestamp: make_timestamp(),
            operator_signing_key: Arc::new(signing_key),
            local_hostname: "local.test.example.com",
            verify_store: Some(&verify_store),
            trusted_keys: Arc::from(vec![verifying_key]),
            dkim_auth: None,
            group_filter: None,
        };
        let (pr, _metrics) = run_pipeline(&signed, &ipfs, &msgid_map, &storage, &transit_pool, ctx)
            .await
            .expect("pipeline must succeed with signed article");

        // Verify that the article_verifications table contains a pass row.
        let rows: Vec<(Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT cid, sig_type, result FROM article_verifications WHERE result = 'pass'",
        )
        .fetch_all(&verify_pool)
        .await
        .expect("article_verifications query must succeed");

        assert!(
            !rows.is_empty(),
            "article_verifications must contain at least one pass row after pipeline run"
        );
        let cid_bytes = pr.cid.to_bytes();
        let pass_row = rows.iter().find(|(cid, _, _)| *cid == cid_bytes);
        assert!(
            pass_row.is_some(),
            "pass row must be for the ingested article CID {}; rows: {rows:?}",
            pr.cid
        );
        let (_, sig_type, result) = pass_row.unwrap();
        assert_eq!(sig_type, "x-stoa-sig");
        assert_eq!(result, "pass");
    }

    fn make_ctx_with_filter(
        key: Arc<SigningKey>,
        ts: HlcTimestamp,
        filter: GroupPolicy,
    ) -> PipelineCtx<'static> {
        PipelineCtx {
            timestamp: ts,
            operator_signing_key: key,
            local_hostname: "local.test.example.com",
            verify_store: None,
            trusted_keys: Arc::from(vec![]),
            dkim_auth: None,
            group_filter: filter,
        }
    }

    #[tokio::test]
    async fn group_filter_accepts_matching_group() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-accept@example.com>", "comp.lang.rust");
        let filter = Arc::new(GroupFilter::new(&["comp.*"]).expect("valid filter"));

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx_with_filter(key, make_timestamp(), Some(filter)),
        )
        .await;

        assert!(result.is_ok(), "pipeline must succeed: {result:?}");
        let (pr, _metrics) = result.unwrap();
        assert!(
            pr.groups.contains(&"comp.lang.rust".to_string()),
            "comp.lang.rust must be in groups: {:?}",
            pr.groups
        );
    }

    #[tokio::test]
    async fn group_filter_rejects_non_matching_group() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-reject@example.com>", "alt.test");
        let filter = Arc::new(GroupFilter::new(&["comp.*"]).expect("valid filter"));

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx_with_filter(key, make_timestamp(), Some(filter)),
        )
        .await;

        // Article is stored in IPFS (Ok), but no log entry for alt.test.
        assert!(
            result.is_ok(),
            "pipeline must succeed even when group is filtered: {result:?}"
        );
        let (pr, _metrics) = result.unwrap();
        assert!(
            !pr.groups.contains(&"alt.test".to_string()),
            "alt.test must NOT be in groups when filtered out: {:?}",
            pr.groups
        );
    }

    #[tokio::test]
    async fn group_filter_negation_excludes() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-neg-excl@example.com>", "alt.binaries.pictures");
        let filter = Arc::new(
            GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"])
                .expect("valid filter"),
        );

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx_with_filter(key, make_timestamp(), Some(filter)),
        )
        .await;

        assert!(result.is_ok(), "pipeline must succeed: {result:?}");
        let (pr, _metrics) = result.unwrap();
        assert!(
            !pr.groups.contains(&"alt.binaries.pictures".to_string()),
            "alt.binaries.pictures must NOT be in groups due to negation: {:?}",
            pr.groups
        );
    }

    #[tokio::test]
    async fn group_filter_negation_accepts_exact() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-neg-accept@example.com>", "alt.test");
        let filter = Arc::new(
            GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"])
                .expect("valid filter"),
        );

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx_with_filter(key, make_timestamp(), Some(filter)),
        )
        .await;

        assert!(result.is_ok(), "pipeline must succeed: {result:?}");
        let (pr, _metrics) = result.unwrap();
        assert!(
            pr.groups.contains(&"alt.test".to_string()),
            "alt.test must be in groups (explicit positive match): {:?}",
            pr.groups
        );
    }

    #[tokio::test]
    async fn group_filter_no_filter_accepts_all() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-no-filter@example.com>", "alt.test");

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(key, make_timestamp()),
        )
        .await;

        assert!(
            result.is_ok(),
            "pipeline must succeed with no filter: {result:?}"
        );
        let (pr, _metrics) = result.unwrap();
        assert!(
            pr.groups.contains(&"alt.test".to_string()),
            "alt.test must be accepted when group_filter is None: {:?}",
            pr.groups
        );
    }

    #[tokio::test]
    async fn group_filter_crosspost_partial_match() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let key = Arc::new(make_signing_key());
        let article = make_article("<gf-crosspost@example.com>", "comp.lang.rust,alt.test");
        let filter = Arc::new(GroupFilter::new(&["comp.*"]).expect("valid filter"));

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx_with_filter(key, make_timestamp(), Some(filter)),
        )
        .await;

        assert!(
            result.is_ok(),
            "pipeline must succeed for crosspost: {result:?}"
        );
        let (pr, _metrics) = result.unwrap();
        assert!(
            pr.groups.contains(&"comp.lang.rust".to_string()),
            "comp.lang.rust must be in groups: {:?}",
            pr.groups
        );
        assert!(
            !pr.groups.contains(&"alt.test".to_string()),
            "alt.test must NOT be in groups when filtered out: {:?}",
            pr.groups
        );
    }

    /// Build an [`Article`] struct suitable for passing to
    /// [`validate_article_ingress`].  All mandatory RFC 5536 headers are
    /// populated with valid placeholder values; only `newsgroups` and
    /// `message_id` vary per test case.
    fn make_article_struct(msgid: &str, newsgroup: &str) -> stoa_core::article::Article {
        use stoa_core::article::{Article, ArticleHeader, GroupName};
        Article {
            header: ArticleHeader {
                from: "sender@example.com".into(),
                date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
                message_id: msgid.into(),
                newsgroups: vec![GroupName::new(newsgroup).expect("valid group name")],
                subject: "Test Article".into(),
                path: "local.test.example.com!not-for-mail".into(),
                extra_headers: vec![],
            },
            body: b"This is the body.\r\n".to_vec(),
        }
    }

    /// End-to-end acceptance-criteria test for wildmat group filtering.
    ///
    /// Oracle: epic acceptance criteria (stoa bead usenet-ipfs-whss.8).
    /// Filter: ["comp.*", "sci.*", "!alt.binaries.*", "alt.test"]
    ///
    /// Article A  comp.lang.rust       → accepted  (comp.* matches)
    /// Article B  sci.math             → accepted  (sci.* matches)
    /// Article C  alt.binaries.pictures → rejected  (!alt.binaries.* negation)
    /// Article D  alt.test             → accepted  (exact match)
    /// Article E  rec.humor            → rejected  (no pattern matches)
    #[tokio::test]
    async fn e2e_wildmat_group_filter_acceptance_criteria() {
        use stoa_core::validation::{validate_article_ingress, ValidationConfig};

        let patterns = ["comp.*", "sci.*", "!alt.binaries.*", "alt.test"];
        let filter = Arc::new(GroupFilter::new(&patterns).expect("valid filter"));

        let val_config = ValidationConfig {
            max_article_bytes: 1024 * 1024,
            allowed_groups: Some(Arc::clone(&filter)),
        };

        let (transit_pool, _transit_tmp) = make_transit_pool().await;
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = stoa_core::group_log::MemLogStorage::new();
        let key = Arc::new(make_signing_key());

        // ── Article A: comp.lang.rust → accepted ─────────────────────────────
        {
            let article_struct = make_article_struct("<a@e2e.test>", "comp.lang.rust");
            let result = validate_article_ingress(&article_struct, &val_config);
            assert!(
                result.is_ok(),
                "Article A (comp.lang.rust) must pass validation: {result:?}"
            );

            let ipfs = MemIpfsStore::new();
            let article_bytes = make_article("<a@e2e.test>", "comp.lang.rust");
            let (pr, _metrics) = run_pipeline(
                &article_bytes,
                &ipfs,
                &msgid_map,
                &storage,
                &transit_pool,
                make_ctx_with_filter(
                    Arc::clone(&key),
                    make_timestamp(),
                    Some(Arc::clone(&filter)),
                ),
            )
            .await
            .expect("Article A pipeline must succeed");
            assert!(
                pr.groups.contains(&"comp.lang.rust".to_string()),
                "Article A: comp.lang.rust must be in groups: {:?}",
                pr.groups
            );
        }

        // ── Article B: sci.math → accepted ───────────────────────────────────
        {
            let article_struct = make_article_struct("<b@e2e.test>", "sci.math");
            let result = validate_article_ingress(&article_struct, &val_config);
            assert!(
                result.is_ok(),
                "Article B (sci.math) must pass validation: {result:?}"
            );

            let ipfs = MemIpfsStore::new();
            let article_bytes = make_article("<b@e2e.test>", "sci.math");
            let (pr, _metrics) = run_pipeline(
                &article_bytes,
                &ipfs,
                &msgid_map,
                &storage,
                &transit_pool,
                make_ctx_with_filter(
                    Arc::clone(&key),
                    make_timestamp(),
                    Some(Arc::clone(&filter)),
                ),
            )
            .await
            .expect("Article B pipeline must succeed");
            assert!(
                pr.groups.contains(&"sci.math".to_string()),
                "Article B: sci.math must be in groups: {:?}",
                pr.groups
            );
        }

        // ── Article C: alt.binaries.pictures → rejected (!alt.binaries.*) ────
        {
            let article_struct = make_article_struct("<c@e2e.test>", "alt.binaries.pictures");
            let result = validate_article_ingress(&article_struct, &val_config);
            assert!(
                result.is_err(),
                "Article C (alt.binaries.pictures) must be rejected by validate_article_ingress"
            );
        }

        // ── Article D: alt.test → accepted (exact match) ─────────────────────
        {
            let article_struct = make_article_struct("<d@e2e.test>", "alt.test");
            let result = validate_article_ingress(&article_struct, &val_config);
            assert!(
                result.is_ok(),
                "Article D (alt.test) must pass validation: {result:?}"
            );

            let ipfs = MemIpfsStore::new();
            let article_bytes = make_article("<d@e2e.test>", "alt.test");
            let (pr, _metrics) = run_pipeline(
                &article_bytes,
                &ipfs,
                &msgid_map,
                &storage,
                &transit_pool,
                make_ctx_with_filter(
                    Arc::clone(&key),
                    make_timestamp(),
                    Some(Arc::clone(&filter)),
                ),
            )
            .await
            .expect("Article D pipeline must succeed");
            assert!(
                pr.groups.contains(&"alt.test".to_string()),
                "Article D: alt.test must be in groups: {:?}",
                pr.groups
            );
        }

        // ── Article E: rec.humor → rejected (no pattern matches) ─────────────
        {
            let article_struct = make_article_struct("<e@e2e.test>", "rec.humor");
            let result = validate_article_ingress(&article_struct, &val_config);
            assert!(
                result.is_err(),
                "Article E (rec.humor) must be rejected by validate_article_ingress"
            );
        }
    }
}
