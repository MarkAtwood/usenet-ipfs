//! IPFS block write abstraction and CID recording for the POST pipeline.
//!
//! `IpfsBlockStore` abstracts raw block storage so that tests can use an
//! in-memory implementation (`MemIpfsStore`) without a running Kubo node.
//! The production implementation is [`KuboBlockStore`].

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::session::response::Response;
use stoa_core::{ipld::builder::build_article, msgid_map::MsgIdMap};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during IPFS block operations.
#[derive(Debug)]
pub enum IpfsWriteError {
    NotReachable(String),
    WriteFailed(String),
    ReadFailed(String),
    NotFound(String),
}

impl std::fmt::Display for IpfsWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsWriteError::NotReachable(msg) => write!(f, "IPFS node not reachable: {msg}"),
            IpfsWriteError::WriteFailed(msg) => write!(f, "IPFS write failed: {msg}"),
            IpfsWriteError::ReadFailed(msg) => write!(f, "IPFS read failed: {msg}"),
            IpfsWriteError::NotFound(msg) => write!(f, "IPFS block not found: {msg}"),
        }
    }
}

impl std::error::Error for IpfsWriteError {}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over IPFS raw block storage.
///
/// In production: backed by a Kubo daemon via [`KuboBlockStore`]. In tests: backed by [`MemIpfsStore`].
#[async_trait]
pub trait IpfsBlockStore: Send + Sync {
    /// Write a raw block to IPFS. Returns the CID of the stored block.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError>;

    /// Store a block with a pre-computed CID (e.g. DAG-CBOR blocks from
    /// `build_article`).  The caller is responsible for ensuring `cid` matches
    /// the content of `data`.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError>;

    /// Read a raw block from IPFS by CID. Returns the block bytes.
    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError>;

    /// Mark `cid` for deletion.
    ///
    /// The default implementation signals that deletion is deferred — callers
    /// must not assume the block is gone until `get_raw` returns `NotFound`.
    /// Override to provide backend-specific behaviour.
    async fn delete(&self, _cid: &Cid) -> Result<stoa_core::ipfs::DeletionOutcome, IpfsWriteError> {
        Ok(stoa_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

/// In-memory IPFS block store for use in unit tests.
///
/// Computes CIDv1 RAW SHA2-256 on `put_raw`, stores the block keyed by
/// the CID's raw bytes, and returns the same bytes on `get_raw`.
pub struct MemIpfsStore {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemIpfsStore {
    pub fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemIpfsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpfsBlockStore for MemIpfsStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.blocks.write().await.insert(cid.to_bytes(), data);
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.blocks
            .read()
            .await
            .get(&cid.to_bytes())
            .cloned()
            .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Production Kubo implementation
// ---------------------------------------------------------------------------

/// IPFS block store backed by a Kubo daemon via its HTTP RPC API.
///
/// Optionally wraps a local filesystem cache: blocks are read from disk on
/// cache hits and written through to both disk and Kubo on puts. The cache
/// directory holds one file per CID (named by the CID's string representation).
/// No LRU eviction is performed; disk management is the operator's responsibility.
///
/// The Kubo client is wrapped in a circuit breaker with default thresholds
/// (5 failures in 10 s → open; probe after 30 s).  When the circuit is open,
/// `block_put` / `block_get` return errors immediately without an HTTP call.
pub struct KuboBlockStore {
    client: stoa_core::ipfs::CircuitBreakerKuboClient,
    cache_dir: Option<std::path::PathBuf>,
}

impl KuboBlockStore {
    /// Create a store targeting the Kubo daemon at `api_url`.
    ///
    /// If `cache_dir` is `Some`, blocks are cached in that directory.
    /// The directory must already exist.
    pub fn new(api_url: &str, cache_dir: Option<std::path::PathBuf>) -> Self {
        Self {
            client: stoa_core::ipfs::CircuitBreakerKuboClient::new(
                api_url,
                stoa_core::circuit_breaker::CircuitBreakerConfig::default(),
            ),
            cache_dir,
        }
    }

    fn cache_path(&self, cid: &Cid) -> Option<std::path::PathBuf> {
        self.cache_dir.as_ref().map(|dir| dir.join(cid.to_string()))
    }

    async fn cache_get(&self, cid: &Cid) -> Option<Vec<u8>> {
        let path = self.cache_path(cid)?;
        tokio::fs::read(&path).await.ok()
    }

    async fn cache_put(&self, cid: &Cid, bytes: &[u8]) {
        if let Some(path) = self.cache_path(cid) {
            if let Err(e) = tokio::fs::write(&path, bytes).await {
                tracing::warn!(cid = %cid, "block cache write failed: {e}");
            }
        }
    }
}

#[async_trait]
impl IpfsBlockStore for KuboBlockStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let cid = self
            .client
            .block_put(data, 0x55)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        self.cache_put(&cid, data).await;
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        let returned_cid = self
            .client
            .block_put(&data, cid.codec())
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        if returned_cid != cid {
            return Err(IpfsWriteError::WriteFailed(format!(
                "CID mismatch: Kubo returned {returned_cid} but expected {cid}"
            )));
        }
        self.cache_put(&cid, &data).await;
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        if let Some(bytes) = self.cache_get(cid).await {
            return Ok(bytes);
        }
        match self
            .client
            .block_get(cid)
            .await
            .map_err(|e| IpfsWriteError::NotReachable(e.to_string()))?
        {
            Some(bytes) => {
                self.cache_put(cid, &bytes).await;
                Ok(bytes)
            }
            None => Err(IpfsWriteError::NotFound(cid.to_string())),
        }
    }

    /// Unpin `cid` from Kubo. The block remains readable until `ipfs repo gc` runs.
    async fn delete(&self, cid: &Cid) -> Result<stoa_core::ipfs::DeletionOutcome, IpfsWriteError> {
        self.client
            .pin_rm(cid)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(stoa_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Store factory
// ---------------------------------------------------------------------------

/// Construct the IPFS block store from configuration.
///
/// Prefers `config.backend` when present; falls back to the legacy `config.ipfs`
/// section for backward compatibility.
///
/// Returns `Err` for backends that are not yet implemented.
pub async fn build_block_store(
    config: &crate::config::Config,
) -> Result<std::sync::Arc<dyn IpfsBlockStore>, String> {
    use std::sync::Arc;
    if let Some(backend) = &config.backend {
        use crate::config::BackendType;
        match backend.backend_type {
            BackendType::Kubo => {
                let kubo_cfg = backend
                    .kubo
                    .as_ref()
                    .ok_or("backend.type = 'kubo' requires a [backend.kubo] section")?;
                let cache_dir = kubo_cfg.cache_path.as_ref().map(std::path::PathBuf::from);
                Ok(Arc::new(KuboBlockStore::new(&kubo_cfg.api_url, cache_dir)))
            }
            BackendType::Lmdb => {
                let lmdb_cfg = backend
                    .lmdb
                    .as_ref()
                    .ok_or("backend.type = 'lmdb' requires a [backend.lmdb] section")?;
                let store = super::lmdb_store::LmdbBlockStore::open(
                    std::path::Path::new(&lmdb_cfg.path),
                    lmdb_cfg.map_size_gb,
                )
                .map_err(|e| format!("LMDB store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::S3 => {
                let s3_cfg = backend
                    .s3
                    .as_ref()
                    .ok_or("backend.type = 's3' requires a [backend.s3] section")?;
                let store = super::s3_store::S3BlockStore::new(s3_cfg)
                    .await
                    .map_err(|e| format!("S3 store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::Azure => {
                let azure_cfg = backend
                    .azure
                    .as_ref()
                    .ok_or("backend.type = 'azure' requires a [backend.azure] section")?;
                let store = super::azure_store::AzureBlockStore::new(azure_cfg)
                    .await
                    .map_err(|e| format!("Azure store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::Gcs => {
                let gcs_cfg = backend
                    .gcs
                    .as_ref()
                    .ok_or("backend.type = 'gcs' requires a [backend.gcs] section")?;
                let store = super::gcs_store::GcsBlockStore::new(gcs_cfg)
                    .await
                    .map_err(|e| format!("GCS store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::Sqlite => {
                let sqlite_cfg = backend
                    .sqlite
                    .as_ref()
                    .ok_or("backend.type = 'sqlite' requires a [backend.sqlite] section")?;
                let store = super::sqlite_store::SqliteBlockStore::open(std::path::Path::new(
                    &sqlite_cfg.path,
                ))
                .await
                .map_err(|e| format!("sqlite store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::Filesystem => {
                let fs_cfg = backend
                    .filesystem
                    .as_ref()
                    .ok_or("backend.type = 'filesystem' requires a [backend.filesystem] section")?;
                let store = super::fs_store::FsBlockStore::open(
                    std::path::Path::new(&fs_cfg.path),
                    fs_cfg.max_bytes,
                )
                .map_err(|e| format!("filesystem store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::WebDav => {
                let webdav_cfg = backend
                    .webdav
                    .as_ref()
                    .ok_or("backend.type = 'web_dav' requires a [backend.webdav] section")?;
                let store = super::webdav_store::WebDavBlockStore::new(webdav_cfg)
                    .await
                    .map_err(|e| format!("WebDAV store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::RocksDb => {
                let rocks_cfg = backend
                    .rocksdb
                    .as_ref()
                    .ok_or("backend.type = 'rocks_db' requires a [backend.rocksdb] section")?;
                let store = super::rocks_store::RocksBlockStore::open(
                    std::path::Path::new(&rocks_cfg.path),
                    rocks_cfg.cache_size_mb,
                )
                .map_err(|e| format!("RocksDB store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::PgBlob => {
                let pg_cfg = backend
                    .pg_blob
                    .as_ref()
                    .ok_or("backend.type = 'pg_blob' requires a [backend.pg_blob] section")?;
                let store = super::pg_store::PgBlockStore::new(pg_cfg)
                    .await
                    .map_err(|e| format!("pg block store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::GitSha256 => {
                let git_cfg = backend
                    .git_sha256
                    .as_ref()
                    .ok_or("backend.type = 'git_sha256' requires a [backend.git_sha256] section")?;
                let store = super::git_store::GitObjectBlockStore::new(git_cfg)
                    .await
                    .map_err(|e| format!("git block store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::Rados => Err("backend.type = 'rados' is not supported in stoa-reader; \
                 use the S3 backend pointed at RADOS Gateway instead"
                .into()),
        }
    } else {
        // Backward-compat: use legacy [ipfs] section.
        let cache_dir = config
            .ipfs
            .cache_path
            .as_ref()
            .map(std::path::PathBuf::from);
        Ok(Arc::new(KuboBlockStore::new(
            &config.ipfs.api_url,
            cache_dir,
        )))
    }
}

// ---------------------------------------------------------------------------
// Pipeline functions
// ---------------------------------------------------------------------------

/// Write a signed article to IPFS and record the Message-ID → CID mapping.
///
/// Steps:
/// 1. Check `msgid_map` for `message_id` — return `Err(441)` if already known
///    (duplicate). This gate prevents concurrent ingestion from writing orphaned
///    IPFS blocks when `msgid_map.insert` would hit ON CONFLICT DO NOTHING.
/// 2. Write block to IPFS via `ipfs_store.put_raw(article_bytes)`.
///    The returned CID is CIDv1 RAW SHA2-256 of `article_bytes`.
/// 3. Insert `(message_id, cid)` into `msgid_map`.
/// 4. Return `Ok(cid)` on success.
pub async fn write_article_to_ipfs(
    ipfs_store: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    article_bytes: &[u8],
    message_id: &str,
) -> Result<Cid, Response> {
    // Defensive backstop dedup: rejects a duplicate that slipped past the
    // primary gate (post::pipeline::check_duplicate_msgid) in a concurrent
    // POST race.  Do NOT remove this check; see the doc on check_duplicate_msgid
    // for the full two-level dedup architecture.
    match msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(_)) => {
            return Err(Response::new(
                441,
                "Duplicate article: Message-ID already known",
            ))
        }
        Ok(None) => {}
        Err(e) => {
            return Err(Response::new(
                500,
                format!("Internal error: storage lookup failed: {e}"),
            ))
        }
    }

    let cid = ipfs_store
        .put_raw(article_bytes)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: IPFS write error: {e}")))?;

    msgid_map
        .insert(message_id, &cid)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: storage error: {e}")))?;

    Ok(cid)
}

/// Write a signed article to IPFS as a proper IPLD block set and record the
/// Message-ID → root CID mapping.
///
/// Uses [`build_article`] to construct DAG-CBOR root (codec 0x71) plus raw
/// header/body/MIME sub-blocks.  Every block is stored via [`put_block`] so
/// that the root CID carries the correct DAG-CBOR codec required by
/// [`verify_entry`].
///
/// Steps:
/// 1. Check `msgid_map` for `message_id` — return `Err(441)` if already known.
/// 2. Split `article_bytes` into header and body sections.
/// 3. Call [`build_article`] to produce the IPLD block set.
/// 4. Store every block via `ipfs_store.put_block(cid, data)`.
/// 5. Insert `(message_id, root_cid)` into `msgid_map`.
/// 6. Return `Ok(root_cid)` on success.
///
/// `operator_signature`: raw 64-byte Ed25519 signature from `sign_article`
/// (over the pre-sign article bytes), or `vec![]` for unsigned articles such
/// as ActivityPub-ingested articles.
pub async fn write_ipld_article_to_ipfs(
    ipfs_store: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    article_bytes: &[u8],
    message_id: &str,
    newsgroups: Vec<String>,
    hlc_timestamp: u64,
    operator_signature: Vec<u8>,
) -> Result<Cid, Response> {
    // Defensive backstop dedup: same rationale as the lookup in
    // write_article_to_ipfs above; see post::pipeline::check_duplicate_msgid.
    match msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(_)) => {
            return Err(Response::new(
                441,
                "Duplicate article: Message-ID already known",
            ))
        }
        Ok(None) => {}
        Err(e) => {
            return Err(Response::new(
                500,
                format!("Internal error: storage lookup failed: {e}"),
            ))
        }
    }

    // Split header and body.
    let (header_bytes, body_bytes) = split_header_body(article_bytes);

    // Build the IPLD block set.
    let built = build_article(
        &header_bytes,
        &body_bytes,
        message_id.to_owned(),
        newsgroups,
        hlc_timestamp,
        operator_signature,
    )
    .map_err(|e| Response::new(441, format!("Posting failed: IPLD build error: {e}")))?;

    // Store all blocks.
    for (cid, data) in built.blocks {
        ipfs_store
            .put_block(cid, data)
            .await
            .map_err(|e| Response::new(441, format!("Posting failed: IPFS write error: {e}")))?;
    }

    // Record Message-ID → root CID mapping.
    msgid_map
        .insert(message_id, &built.root_cid)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: storage error: {e}")))?;

    Ok(built.root_cid)
}

fn split_header_body(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (h, b) = crate::post::split_header_body(bytes);
    (h.to_vec(), b.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stoa_core::msgid_map::MsgIdMap;

    async fn make_msgid_map() -> MsgIdMap {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        // Keep tmp alive for the lifetime of the pool by leaking it;
        // the file is cleaned up when the process ends or the pool drops.
        std::mem::forget(tmp);
        MsgIdMap::new(pool)
    }

    /// Failure injection wrapper for `IpfsBlockStore`.
    ///
    /// Wraps a `MemIpfsStore` and injects failures based on a configurable
    /// policy. For use in tests only.
    struct FailingIpfsStore {
        inner: MemIpfsStore,
        /// If `Some(n)`, fail on every call whose 1-indexed count is divisible
        /// by `n`.
        fail_every_n: Option<u64>,
        call_count: std::sync::atomic::AtomicU64,
        /// If `true`, every call fails regardless of `fail_every_n`.
        always_fail: bool,
    }

    impl FailingIpfsStore {
        fn always_fail() -> Self {
            Self {
                inner: MemIpfsStore::new(),
                fail_every_n: None,
                call_count: std::sync::atomic::AtomicU64::new(0),
                always_fail: true,
            }
        }

        fn fail_every_n(n: u64) -> Self {
            Self {
                inner: MemIpfsStore::new(),
                fail_every_n: Some(n),
                call_count: std::sync::atomic::AtomicU64::new(0),
                always_fail: false,
            }
        }

        /// Increment the call counter and return `true` if this call should
        /// be failed according to the configured policy.
        fn should_fail(&self) -> bool {
            if self.always_fail {
                return true;
            }
            if let Some(n) = self.fail_every_n {
                let count = self
                    .call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                return count % n == 0;
            }
            false
        }
    }

    #[async_trait]
    impl IpfsBlockStore for FailingIpfsStore {
        async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.put_raw(data).await
        }

        async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.put_block(cid, data).await
        }

        async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.get_raw(cid).await
        }
    }

    #[tokio::test]
    async fn write_returns_stable_cid() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid1 = store.put_raw(data).await.unwrap();
        let cid2 = store.put_raw(data).await.unwrap();

        assert_eq!(cid1, cid2, "same bytes must produce the same CID");
    }

    #[tokio::test]
    async fn write_records_in_msgid_map() {
        let store = MemIpfsStore::new();
        let map = make_msgid_map().await;
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let msgid = "<test-record@example.com>";

        let cid = write_article_to_ipfs(&store, &map, data, msgid)
            .await
            .unwrap();

        let found = map.lookup_by_msgid(msgid).await.unwrap();
        assert_eq!(
            found,
            Some(cid),
            "msgid_map must record the CID after write"
        );
    }

    #[tokio::test]
    async fn write_then_get_block() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw(data).await.unwrap();
        let retrieved = store.get_raw(&cid).await.unwrap();

        assert_eq!(retrieved, data, "retrieved bytes must match written bytes");
    }

    #[tokio::test]
    async fn ipfs_failure_does_not_record_msgid() {
        let store = FailingIpfsStore::always_fail();
        let map = make_msgid_map().await;
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let msgid = "<test-failure@example.com>";

        let result = write_article_to_ipfs(&store, &map, data, msgid).await;
        assert!(result.is_err(), "IPFS failure must return Err");
        assert_eq!(result.unwrap_err().code, 441);

        let found = map.lookup_by_msgid(msgid).await.unwrap();
        assert!(
            found.is_none(),
            "msgid_map must not be updated when IPFS write fails"
        );
    }

    #[tokio::test]
    async fn cid_uses_raw_codec() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw(data).await.unwrap();

        assert_eq!(cid.codec(), 0x55, "CID codec must be RAW (0x55)");
    }

    #[tokio::test]
    async fn always_fail_store_returns_error() {
        let store = FailingIpfsStore::always_fail();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let result = store.put_raw(data).await;
        assert!(
            result.is_err(),
            "always_fail store must return Err on every call"
        );
    }

    #[tokio::test]
    async fn fail_every_n_fails_on_nth_call() {
        let store = FailingIpfsStore::fail_every_n(2);
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        // Call 1 (count=1, 1%2 != 0): should succeed.
        let result1 = store.put_raw(data).await;
        assert!(result1.is_ok(), "call 1 must succeed with fail_every_n=2");

        // Call 2 (count=2, 2%2 == 0): should fail.
        let result2 = store.put_raw(data).await;
        assert!(result2.is_err(), "call 2 must fail with fail_every_n=2");

        // Call 3 (count=3, 3%2 != 0): should succeed.
        let result3 = store.put_raw(data).await;
        assert!(result3.is_ok(), "call 3 must succeed with fail_every_n=2");
    }

    #[tokio::test]
    async fn non_failing_store_roundtrip() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw(data).await.unwrap();
        let retrieved = store.get_raw(&cid).await.unwrap();

        assert_eq!(
            retrieved, data,
            "MemIpfsStore put/get roundtrip must be exact"
        );
    }
}
