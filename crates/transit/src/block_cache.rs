//! Local LRU block cache for IPFS content (stoa-31v).
//!
//! [`BlockCache`] wraps any [`IpfsStore`] implementation and adds a
//! content-addressed on-disk cache in front of it.  Because CIDs are
//! immutable, cache invalidation is trivially correct: the same CID always
//! maps to the same bytes, so a cached entry is valid indefinitely.
//!
//! # Cache structure
//!
//! Each cached block is stored as a file in `config.path`, named by the CID
//! string (multibase, e.g. `BAFY…`).  A SQLite table
//! `transit_block_cache` tracks `(cid, file_path, byte_size, last_access)` so
//! that LRU eviction can proceed without a directory scan.
//!
//! # Serving staged articles from cache
//!
//! Articles that have been staged to disk (stoa-9mf) but not yet
//! written to IPFS are served via the staging path, not through this cache.
//! Once the pipeline completes, the block is both in IPFS and (after the next
//! read) in this cache.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cid::Cid;
use serde::Deserialize;
use sqlx::AnyPool;
use tokio::fs;
use tracing::{debug, warn};

use crate::peering::pipeline::{IpfsError, IpfsStore};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Local block cache configuration (`[cache]` in transit.toml).
///
/// Omit the entire section to disable caching (all reads and writes go
/// directly to the underlying IPFS store).
#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    /// Directory for cache files.  Created at startup if it does not exist.
    pub path: String,
    /// Maximum total cache size in bytes.  Default: 10 GiB.
    ///
    /// When this limit would be exceeded by a new entry, LRU entries are
    /// evicted until there is enough room.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Maximum number of cached entries.  Default: 1 000 000.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
}

fn default_max_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}
fn default_max_entries() -> u64 {
    1_000_000
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Internal cache errors.  These are non-fatal: a cache miss or eviction
/// failure degrades to a direct IPFS store call, not a hard error.
#[non_exhaustive]
#[derive(Debug)]
pub enum CacheError {
    Db(sqlx::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Db(e) => write!(f, "cache DB error: {e}"),
            CacheError::Io(e) => write!(f, "cache I/O error: {e}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<sqlx::Error> for CacheError {
    fn from(e: sqlx::Error) -> Self {
        CacheError::Db(e)
    }
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e)
    }
}

// ── BlockCache ────────────────────────────────────────────────────────────────

/// LRU block cache that wraps an [`IpfsStore`].
///
/// Implements [`IpfsStore`] so it can be swapped in transparently anywhere the
/// underlying store is used.
pub struct BlockCache {
    config: CacheConfig,
    pool: Arc<AnyPool>,
    inner: Arc<dyn IpfsStore>,
}

impl BlockCache {
    /// Wrap `inner` with an LRU block cache.
    ///
    /// Caller must ensure the cache directory exists before calling; use
    /// [`tokio::fs::create_dir_all`] at startup.
    pub fn new(config: CacheConfig, pool: Arc<AnyPool>, inner: Arc<dyn IpfsStore>) -> Self {
        Self {
            config,
            pool,
            inner,
        }
    }

    /// Check the local cache for `cid`.  On a hit, updates `last_access` and
    /// returns the bytes.  Returns `None` on a miss.
    async fn cache_get(&self, cid: &Cid) -> Option<Vec<u8>> {
        let cid_str = cid.to_string();
        let row: Option<(String,)> =
            sqlx::query_as("SELECT file_path FROM transit_block_cache WHERE cid = ?")
                .bind(&cid_str)
                .fetch_optional(&*self.pool)
                .await
                .ok()
                .flatten();

        let (file_path,) = row?;
        let bytes = fs::read(&file_path).await.ok()?;

        // Update last_access for LRU ordering.
        let now = unix_millis();
        let _ = sqlx::query("UPDATE transit_block_cache SET last_access = ? WHERE cid = ?")
            .bind(now)
            .bind(&cid_str)
            .execute(&*self.pool)
            .await;

        debug!(cid = %cid_str, "cache hit");
        Some(bytes)
    }

    /// Write `bytes` into the local cache under `cid`.
    ///
    /// Evicts LRU entries if necessary.  Errors are logged but not propagated
    /// — the caller already has the bytes from IPFS.
    async fn cache_put(&self, cid: &Cid, bytes: &[u8]) {
        if let Err(e) = self.do_cache_put(cid, bytes).await {
            warn!(cid = %cid, "block cache put failed: {e}");
        }
    }

    async fn do_cache_put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), CacheError> {
        let cid_str = cid.to_string();

        // Skip if already cached.
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM transit_block_cache WHERE cid = ?")
                .bind(&cid_str)
                .fetch_optional(&*self.pool)
                .await?;
        if exists.is_some() {
            return Ok(());
        }

        // Evict until there is room for this entry.
        self.evict_for(bytes.len() as u64).await?;

        let path_buf = PathBuf::from(&self.config.path).join(&cid_str);
        let file_path = path_buf.to_str().ok_or_else(|| {
            CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "block cache path contains non-UTF-8 bytes: {}",
                    path_buf.display()
                ),
            ))
        })?;

        // Write the file first, then insert the DB row.
        //
        // The previous order (INSERT then write) had a TOCTOU window: a
        // concurrent get_raw could find the DB row before the file existed,
        // producing a misleading I/O error instead of a cache miss.
        //
        // With the new order: if the file write fails, nothing is in the DB
        // (no cleanup needed).  If the DB INSERT fails after a successful file
        // write, we delete the file to avoid orphan disk usage.
        if let Err(e) = fs::write(&file_path, bytes).await {
            return Err(CacheError::Io(e));
        }

        let now = unix_millis();
        if let Err(e) = sqlx::query(
            "INSERT INTO transit_block_cache \
             (cid, file_path, byte_size, last_access) VALUES (?, ?, ?, ?) \
             ON CONFLICT (cid) DO NOTHING",
        )
        .bind(&cid_str)
        .bind(file_path)
        .bind(bytes.len() as i64)
        .bind(now)
        .execute(&*self.pool)
        .await
        {
            // Clean up the file so it does not leak disk space.
            let _ = fs::remove_file(&file_path).await;
            return Err(CacheError::Db(e));
        }

        Ok(())
    }

    /// Evict LRU entries until both limits are satisfied when `incoming_bytes`
    /// are added.
    ///
    /// Uses two DB round-trips regardless of eviction count: one SELECT to
    /// collect LRU victims, one batch DELETE to remove them all.
    async fn evict_for(&self, incoming_bytes: u64) -> Result<(), CacheError> {
        let (initial_count, initial_bytes): (i64, i64) =
            sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(byte_size), 0) FROM transit_block_cache")
                .fetch_one(&*self.pool)
                .await?;

        let mut count = initial_count as u64;
        let mut total_bytes = initial_bytes as u64;

        // Fast path: nothing to evict.
        if count < self.config.max_entries && total_bytes + incoming_bytes <= self.config.max_bytes
        {
            return Ok(());
        }

        // Fetch LRU candidates in a single query.  We scan in last_access
        // order and stop accumulating once both constraints are satisfied.
        // The result set is bounded by the cache entry limit.
        let candidates: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT cid, file_path, byte_size \
             FROM transit_block_cache \
             ORDER BY last_access ASC",
        )
        .fetch_all(&*self.pool)
        .await?;

        let mut victim_cids: Vec<String> = Vec::new();
        let mut victim_paths: Vec<String> = Vec::new();
        for (cid, path, size) in candidates {
            let needs_eviction = (count + 1 > self.config.max_entries)
                || (total_bytes + incoming_bytes > self.config.max_bytes);
            if !needs_eviction {
                break;
            }
            count = count.saturating_sub(1);
            total_bytes = total_bytes.saturating_sub(size as u64);
            victim_cids.push(cid);
            victim_paths.push(path);
        }

        if victim_cids.is_empty() {
            return Ok(());
        }

        // Delete cache files (non-fatal per entry).
        for (cid, path) in victim_cids.iter().zip(victim_paths.iter()) {
            if let Err(e) = fs::remove_file(path).await {
                warn!(cid = %cid, "could not delete cache file during eviction: {e}");
            }
        }

        // Batch DELETE in chunks to stay within SQLite's 999-parameter limit.
        const CHUNK_SIZE: usize = 333;
        for chunk in victim_cids.chunks(CHUNK_SIZE) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let sql = format!(
                "DELETE FROM transit_block_cache WHERE cid IN ({})",
                placeholders
            );
            let mut q = sqlx::query(&sql);
            for cid in chunk {
                q = q.bind(cid);
            }
            q.execute(&*self.pool).await?;
        }

        debug!(
            evicted = victim_cids.len(),
            "evicted LRU entries from block cache"
        );
        Ok(())
    }
}

#[async_trait]
impl IpfsStore for BlockCache {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let cid = self.inner.put_raw(data).await?;
        self.cache_put(&cid, data).await;
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        if let Some(bytes) = self.cache_get(cid).await {
            return Ok(Some(bytes));
        }
        let result = self.inner.get_raw(cid).await?;
        if let Some(ref bytes) = result {
            self.cache_put(cid, bytes).await;
        }
        Ok(result)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Monotonically increasing access timestamp with millisecond precision.
///
/// Using milliseconds (rather than seconds) means that multiple cache inserts
/// within the same second still produce distinct `last_access` values, which
/// keeps LRU ordering correct even in rapid test runs.
///
/// Milliseconds are used instead of nanoseconds to avoid the `as i64` truncation
/// that would wrap to negative around year 2262.  Millisecond values fit safely
/// in `i64` until approximately year 292 million.
fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peering::pipeline::MemIpfsStore;

    /// Temp-file SQLite AnyPool with the transit block cache schema via migrations.
    ///
    /// Returns `(pool, tmp)` — keep `tmp` alive for the duration of the test so
    /// the file is not deleted before the pool is dropped.
    async fn make_pool() -> (Arc<AnyPool>, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (Arc::new(pool), tmp)
    }

    fn cache_config(dir: &str, max_entries: u64, max_bytes: u64) -> CacheConfig {
        CacheConfig {
            path: dir.to_owned(),
            max_bytes,
            max_entries,
        }
    }

    fn make_cache(dir: &str, pool: Arc<AnyPool>, max_entries: u64, max_bytes: u64) -> BlockCache {
        BlockCache::new(
            cache_config(dir, max_entries, max_bytes),
            pool,
            Arc::new(MemIpfsStore::new()),
        )
    }

    #[tokio::test]
    async fn put_raw_then_get_raw_serves_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let cache = make_cache(
            dir.path().to_str().unwrap(),
            pool.clone(),
            100,
            10 * 1024 * 1024,
        );

        let data = b"hello from ipfs";
        let cid = cache.put_raw(data).await.unwrap();

        // Verify the row exists in cache.
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_block_cache")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "entry must be cached after put_raw");

        // get_raw should return from cache without touching inner store.
        let result = cache.get_raw(&cid).await.unwrap();
        assert_eq!(result.as_deref(), Some(data.as_slice()));
    }

    #[tokio::test]
    async fn get_raw_miss_fetches_from_inner_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let inner = Arc::new(MemIpfsStore::new());

        // Pre-seed the inner store directly (bypassing the cache).
        let data = b"seeded block";
        let cid = inner.put_raw(data).await.unwrap();

        let cache = BlockCache::new(
            cache_config(dir.path().to_str().unwrap(), 100, 10 * 1024 * 1024),
            pool.clone(),
            Arc::clone(&inner) as Arc<dyn IpfsStore>,
        );

        // Cache is initially empty.
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_block_cache")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        let result = cache.get_raw(&cid).await.unwrap();
        assert_eq!(result.as_deref(), Some(data.as_slice()));

        // Cache should now have the entry.
        let (count2,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_block_cache")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count2, 1, "miss should populate the cache");
    }

    #[tokio::test]
    async fn eviction_removes_lru_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        // max_entries = 2 so the 3rd put triggers eviction.
        let cache = make_cache(dir.path().to_str().unwrap(), pool.clone(), 2, u64::MAX);

        let cid1 = cache.put_raw(b"block one").await.unwrap();
        // Sleep 2 ms to guarantee cid2 gets a strictly larger last_access
        // timestamp than cid1, preventing LRU tie-breaking non-determinism.
        tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        let cid2 = cache.put_raw(b"block two").await.unwrap();

        // Touch cid1 to make it more recently used than cid2.
        tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        let _ = cache.get_raw(&cid1).await.unwrap();

        // Adding a 3rd entry must evict cid2 (oldest last_access).
        let _cid3 = cache.put_raw(b"block three").await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_block_cache")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "after eviction, should have exactly max_entries");

        // cid2 must have been evicted.
        let evicted: Option<(String,)> =
            sqlx::query_as("SELECT cid FROM transit_block_cache WHERE cid = ?")
                .bind(cid2.to_string())
                .fetch_optional(&*pool)
                .await
                .unwrap();
        assert!(evicted.is_none(), "LRU entry (cid2) must have been evicted");
    }

    #[tokio::test]
    async fn get_raw_returns_none_for_unknown_cid() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let cache = make_cache(dir.path().to_str().unwrap(), pool, 100, 10 * 1024 * 1024);

        // Use a CID that was never stored.
        let bogus_bytes = [0u8; 32];
        use multihash_codetable::{Code, MultihashDigest};
        let mh = Code::Sha2_256.digest(&bogus_bytes);
        let bogus_cid = Cid::new_v1(0x55, mh); // raw codec

        let result = cache.get_raw(&bogus_cid).await.unwrap();
        assert!(result.is_none(), "unknown CID must return None");
    }
}
