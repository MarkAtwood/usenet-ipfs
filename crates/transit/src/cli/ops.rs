//! Operator CLI subcommands: status, pin, unpin, gc-run, peer-list.
//!
//! These functions operate directly against the local SQLite database.
//! No running daemon is required; they are suitable for use from a
//! maintenance shell or init script.

use sqlx::AnyPool;
use stoa_core::error::StorageError;

use crate::cli::peers::OutputFormat;
use crate::retention::pin_client::PinClient;
use crate::retention::policy::{ArticleMeta, PinPolicy};

/// Row returned by the pinned-CIDs + articles LEFT JOIN in [`cmd_gc_run`].
/// Fields after `cid` are `NULL` when a pinned CID has no `articles` row.
type PinnedCidRow = (String, Option<String>, Option<i64>, Option<i64>);

/// Print daemon status: peer count, article count from msgid_map, pinned CID count.
///
/// All counts are read directly from SQLite. If a table does not exist
/// (first run before migrations), the count is reported as 0.
pub async fn cmd_status(
    pool: &AnyPool,
    core_pool: &AnyPool,
    format: OutputFormat,
) -> Result<String, StorageError> {
    let article_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(core_pool)
        .await
        .unwrap_or(0);

    let now_ms_peers = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let peer_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM peers WHERE blacklisted_until IS NULL OR blacklisted_until <= ?",
    )
    .bind(now_ms_peers)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    ensure_pinned_cids_table(pool).await?;

    let pinned_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pinned_cids")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    match format {
        OutputFormat::Table => Ok(format!(
            "peers (active):  {peer_count}\n\
             articles:        {article_count}\n\
             pinned CIDs:     {pinned_count}\n"
        )),
        OutputFormat::Json => {
            let v = serde_json::json!({
                "peers_active": peer_count,
                "articles": article_count,
                "pinned_cids": pinned_count,
            });
            Ok(serde_json::to_string_pretty(&v).unwrap())
        }
    }
}

/// Record a CID as operator-pinned in the pinned_cids table.
///
/// The CID string must be valid (base32/base58 multibase CIDv0 or CIDv1).
/// Returns `"pinned: {cid}"` on success.
pub async fn cmd_pin(pool: &AnyPool, cid_str: &str) -> Result<String, StorageError> {
    cid_str
        .parse::<cid::Cid>()
        .map_err(|e| StorageError::Database(format!("invalid CID '{cid_str}': {e}")))?;

    ensure_pinned_cids_table(pool).await?;

    let now_ms = now_ms();
    sqlx::query(
        "INSERT INTO pinned_cids (cid, pinned_at_ms) VALUES (?, ?) \
         ON CONFLICT (cid) DO NOTHING",
    )
    .bind(cid_str)
    .bind(now_ms)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    Ok(format!("pinned: {cid_str}\n"))
}

/// Remove a CID from the operator-pinned table.
///
/// Returns `"unpinned: {cid}"` if found and removed, or `"not pinned: {cid}"` if absent.
pub async fn cmd_unpin(pool: &AnyPool, cid_str: &str) -> Result<String, StorageError> {
    ensure_pinned_cids_table(pool).await?;

    let result = sqlx::query("DELETE FROM pinned_cids WHERE cid = ?")
        .bind(cid_str)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        Ok(format!("not pinned: {cid_str}\n"))
    } else {
        Ok(format!("unpinned: {cid_str}\n"))
    }
}

/// Run a GC cycle immediately using the given policy.
///
/// Scans all entries in `pinned_cids`, joins against the `articles` table to
/// retrieve the real group name, ingestion time, and byte count for each CID,
/// then evaluates each against the policy.  CIDs with no matching `articles`
/// row (e.g. manually pinned entries) are evaluated with group="unknown",
/// size=0, age=0 and a warning is emitted once.
///
/// For each CID that should be GC'd the function:
/// 1. Calls `pin_client.unpin()` (404 / already-unpinned is tolerated).
/// 2. Deletes the row from `articles` so the CID is no longer offered as a
///    future GC candidate.
/// 3. Deletes the row from `pinned_cids`.
///
/// Returns a summary string of the form `"gc-run: {scanned} scanned, {unpinned} unpinned\n"`.
pub async fn cmd_gc_run(
    pool: &AnyPool,
    policy: &PinPolicy,
    pin_client: &dyn PinClient,
) -> Result<String, StorageError> {
    ensure_pinned_cids_table(pool).await?;

    // Each row: (cid, group_name?, ingested_at_ms?, byte_count?)
    // The LEFT JOIN yields NULLs in the article columns when a pinned CID has
    // no corresponding articles row (e.g. manually pinned).
    let rows: Vec<PinnedCidRow> = sqlx::query_as(
        "SELECT p.cid, a.group_name, a.ingested_at_ms, a.byte_count \
         FROM pinned_cids p \
         LEFT JOIN articles a ON a.cid = p.cid",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let scanned = rows.len();
    let now_ms = now_ms();
    let mut missing_meta_warned = false;
    let mut unpinned = 0usize;

    for (cid_str, group_name, ingested_at_ms, byte_count) in &rows {
        let meta = if let Some(group) = group_name {
            let age_days = ingested_at_ms.map_or(0, |ingested| {
                let elapsed_ms = now_ms.saturating_sub(ingested);
                (elapsed_ms / (86_400 * 1_000)) as u64
            });
            ArticleMeta {
                group: group.clone(),
                size_bytes: byte_count.unwrap_or(0) as usize,
                age_days,
            }
        } else {
            if !missing_meta_warned {
                tracing::warn!(
                    "gc-run: one or more pinned CIDs have no articles row; \
                     age-based and group-scoped policy conditions cannot be \
                     evaluated for those entries (pass-through: group=unknown, \
                     size=0, age=0)"
                );
                missing_meta_warned = true;
            }
            ArticleMeta {
                group: "unknown".to_string(),
                size_bytes: 0,
                age_days: 0,
            }
        };

        if !policy.should_pin(&meta) {
            let cid = match cid_str.parse::<cid::Cid>() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(cid = %cid_str, "gc-run: invalid CID in pinned_cids, skipping: {e}");
                    continue;
                }
            };

            // Step 1: Unpin from IPFS. A 404 / already-unpinned is not an
            // error — the block may have been evicted already.
            if let Err(e) = pin_client.unpin(&cid).await {
                tracing::warn!(cid = %cid_str, "gc-run: IPFS unpin failed, skipping: {e}");
                continue;
            }

            // Step 2: Remove from articles table so the CID is no longer
            // offered as a GC candidate on subsequent runs.
            if let Err(e) = sqlx::query("DELETE FROM articles WHERE cid = ?")
                .bind(cid_str)
                .execute(pool)
                .await
            {
                tracing::warn!(cid = %cid_str, "gc-run: failed to delete articles row: {e}");
            }

            // Step 3: Remove from pinned_cids.
            sqlx::query("DELETE FROM pinned_cids WHERE cid = ?")
                .bind(cid_str)
                .execute(pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;

            unpinned += 1;
        }
    }

    Ok(format!("gc-run: {scanned} scanned, {unpinned} unpinned\n"))
}

/// `transit peer-list`: display all peers with score and status.
///
/// Delegates to the peer CLI implementation.
pub use crate::cli::peers::cmd_peer_list;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Create the pinned_cids table if it does not exist.
async fn ensure_pinned_cids_table(pool: &AnyPool) -> Result<(), StorageError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pinned_cids (\
            cid TEXT PRIMARY KEY NOT NULL, \
            pinned_at_ms INTEGER NOT NULL\
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Current Unix time in milliseconds.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::pin_client::MemPinClient;
    use crate::retention::policy::{PinAction, PinRule};
    use sqlx::AnyPool;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn make_core_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    #[tokio::test]
    async fn status_on_empty_db_table() {
        let (transit_pool, _tmp) = make_pool().await;
        let (core_pool, _core_tmp) = make_core_pool().await;
        let result = cmd_status(&transit_pool, &core_pool, OutputFormat::Table)
            .await
            .unwrap();
        assert!(
            result.contains("peers") || result.contains("articles"),
            "status output: {result}"
        );
    }

    #[tokio::test]
    async fn status_on_empty_db_json() {
        let (transit_pool, _tmp) = make_pool().await;
        let (core_pool, _core_tmp) = make_core_pool().await;
        let result = cmd_status(&transit_pool, &core_pool, OutputFormat::Json)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["peers_active"], 0);
        assert_eq!(v["articles"], 0);
        assert_eq!(v["pinned_cids"], 0);
    }

    #[tokio::test]
    async fn pin_unpin_roundtrip() {
        let (pool, _tmp) = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";

        let pin_result = cmd_pin(&pool, cid_str).await.unwrap();
        assert!(pin_result.contains("pinned"), "pin result: {pin_result}");

        let unpin_result = cmd_unpin(&pool, cid_str).await.unwrap();
        assert!(
            unpin_result.contains("unpinned"),
            "unpin result: {unpin_result}"
        );
    }

    #[tokio::test]
    async fn unpin_not_pinned() {
        let (pool, _tmp) = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        let result = cmd_unpin(&pool, cid_str).await.unwrap();
        assert!(
            result.contains("not pinned"),
            "should say not pinned: {result}"
        );
    }

    #[tokio::test]
    async fn pin_is_idempotent() {
        let (pool, _tmp) = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();
        let second = cmd_pin(&pool, cid_str).await.unwrap();
        assert!(second.contains("pinned"), "second pin result: {second}");
    }

    #[tokio::test]
    async fn gc_run_empty() {
        let (pool, _tmp) = make_pool().await;
        let policy = PinPolicy::new(vec![]);
        let pin_client = MemPinClient::new();
        let result = cmd_gc_run(&pool, &policy, &pin_client).await.unwrap();
        assert!(result.contains("gc-run"), "gc result: {result}");
        assert!(
            result.contains("0 scanned"),
            "should be 0 scanned: {result}"
        );
    }

    #[tokio::test]
    async fn gc_run_unpins_when_policy_rejects_all() {
        let (pool, _tmp) = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();

        let pin_client = MemPinClient::new();
        let policy = PinPolicy::new(vec![]);
        let result = cmd_gc_run(&pool, &policy, &pin_client).await.unwrap();
        assert!(
            result.contains("1 scanned"),
            "should be 1 scanned: {result}"
        );
        assert!(
            result.contains("1 unpinned"),
            "should be 1 unpinned: {result}"
        );
    }

    #[tokio::test]
    async fn gc_run_preserves_when_policy_accepts_all() {
        let (pool, _tmp) = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();

        let pin_client = MemPinClient::new();
        let policy = PinPolicy::new(vec![PinRule {
            groups: "all".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        }]);
        let result = cmd_gc_run(&pool, &policy, &pin_client).await.unwrap();
        assert!(
            result.contains("1 scanned"),
            "should be 1 scanned: {result}"
        );
        assert!(
            result.contains("0 unpinned"),
            "should be 0 unpinned: {result}"
        );
    }

    #[tokio::test]
    async fn invalid_cid_rejected() {
        let (pool, _tmp) = make_pool().await;
        let result = cmd_pin(&pool, "not-a-valid-cid").await;
        assert!(result.is_err(), "invalid CID should fail");
    }
}
