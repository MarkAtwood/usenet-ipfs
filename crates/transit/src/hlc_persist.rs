//! Persist and load the HLC clock state across restarts (usenet-ipfs-gq0z).
//!
//! A single row in `hlc_checkpoint` stores the last emitted timestamp.
//! On startup, `load_hlc_checkpoint` reads it; `HlcClock::new_seeded` then
//! ensures the first `send()` after restart is above the persisted value.
//!
//! A background task calls `save_hlc_checkpoint` every 30 seconds.

use sqlx::AnyPool;
use stoa_core::hlc::HlcTimestamp;

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (pool, tmp)
    }

    #[tokio::test]
    async fn load_returns_none_on_empty_table() {
        let (pool, _tmp) = make_pool().await;
        let result = load_hlc_checkpoint(&pool).await.unwrap();
        assert!(result.is_none(), "no checkpoint row must return None");
    }

    #[tokio::test]
    async fn save_and_load_roundtrip_preserves_node_id() {
        let (pool, _tmp) = make_pool().await;
        let ts = HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 42,
            node_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        save_hlc_checkpoint(&pool, ts, 1_700_000_000_999)
            .await
            .unwrap();

        let loaded = load_hlc_checkpoint(&pool)
            .await
            .unwrap()
            .expect("checkpoint must be present after save");
        assert_eq!(loaded.wall_ms, ts.wall_ms);
        assert_eq!(loaded.logical, ts.logical);
        assert_eq!(
            loaded.node_id, ts.node_id,
            "node_id must survive the save/load round-trip"
        );
    }

    #[tokio::test]
    async fn save_overwrites_previous_checkpoint() {
        let (pool, _tmp) = make_pool().await;
        let ts1 = HlcTimestamp {
            wall_ms: 1000,
            logical: 1,
            node_id: [0xAA; 8],
        };
        let ts2 = HlcTimestamp {
            wall_ms: 2000,
            logical: 0,
            node_id: [0xBB; 8],
        };
        save_hlc_checkpoint(&pool, ts1, 1000).await.unwrap();
        save_hlc_checkpoint(&pool, ts2, 2000).await.unwrap();

        let loaded = load_hlc_checkpoint(&pool).await.unwrap().unwrap();
        assert_eq!(loaded.wall_ms, 2000);
        assert_eq!(
            loaded.node_id, [0xBB; 8],
            "second save must overwrite first"
        );
    }
}

/// Load the persisted HLC checkpoint.
///
/// Returns `Ok(None)` on first run (table row does not exist yet).
/// The returned `HlcTimestamp.node_id` is the node_id stored at the last
/// save; callers should cross-check it against the authoritative
/// `ensure_instance_node_id` value and warn on mismatch.
pub async fn load_hlc_checkpoint(pool: &AnyPool) -> Result<Option<HlcTimestamp>, sqlx::Error> {
    let row: Option<(i64, i64, Vec<u8>)> =
        sqlx::query_as("SELECT wall_ms, logical, node_id FROM hlc_checkpoint WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(wall_ms, logical, node_id_bytes)| {
        let mut node_id = [0u8; 8];
        let len = node_id_bytes.len().min(8);
        node_id[..len].copy_from_slice(&node_id_bytes[..len]);
        HlcTimestamp {
            wall_ms: wall_ms as u64,
            logical: logical as u32,
            node_id,
        }
    }))
}

/// Upsert the HLC checkpoint row, including the node_id.
///
/// Best-effort: errors are logged but not propagated to the caller.
pub async fn save_hlc_checkpoint(
    pool: &AnyPool,
    ts: HlcTimestamp,
    now_ms: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO hlc_checkpoint (id, wall_ms, logical, saved_at, node_id) \
         VALUES (1, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET \
           wall_ms  = excluded.wall_ms, \
           logical  = excluded.logical, \
           saved_at = excluded.saved_at, \
           node_id  = excluded.node_id",
    )
    .bind(ts.wall_ms as i64)
    .bind(ts.logical as i64)
    .bind(now_ms as i64)
    .bind(ts.node_id.to_vec())
    .execute(pool)
    .await?;
    Ok(())
}
