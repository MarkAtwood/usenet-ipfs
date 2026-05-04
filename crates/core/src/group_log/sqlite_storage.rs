use cid::Cid;
use sqlx::AnyPool;

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::hlc::HlcTimestamp;

/// Multi-backend `LogStorage` implementation (SQLite or PostgreSQL).
pub struct SqliteLogStorage {
    pool: AnyPool,
}

impl SqliteLogStorage {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn db_err(e: sqlx::Error) -> StorageError {
    StorageError::Database(e.to_string())
}

fn cid_from_bytes(bytes: &[u8]) -> Result<Cid, StorageError> {
    Cid::try_from(bytes).map_err(|e| StorageError::Database(format!("invalid CID bytes: {e}")))
}

// ── trait impl ───────────────────────────────────────────────────────────────

impl LogStorage for SqliteLogStorage {
    async fn insert_entry(&self, id: LogEntryId, entry: LogEntry) -> Result<(), StorageError> {
        let id_bytes = id.as_bytes().to_vec();
        let article_cid_bytes = entry.article_cid.to_bytes();
        // HLC timestamps are stored as wall_ms (u64) in the DB column (i64).
        // logical and node_id are not persisted — they are used only for
        // in-memory CRDT ordering within a single session.  A timestamp
        // wall_ms > i64::MAX (year ~292 million CE) cannot be stored.
        let ts = i64::try_from(entry.hlc_timestamp.wall_ms).map_err(|_| {
            StorageError::Database(format!(
                "HLC timestamp {:?} exceeds i64::MAX — cannot store",
                entry.hlc_timestamp
            ))
        })?;

        // Begin the transaction first so the duplicate check and both inserts
        // are fully atomic.  We do NOT pre-check for duplicates outside the
        // transaction — that creates a TOCTOU window where a concurrent insert
        // can slip in between the check and the INSERT, causing a confusing DB
        // error instead of DuplicateEntry.  Instead, we attempt the INSERT
        // directly and translate a UNIQUE constraint violation to DuplicateEntry.
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let insert_result = sqlx::query(
            "INSERT INTO log_entries (id, hlc_timestamp, article_cid, operator_signature)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id_bytes)
        .bind(ts)
        .bind(&article_cid_bytes)
        .bind(&entry.operator_signature)
        .execute(&mut *tx)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(StorageError::DuplicateEntry(id));
            }
            Err(e) => return Err(db_err(e)),
        }

        for parent_cid in &entry.parent_cids {
            let parent_bytes = parent_cid.to_bytes();
            sqlx::query(
                "INSERT INTO log_entry_parents (entry_id, parent_id) VALUES (?, ?)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&id_bytes)
            .bind(&parent_bytes)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn get_entry(&self, id: &LogEntryId) -> Result<Option<LogEntry>, StorageError> {
        let id_bytes = id.as_bytes().to_vec();

        let row: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT hlc_timestamp, article_cid, operator_signature
             FROM log_entries WHERE id = ?",
        )
        .bind(&id_bytes)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some((ts, cid_bytes, sig)) = row else {
            return Ok(None);
        };

        let article_cid = cid_from_bytes(&cid_bytes)?;

        // Fetch parent CIDs.
        let parent_rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT parent_id FROM log_entry_parents WHERE entry_id = ?")
                .bind(&id_bytes)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        let mut parent_cids = Vec::with_capacity(parent_rows.len());
        for (pb,) in parent_rows {
            parent_cids.push(cid_from_bytes(&pb)?);
        }

        // Guard against database corruption: hlc_timestamp is always stored as
        // a non-negative i64 (validated on insert), so a negative value means
        // the row is corrupt.  A blind `ts as u64` would silently wrap to a
        // huge timestamp, corrupting Merkle-CRDT time ordering.
        if ts < 0 {
            return Err(StorageError::Database(format!(
                "corrupt hlc_timestamp {ts} in log entry: expected non-negative"
            )));
        }

        Ok(Some(LogEntry {
            // Only wall_ms is stored in the DB; logical and node_id are
            // in-memory ordering fields not written to persistent storage.
            hlc_timestamp: HlcTimestamp {
                wall_ms: ts as u64,
                logical: 0,
                node_id: [0u8; 8],
            },
            article_cid,
            operator_signature: sig,
            parent_cids,
        }))
    }

    async fn has_entry(&self, id: &LogEntryId) -> Result<bool, StorageError> {
        let id_bytes = id.as_bytes().to_vec();
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM log_entries WHERE id = ? LIMIT 1")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    async fn get_parent_cids(
        &self,
        id: &LogEntryId,
    ) -> Result<Option<Vec<cid::Cid>>, StorageError> {
        let id_bytes = id.as_bytes().to_vec();

        // First check if the entry exists at all.
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM log_entries WHERE id = ? LIMIT 1")
                .bind(&id_bytes)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        if exists.is_none() {
            return Ok(None);
        }

        // Fetch only the parent CIDs — skip hlc_timestamp, article_cid, operator_signature.
        let parent_rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT parent_id FROM log_entry_parents WHERE entry_id = ?")
                .bind(&id_bytes)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        let mut parent_cids = Vec::with_capacity(parent_rows.len());
        for (pb,) in parent_rows {
            parent_cids.push(cid_from_bytes(&pb)?);
        }
        Ok(Some(parent_cids))
    }

    async fn list_tips(&self, group: &GroupName) -> Result<Vec<LogEntryId>, StorageError> {
        let rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT tip_id FROM group_tips WHERE group_name = ?")
                .bind(group.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        let mut ids = Vec::with_capacity(rows.len());
        for (bytes,) in rows {
            if bytes.len() != 32 {
                return Err(StorageError::Database(format!(
                    "corrupt tip_id: expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            ids.push(LogEntryId::from_bytes(arr));
        }
        Ok(ids)
    }

    async fn set_tips(&self, group: &GroupName, tips: &[LogEntryId]) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        sqlx::query("DELETE FROM group_tips WHERE group_name = ?")
            .bind(group.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        if !tips.is_empty() {
            // Single bulk INSERT avoids O(T) round-trips for T tips.
            // QueryBuilder::push_values handles placeholder generation safely.
            let mut qb = sqlx::QueryBuilder::new("INSERT INTO group_tips (group_name, tip_id) ");
            qb.push_values(tips, |mut b, tip| {
                b.push_bind(group.as_str())
                    .push_bind(tip.as_bytes().to_vec());
            });
            qb.build().execute(&mut *tx).await.map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn advance_tips(
        &self,
        group: &GroupName,
        parents_to_remove: &[LogEntryId],
        new_tip: &LogEntryId,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let group_name = group.as_str();

        if !parents_to_remove.is_empty() {
            // Single bulk DELETE: WHERE tip_id IN (...) avoids O(P) round-trips.
            // QueryBuilder handles placeholder generation safely.
            let mut qb = sqlx::QueryBuilder::new("DELETE FROM group_tips WHERE group_name = ");
            qb.push_bind(group_name);
            qb.push(" AND tip_id IN (");
            let mut sep = qb.separated(", ");
            for p in parents_to_remove {
                sep.push_bind(p.as_bytes().to_vec());
            }
            sep.push_unseparated(")");
            qb.build().execute(&mut *tx).await.map_err(db_err)?;
        }

        let new_tip_bytes = new_tip.as_bytes().to_vec();
        sqlx::query(
            "INSERT INTO group_tips (group_name, tip_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(group_name)
        .bind(&new_tip_bytes)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn insert_entry_and_advance_tips(
        &self,
        id: LogEntryId,
        entry: LogEntry,
        group: &GroupName,
        parents_to_remove: &[LogEntryId],
        new_tip: &LogEntryId,
    ) -> Result<(), StorageError> {
        let id_bytes = id.as_bytes().to_vec();
        let article_cid_bytes = entry.article_cid.to_bytes();
        let ts = i64::try_from(entry.hlc_timestamp.wall_ms).map_err(|_| {
            StorageError::Database(format!(
                "HLC timestamp {:?} exceeds i64::MAX — cannot store",
                entry.hlc_timestamp
            ))
        })?;

        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // INSERT entry — translate UNIQUE violation to DuplicateEntry.
        let insert_result = sqlx::query(
            "INSERT INTO log_entries (id, hlc_timestamp, article_cid, operator_signature)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id_bytes)
        .bind(ts)
        .bind(&article_cid_bytes)
        .bind(&entry.operator_signature)
        .execute(&mut *tx)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(StorageError::DuplicateEntry(id));
            }
            Err(e) => return Err(db_err(e)),
        }

        // INSERT parent edges.
        for parent_cid in &entry.parent_cids {
            let parent_bytes = parent_cid.to_bytes();
            sqlx::query(
                "INSERT INTO log_entry_parents (entry_id, parent_id) VALUES (?, ?)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&id_bytes)
            .bind(&parent_bytes)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        // DELETE parent tips.
        if !parents_to_remove.is_empty() {
            let mut qb = sqlx::QueryBuilder::new("DELETE FROM group_tips WHERE group_name = ");
            qb.push_bind(group.as_str());
            qb.push(" AND tip_id IN (");
            let mut sep = qb.separated(", ");
            for p in parents_to_remove {
                sep.push_bind(p.as_bytes().to_vec());
            }
            sep.push_unseparated(")");
            qb.build().execute(&mut *tx).await.map_err(db_err)?;
        }

        // INSERT new tip.
        let new_tip_bytes = new_tip.as_bytes().to_vec();
        sqlx::query(
            "INSERT INTO group_tips (group_name, tip_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(group.as_str())
        .bind(&new_tip_bytes)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn tip_count(&self, group: &GroupName) -> Result<u64, StorageError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_tips WHERE group_name = ?")
            .bind(group.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        if row.0 < 0 {
            return Err(StorageError::Database(format!(
                "corrupt tip_count {}: expected non-negative",
                row.0
            )));
        }
        Ok(row.0 as u64)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_pool::try_open_any_pool;
    use crate::group_log::storage_tests;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = try_open_any_pool(&url, 1).await.expect("pool");
        (pool, tmp)
    }

    #[tokio::test]
    async fn sqlite_insert_and_get() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_insert_and_get(&s).await;
    }

    #[tokio::test]
    async fn sqlite_get_missing_returns_none() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_get_missing_returns_none(&s).await;
    }

    #[tokio::test]
    async fn sqlite_has_entry() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_has_entry(&s).await;
    }

    #[tokio::test]
    async fn sqlite_set_and_list_tips() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_set_and_list_tips(&s).await;
    }

    #[tokio::test]
    async fn sqlite_tip_count() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_tip_count(&s).await;
    }

    #[tokio::test]
    async fn sqlite_duplicate_insert_rejected() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_duplicate_insert_rejected(&s).await;
    }

    #[tokio::test]
    async fn sqlite_tips_are_group_scoped() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_tips_are_group_scoped(&s).await;
    }

    #[tokio::test]
    async fn sqlite_advance_tips_basic() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_advance_tips_basic(&s).await;
    }

    #[tokio::test]
    async fn sqlite_advance_tips_concurrent() {
        let (pool, _tmp) = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_advance_tips_concurrent(&s).await;
    }
}
