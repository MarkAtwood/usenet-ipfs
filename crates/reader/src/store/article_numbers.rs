//! SQLite-backed local article number store.
//!
//! Assigns and records sequential article numbers per group. Numbers are
//! local to this reader instance and are never treated as network-stable
//! identifiers (see design invariant #5).

use cid::Cid;

/// Assigns and records local sequential article numbers per group.
///
/// CIDs are stored as raw bytes (`cid.to_bytes()`).
pub struct ArticleNumberStore {
    pool: sqlx::AnyPool,
}

impl ArticleNumberStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Return a reference to the underlying pool.
    ///
    /// Exposed for `backfill_overview`, which runs a JOIN across the
    /// `article_numbers` and `overview` tables — both live in the same
    /// SQLite database (reader_pool).
    pub fn pool(&self) -> &sqlx::AnyPool {
        &self.pool
    }

    /// Assign a sequential article number to a CID within a group.
    ///
    /// Idempotent: if `(group, cid)` already has a number, return it.
    /// Numbers start at 1 and increment by 1.
    ///
    /// # DECISION (rbe3.4): two queries instead of three
    ///
    /// The previous implementation used three round-trips: SELECT (idempotency
    /// check) + SELECT MAX (next number) + INSERT.  This collapses to two:
    ///
    /// 1. `INSERT OR IGNORE … VALUES (?, (SELECT COALESCE(MAX…)+1 …), ?)` —
    ///    atomic under SQLite's write lock; the subquery computes the next
    ///    number only when the insert fires; the UNIQUE index on (group_name,
    ///    cid) causes OR IGNORE to suppress the insert idempotently.
    /// 2. `SELECT article_number … WHERE group_name = ? AND cid = ?` —
    ///    reads back the assigned number (works for both new and existing rows).
    ///
    /// The write transaction wraps both queries so concurrent callers cannot
    /// observe a partial state.
    pub async fn assign_number(&self, group: &str, cid: &Cid) -> Result<u64, sqlx::Error> {
        let cid_bytes = cid.to_bytes();

        let mut tx = self.pool.begin().await?;

        // Attempt to insert, computing the next sequential number via subquery.
        // ON CONFLICT DO NOTHING suppresses the insert when (group_name, cid)
        // already has a row — the UNIQUE index on article_numbers_cid_idx
        // enforces uniqueness on (group_name, cid).
        sqlx::query(
            "INSERT INTO article_numbers (group_name, article_number, cid) \
             VALUES (?, (SELECT COALESCE(MAX(article_number), 0) + 1 \
                         FROM article_numbers WHERE group_name = ?), ?) \
             ON CONFLICT DO NOTHING",
        )
        .bind(group)
        .bind(group)
        .bind(&cid_bytes)
        .execute(&mut *tx)
        .await?;

        // Read back the assigned number — valid for both the newly-inserted row
        // and the pre-existing row when the insert was suppressed by OR IGNORE.
        let number: i64 = sqlx::query_scalar(
            "SELECT article_number FROM article_numbers WHERE group_name = ? AND cid = ?",
        )
        .bind(group)
        .bind(&cid_bytes)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(number as u64)
    }

    /// Look up the CID for a given `(group, number)` pair.
    ///
    /// Returns `None` if no article with that number exists in the group.
    pub async fn lookup_cid(&self, group: &str, number: u64) -> Result<Option<Cid>, sqlx::Error> {
        let number = number as i64;

        let row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cid FROM article_numbers WHERE group_name = ? AND article_number = ?",
        )
        .bind(group)
        .bind(number)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some(bytes) => {
                let cid = Cid::try_from(bytes.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok(Some(cid))
            }
        }
    }

    /// Return all `(group_name, article_number, cid)` rows across all groups.
    ///
    /// Used for startup backfill of the overview index.
    pub async fn list_all_articles(&self) -> Result<Vec<(String, u64, Cid)>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            group_name: String,
            article_number: i64,
            cid: Vec<u8>,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT group_name, article_number, cid FROM article_numbers ORDER BY group_name, article_number",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let cid = Cid::try_from(row.cid.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok((row.group_name, row.article_number as u64, cid))
            })
            .collect()
    }

    /// Return all distinct group names that have at least one article,
    /// with their `(group_name, low, high)` article number ranges.
    ///
    /// Used by `LIST ACTIVE` to enumerate every group the server carries.
    pub async fn list_groups(&self) -> Result<Vec<(String, u64, u64)>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            group_name: String,
            low: i64,
            high: i64,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT group_name, \
                    MIN(article_number) AS low, \
                    MAX(article_number) AS high \
             FROM article_numbers \
             GROUP BY group_name \
             ORDER BY group_name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.group_name, r.low as u64, r.high as u64))
            .collect())
    }

    /// Return the `(low, high)` article number range for a group.
    ///
    /// Batch-lookup CIDs for a slice of article numbers in one query.
    ///
    /// Returns a `HashMap<article_number, CID>` containing only the numbers that
    /// were found. Numbers not in the store are silently absent from the map.
    /// Replaces N sequential `lookup_cid` calls with a single IN-clause query.
    pub async fn lookup_cids_batch(
        &self,
        group: &str,
        numbers: &[u64],
    ) -> Result<std::collections::HashMap<u64, Cid>, sqlx::Error> {
        if numbers.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let mut qb = sqlx::QueryBuilder::new(
            "SELECT article_number, cid FROM article_numbers WHERE group_name = ",
        );
        qb.push_bind(group);
        qb.push(" AND article_number IN (");
        let mut sep = qb.separated(", ");
        for &n in numbers {
            sep.push_bind(n as i64);
        }
        sep.push_unseparated(")");

        let rows: Vec<(i64, Vec<u8>)> = qb.build_query_as().fetch_all(&self.pool).await?;
        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for (num, cid_bytes) in rows {
            let cid = Cid::try_from(cid_bytes.as_slice())
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
            map.insert(num as u64, cid);
        }
        Ok(map)
    }

    /// Reverse-lookup the group name and article number for a given CID.
    ///
    /// Used by SearchSnippet/get to map email IDs (CID strings) back to
    /// their overview-store location without loading all articles into memory.
    pub async fn lookup_by_cid(&self, cid: &Cid) -> Result<Option<(String, u64)>, sqlx::Error> {
        let cid_bytes = cid.to_bytes();

        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT group_name, article_number FROM article_numbers WHERE cid = ? LIMIT 1",
        )
        .bind(cid_bytes)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(g, n)| (g, n as u64)))
    }

    /// Return the smallest article number in `group` that is strictly greater
    /// than `current`.  Returns `None` when `current` is already the last article.
    ///
    /// Used by the NEXT command handler to advance the article pointer.
    pub async fn next_after(
        &self,
        group: &str,
        current: u64,
    ) -> Result<Option<(u64, Cid)>, sqlx::Error> {
        let current = current as i64;
        let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT article_number, cid FROM article_numbers \
             WHERE group_name = ? AND article_number > ? \
             ORDER BY article_number ASC LIMIT 1",
        )
        .bind(group)
        .bind(current)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((n, cid_bytes)) => {
                let cid = Cid::try_from(cid_bytes.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok(Some((n as u64, cid)))
            }
        }
    }

    /// Return the largest article number in `group` that is strictly less than
    /// `current`.  Returns `None` when `current` is already the first article.
    ///
    /// Used by the LAST command handler to retreat the article pointer.
    pub async fn prev_before(
        &self,
        group: &str,
        current: u64,
    ) -> Result<Option<(u64, Cid)>, sqlx::Error> {
        let current = current as i64;
        let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT article_number, cid FROM article_numbers \
             WHERE group_name = ? AND article_number < ? \
             ORDER BY article_number DESC LIMIT 1",
        )
        .bind(group)
        .bind(current)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((n, cid_bytes)) => {
                let cid = Cid::try_from(cid_bytes.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok(Some((n as u64, cid)))
            }
        }
    }

    /// Returns `(1, 0)` for an empty group (RFC 3977 convention: `low > high`
    /// means empty).
    pub async fn group_range(&self, group: &str) -> Result<(u64, u64), sqlx::Error> {
        let row: (Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT MIN(article_number), MAX(article_number) FROM article_numbers WHERE group_name = ?",
        )
        .bind(group)
        .fetch_one(&self.pool)
        .await?;

        match row {
            (Some(lo), Some(hi)) => Ok((lo as u64, hi as u64)),
            // No rows for this group — return the RFC 3977 empty sentinel.
            _ => Ok((1, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    async fn make_store() -> (ArticleNumberStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (ArticleNumberStore::new(pool), tmp)
    }

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(data))
    }

    #[tokio::test]
    async fn assign_sequential() {
        let (store, _tmp) = make_store().await;

        let n1 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-1"))
            .await
            .unwrap();
        let n2 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-2"))
            .await
            .unwrap();
        let n3 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-3"))
            .await
            .unwrap();

        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
        assert_eq!(n3, 3);
    }

    #[tokio::test]
    async fn assign_idempotent() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"idempotent-article");

        let first = store.assign_number("comp.lang.rust", &cid).await.unwrap();
        let second = store.assign_number("comp.lang.rust", &cid).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(first, 1);
    }

    #[tokio::test]
    async fn lookup_cid() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"lookup-article");

        let number = store.assign_number("comp.lang.rust", &cid).await.unwrap();
        let found = store.lookup_cid("comp.lang.rust", number).await.unwrap();

        assert_eq!(found, Some(cid));
    }

    #[tokio::test]
    async fn lookup_missing() {
        let (store, _tmp) = make_store().await;

        let found = store.lookup_cid("comp.lang.rust", 9999).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn group_range_empty() {
        let (store, _tmp) = make_store().await;

        let (lo, hi) = store.group_range("comp.lang.rust").await.unwrap();
        assert_eq!((lo, hi), (1, 0));
    }

    #[tokio::test]
    async fn group_range_after_inserts() {
        let (store, _tmp) = make_store().await;

        store
            .assign_number("comp.lang.rust", &test_cid(b"r1"))
            .await
            .unwrap();
        store
            .assign_number("comp.lang.rust", &test_cid(b"r2"))
            .await
            .unwrap();
        store
            .assign_number("comp.lang.rust", &test_cid(b"r3"))
            .await
            .unwrap();

        let (lo, hi) = store.group_range("comp.lang.rust").await.unwrap();
        assert_eq!((lo, hi), (1, 3));
    }

    #[tokio::test]
    async fn multi_group_isolation() {
        let (store, _tmp) = make_store().await;

        let a1 = store
            .assign_number("comp.lang.rust", &test_cid(b"rust-1"))
            .await
            .unwrap();
        let b1 = store
            .assign_number("alt.test", &test_cid(b"test-1"))
            .await
            .unwrap();
        let a2 = store
            .assign_number("comp.lang.rust", &test_cid(b"rust-2"))
            .await
            .unwrap();
        let b2 = store
            .assign_number("alt.test", &test_cid(b"test-2"))
            .await
            .unwrap();

        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(b1, 1);
        assert_eq!(b2, 2);
    }
}
