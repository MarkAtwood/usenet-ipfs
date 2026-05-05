//! Per-user article flags: `\Seen` and `\Flagged` (JMAP keywords).
//!
//! # Why `user_id` is retained in this table
//!
//! The i5ay simplification dropped `user_id` from the mailbox *storage* tables
//! (`mailboxes`, `messages`) because those tables hold message content that is
//! shared across all users in a single-user deployment.  Read/flag state is
//! per-user *preference*, not storage, so `user_id` belongs here.
//!
//! In v1, `user_id = 1` is always used (single-user model).  Retaining the
//! column means future multi-user support requires no schema migration — only a
//! new caller convention.

use cid::Cid;

/// Per-user article flags: `\Seen` and `\Flagged` (JMAP keywords).
#[derive(Debug, Clone, PartialEq)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
}

pub struct UserFlagsStore {
    pool: sqlx::AnyPool,
}

impl UserFlagsStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Set \Seen and \Flagged for (user_id, cid). Creates the row if absent.
    pub async fn set_flags(
        &self,
        user_id: i64,
        cid: &Cid,
        seen: bool,
        flagged: bool,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        sqlx::query(
            "INSERT INTO user_flags (user_id, article_cid, seen, flagged)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id, article_cid) DO UPDATE SET seen = ?, flagged = ?",
        )
        .bind(user_id)
        .bind(&cid_bytes)
        .bind(seen as i64)
        .bind(flagged as i64)
        .bind(seen as i64)
        .bind(flagged as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get flags for (user_id, cid). Returns None if no row exists (all flags default to false).
    pub async fn get_flags(&self, user_id: i64, cid: &Cid) -> Result<Option<Flags>, sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT seen, flagged FROM user_flags WHERE user_id = ? AND article_cid = ?",
        )
        .bind(user_id)
        .bind(&cid_bytes)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(seen, flagged)| Flags {
            seen: seen != 0,
            flagged: flagged != 0,
        }))
    }

    /// Return all CIDs that match a given flag for a user.
    /// Used for listing unseen/flagged articles.
    pub async fn list_cids_with_flag(
        &self,
        user_id: i64,
        seen: Option<bool>,
        flagged: Option<bool>,
    ) -> Result<Vec<Cid>, sqlx::Error> {
        let rows: Vec<Vec<u8>> = match (seen, flagged) {
            (None, None) => {
                sqlx::query_scalar("SELECT article_cid FROM user_flags WHERE user_id = ?")
                    .bind(user_id)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Some(s), None) => {
                sqlx::query_scalar(
                    "SELECT article_cid FROM user_flags WHERE user_id = ? AND seen = ?",
                )
                .bind(user_id)
                .bind(s as i64)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(f)) => {
                sqlx::query_scalar(
                    "SELECT article_cid FROM user_flags WHERE user_id = ? AND flagged = ?",
                )
                .bind(user_id)
                .bind(f as i64)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(s), Some(f)) => sqlx::query_scalar(
                "SELECT article_cid FROM user_flags WHERE user_id = ? AND seen = ? AND flagged = ?",
            )
            .bind(user_id)
            .bind(s as i64)
            .bind(f as i64)
            .fetch_all(&self.pool)
            .await?,
        };
        rows.into_iter()
            .map(|bytes| {
                Cid::try_from(bytes.as_slice()).map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl crate::store::FlagsStore for UserFlagsStore {
    async fn set_flags(
        &self,
        user_id: i64,
        cid: &cid::Cid,
        seen: bool,
        flagged: bool,
    ) -> Result<(), sqlx::Error> {
        self.set_flags(user_id, cid, seen, flagged).await
    }

    async fn get_flags(
        &self,
        user_id: i64,
        cid: &cid::Cid,
    ) -> Result<Option<crate::state::flags::Flags>, sqlx::Error> {
        self.get_flags(user_id, cid).await
    }

    async fn list_cids_with_flag(
        &self,
        user_id: i64,
        seen: Option<bool>,
        flagged: Option<bool>,
    ) -> Result<Vec<cid::Cid>, sqlx::Error> {
        self.list_cids_with_flag(user_id, seen, flagged).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn make_store() -> (UserFlagsStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .expect("insert user");
        (UserFlagsStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn get_flags_returns_none_for_unset() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"article-1");
        let flags = store.get_flags(1, &cid).await.unwrap();
        assert!(flags.is_none());
    }

    #[tokio::test]
    async fn set_and_get_flags() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"article-2");
        store.set_flags(1, &cid, true, false).await.unwrap();
        let flags = store.get_flags(1, &cid).await.unwrap().expect("must exist");
        assert!(flags.seen);
        assert!(!flags.flagged);
    }

    #[tokio::test]
    async fn toggle_seen_does_not_affect_flagged() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"article-3");
        store.set_flags(1, &cid, false, true).await.unwrap();
        store.set_flags(1, &cid, true, true).await.unwrap();
        let flags = store.get_flags(1, &cid).await.unwrap().expect("must exist");
        assert!(flags.seen);
        assert!(flags.flagged, "flagged must still be true");
    }

    #[tokio::test]
    async fn list_cids_with_seen_flag() {
        let (store, _tmp) = make_store().await;
        let c1 = test_cid(b"seen-article");
        let c2 = test_cid(b"unseen-article");
        store.set_flags(1, &c1, true, false).await.unwrap();
        store.set_flags(1, &c2, false, false).await.unwrap();
        let seen_cids = store
            .list_cids_with_flag(1, Some(true), None)
            .await
            .unwrap();
        assert_eq!(seen_cids.len(), 1);
        assert_eq!(seen_cids[0], c1);
    }
}
