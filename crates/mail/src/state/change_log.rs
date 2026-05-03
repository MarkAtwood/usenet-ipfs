//! JMAP change log for incremental sync (`/changes` methods).
//!
//! Populated by `Email/set` when articles are created, keywords are updated,
//! or items are destroyed.  `Email/changes` and `Mailbox/changes` query this
//! table to return deltas.

use sqlx::AnyPool;

/// Store for the JMAP change log.
pub struct ChangeLogStore {
    pool: AnyPool,
}

impl ChangeLogStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Record a batch of item IDs under the given `change` action at `seq`.
    ///
    /// `change` must be one of `"created"`, `"updated"`, or `"destroyed"`.
    async fn record_action(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
        change: &str,
    ) -> Result<(), sqlx::Error> {
        if item_ids.is_empty() {
            return Ok(());
        }
        let mut qb: sqlx::QueryBuilder<sqlx::Any> = sqlx::QueryBuilder::new(
            "INSERT OR IGNORE INTO jmap_change_log (user_id, seq, scope, item_id, change) ",
        );
        qb.push_values(item_ids.iter(), |mut b, id| {
            b.push_bind(user_id)
                .push_bind(seq)
                .push_bind(scope)
                .push_bind(id.as_str())
                .push_bind(change);
        });
        qb.build().execute(&self.pool).await?;
        Ok(())
    }

    /// Record a batch of created item IDs at the given state version.
    ///
    /// `user_id` scopes the log entry to the owning user.
    /// `scope` is `"Email"` or `"Mailbox"`.
    /// `seq` is the new state version returned by `StateStore::bump_state`.
    pub async fn record_created(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.record_action(user_id, scope, item_ids, seq, "created")
            .await
    }

    /// Record a batch of updated item IDs at the given state version.
    ///
    /// Called when keyword flags are changed via `Email/set`.
    pub async fn record_updated(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.record_action(user_id, scope, item_ids, seq, "updated")
            .await
    }

    /// Record a batch of destroyed item IDs at the given state version.
    pub async fn record_destroyed(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.record_action(user_id, scope, item_ids, seq, "destroyed")
            .await
    }

    /// Return item IDs changed since `since_seq` for the given user and scope,
    /// split by action type.
    ///
    /// Returns `(created, updated, destroyed)` vecs, each ordered by `seq ASC`.
    pub async fn query_since(
        &self,
        user_id: i64,
        scope: &str,
        since_seq: i64,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), sqlx::Error> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT item_id, change FROM jmap_change_log \
             WHERE user_id = ? AND scope = ? AND seq > ? \
             ORDER BY seq ASC",
        )
        .bind(user_id)
        .bind(scope)
        .bind(since_seq)
        .fetch_all(&self.pool)
        .await?;

        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut destroyed = Vec::new();
        for (id, change) in rows {
            match change.as_str() {
                "created" => created.push(id),
                "updated" => updated.push(id),
                "destroyed" => destroyed.push(id),
                _ => {}
            }
        }
        Ok((created, updated, destroyed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (ChangeLogStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (ChangeLogStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn query_since_returns_created_items_after_seq() {
        let (store, _tmp) = make_store().await;
        store
            .record_created(1, "Email", &["cid1".to_string(), "cid2".to_string()], 1)
            .await
            .unwrap();
        store
            .record_created(1, "Email", &["cid3".to_string()], 2)
            .await
            .unwrap();

        let (created, updated, destroyed) = store.query_since(1, "Email", 0).await.unwrap();
        assert_eq!(created.len(), 3);
        assert!(updated.is_empty());
        assert!(destroyed.is_empty());

        let (created, _, _) = store.query_since(1, "Email", 1).await.unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0], "cid3");

        let (created, _, _) = store.query_since(1, "Email", 2).await.unwrap();
        assert!(created.is_empty());
    }

    #[tokio::test]
    async fn query_since_returns_updated_and_destroyed() {
        let (store, _tmp) = make_store().await;
        store
            .record_created(1, "Email", &["cid1".to_string()], 1)
            .await
            .unwrap();
        store
            .record_updated(1, "Email", &["cid1".to_string()], 2)
            .await
            .unwrap();
        store
            .record_destroyed(1, "Email", &["cid2".to_string()], 3)
            .await
            .unwrap();

        let (created, updated, destroyed) = store.query_since(1, "Email", 0).await.unwrap();
        assert_eq!(created, vec!["cid1"]);
        assert_eq!(updated, vec!["cid1"]);
        assert_eq!(destroyed, vec!["cid2"]);

        // Since seq=1: only the updated and destroyed entries are visible.
        let (created, updated, destroyed) = store.query_since(1, "Email", 1).await.unwrap();
        assert!(created.is_empty());
        assert_eq!(updated, vec!["cid1"]);
        assert_eq!(destroyed, vec!["cid2"]);
    }

    #[tokio::test]
    async fn query_since_is_scope_isolated() {
        let (store, _tmp) = make_store().await;
        store
            .record_created(1, "Email", &["email1".to_string()], 1)
            .await
            .unwrap();
        store
            .record_created(1, "Mailbox", &["mbox1".to_string()], 1)
            .await
            .unwrap();

        let (email_created, _, _) = store.query_since(1, "Email", 0).await.unwrap();
        assert_eq!(email_created, vec!["email1"]);

        let (mbox_created, _, _) = store.query_since(1, "Mailbox", 0).await.unwrap();
        assert_eq!(mbox_created, vec!["mbox1"]);
    }

    #[tokio::test]
    async fn query_since_is_user_isolated() {
        let (store, _tmp) = make_store().await;
        store
            .record_created(1, "Email", &["alice_cid".to_string()], 1)
            .await
            .unwrap();
        store
            .record_created(2, "Email", &["bob_cid".to_string()], 1)
            .await
            .unwrap();

        let (alice_created, _, _) = store.query_since(1, "Email", 0).await.unwrap();
        assert_eq!(
            alice_created,
            vec!["alice_cid"],
            "alice must not see bob's mail"
        );

        let (bob_created, _, _) = store.query_since(2, "Email", 0).await.unwrap();
        assert_eq!(
            bob_created,
            vec!["bob_cid"],
            "bob must not see alice's mail"
        );
    }
}
