//! Manages per-user newsgroup subscriptions.
//!
//! # Why `user_id` is retained in this table
//!
//! The i5ay simplification dropped `user_id` from the mailbox *storage* tables
//! (`mailboxes`, `messages`) because those tables hold message content that is
//! shared across all users in a single-user deployment.  Subscriptions are
//! per-user *preferences*, not storage, so `user_id` belongs here.
//!
//! In v1, `user_id = 1` is always used (single-user model).  Retaining the
//! column means future multi-user support requires no schema migration — only a
//! new caller convention.

/// Manages per-user newsgroup subscriptions.
pub struct SubscriptionStore {
    pool: sqlx::AnyPool,
}

impl SubscriptionStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Subscribe a user to a group (idempotent).
    pub async fn subscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO subscriptions (user_id, group_name, subscribed_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id, group_name) DO NOTHING",
        )
        .bind(user_id)
        .bind(group_name)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Unsubscribe a user from a group (idempotent).
    pub async fn unsubscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM subscriptions WHERE user_id = ? AND group_name = ?")
            .bind(user_id)
            .bind(group_name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Return all group names a user is subscribed to.
    pub async fn list_subscribed(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT group_name FROM subscriptions WHERE user_id = ? ORDER BY group_name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    /// Check whether a user is subscribed to a specific group.
    pub async fn is_subscribed(&self, user_id: i64, group_name: &str) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscriptions WHERE user_id = ? AND group_name = ?",
        )
        .bind(user_id)
        .bind(group_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }
}

#[async_trait::async_trait]
impl crate::store::SubscriptionStore for SubscriptionStore {
    async fn subscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        self.subscribe(user_id, group_name).await
    }

    async fn unsubscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        self.unsubscribe(user_id, group_name).await
    }

    async fn list_subscribed(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        self.list_subscribed(user_id).await
    }

    async fn is_subscribed(&self, user_id: i64, group_name: &str) -> Result<bool, sqlx::Error> {
        self.is_subscribed(user_id, group_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (SubscriptionStore, tempfile::TempPath) {
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
        (SubscriptionStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn subscribe_and_list() {
        let (store, _tmp) = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.subscribe(1, "alt.test").await.unwrap();
        let subs = store.list_subscribed(1).await.unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&"comp.lang.rust".to_string()));
        assert!(subs.contains(&"alt.test".to_string()));
    }

    #[tokio::test]
    async fn subscribe_idempotent() {
        let (store, _tmp) = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.subscribe(1, "comp.lang.rust").await.unwrap(); // must not error
        let subs = store.list_subscribed(1).await.unwrap();
        assert_eq!(subs.len(), 1);
    }

    #[tokio::test]
    async fn unsubscribe_removes() {
        let (store, _tmp) = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.unsubscribe(1, "comp.lang.rust").await.unwrap();
        let subs = store.list_subscribed(1).await.unwrap();
        assert!(subs.is_empty());
    }

    #[tokio::test]
    async fn is_subscribed_check() {
        let (store, _tmp) = make_store().await;
        assert!(!store.is_subscribed(1, "comp.lang.rust").await.unwrap());
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        assert!(store.is_subscribed(1, "comp.lang.rust").await.unwrap());
    }
}
