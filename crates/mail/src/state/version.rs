/// Manages JMAP opaque state strings per scope (e.g. "Mailbox", "Email").
///
/// State strings are monotonically increasing version numbers encoded as decimal strings.
pub struct StateStore {
    pool: sqlx::AnyPool,
}

impl StateStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Return the current state string for a scope.
    /// Returns "0" if the scope has never been written.
    pub async fn get_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error> {
        let version: Option<i64> =
            sqlx::query_scalar("SELECT version FROM state_version WHERE user_id = ? AND scope = ?")
                .bind(user_id)
                .bind(scope)
                .fetch_optional(&self.pool)
                .await?;
        Ok(version.unwrap_or(0).to_string())
    }

    /// Increment the version for a scope and return the new state string.
    ///
    /// Uses a single `INSERT … RETURNING` so the read is atomic with the write,
    /// eliminating the TOCTOU window that existed when a separate SELECT followed
    /// the INSERT.
    pub async fn bump_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error> {
        let (version,): (i64,) = sqlx::query_as(
            "INSERT INTO state_version (user_id, scope, version) VALUES (?, ?, 1)
             ON CONFLICT(user_id, scope) DO UPDATE SET version = version + 1
             RETURNING version",
        )
        .bind(user_id)
        .bind(scope)
        .fetch_one(&self.pool)
        .await?;
        Ok(version.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (StateStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (StateStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn initial_state_is_zero() {
        let (store, _tmp) = make_store().await;
        let state = store.get_state(1, "Mailbox").await.unwrap();
        assert_eq!(state, "0");
    }

    #[tokio::test]
    async fn bump_increments_state() {
        let (store, _tmp) = make_store().await;
        let s1 = store.bump_state(1, "Email").await.unwrap();
        let s2 = store.bump_state(1, "Email").await.unwrap();
        assert_ne!(s1, s2, "state must change after bump");
        assert!(!s1.is_empty());
        assert!(!s2.is_empty());
    }

    #[tokio::test]
    async fn different_scopes_are_independent() {
        let (store, _tmp) = make_store().await;
        store.bump_state(1, "Mailbox").await.unwrap();
        let email_state = store.get_state(1, "Email").await.unwrap();
        assert_eq!(email_state, "0", "Email scope must be independent");
    }

    #[tokio::test]
    async fn different_users_are_independent() {
        let (store, _tmp) = make_store().await;
        store.bump_state(1, "Email").await.unwrap();
        let state_u2 = store.get_state(2, "Email").await.unwrap();
        assert_eq!(state_u2, "0", "user 2 must have its own independent state");
    }
}
