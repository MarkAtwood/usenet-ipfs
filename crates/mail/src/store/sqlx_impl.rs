//! `SqlxMailStore` — sqlx-backed implementation of all [`MailStore`] sub-traits.
//!
//! Holds an `Arc<sqlx::AnyPool>` and delegates to the concrete store structs
//! that already live in `state/`, `token_store`, `mailbox/provision`, and
//! `activitypub/`.  All SQL remains inside those concrete structs; this module
//! wires them together behind the trait boundary.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cid::Cid;

use crate::{
    activitypub::follower_store::Follower, mailbox::types::SpecialMailbox, state::flags::Flags,
    token_store::TokenInfo,
};

use super::{
    BearerTokenStore, ChangeLogStore, FlagsStore, FollowerStore, MailboxProvisionStore,
    ReceivedActivityStore, SmtpMessageStore, StateVersionStore, SubscriptionStore, UserStore,
};

/// sqlx-backed implementation of every `MailStore` sub-trait.
pub struct SqlxMailStore {
    pool: Arc<sqlx::AnyPool>,
    token_store: crate::token_store::TokenStore,
    subscription_store: crate::state::subscriptions::SubscriptionStore,
    flags_store: crate::state::flags::UserFlagsStore,
    state_store: crate::state::version::StateStore,
    change_log: crate::state::change_log::ChangeLogStore,
    follower_store: crate::activitypub::follower_store::FollowerStore,
}

impl SqlxMailStore {
    /// Create a new `SqlxMailStore` wrapping `pool`.
    pub fn new(pool: Arc<sqlx::AnyPool>) -> Self {
        let p = (*pool).clone();
        Self {
            pool: Arc::clone(&pool),
            token_store: crate::token_store::TokenStore::new(Arc::clone(&pool)),
            subscription_store: crate::state::subscriptions::SubscriptionStore::new(p.clone()),
            flags_store: crate::state::flags::UserFlagsStore::new(p.clone()),
            state_store: crate::state::version::StateStore::new(p.clone()),
            change_log: crate::state::change_log::ChangeLogStore::new(p.clone()),
            follower_store: crate::activitypub::follower_store::FollowerStore::new(p),
        }
    }
}

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

/// Singleton user_id used when no explicit row exists for the principal.
const SINGLETON_USER_ID: i64 = 1;

#[async_trait]
impl UserStore for SqlxMailStore {
    async fn resolve_user_id(&self, username: &str) -> Result<Option<i64>, sqlx::Error> {
        match sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(self.pool.as_ref())
            .await?
        {
            Some(id) => Ok(Some(id)),
            // Demo/single-user fallback: any unknown username maps to user 1.
            None => Ok(Some(SINGLETON_USER_ID)),
        }
    }
}

// ---------------------------------------------------------------------------
// BearerTokenStore
// ---------------------------------------------------------------------------

#[async_trait]
impl BearerTokenStore for SqlxMailStore {
    async fn issue_token(
        &self,
        username: &str,
        label: Option<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, String, Option<i64>), sqlx::Error> {
        self.token_store
            .issue(username, label, expires_in_days)
            .await
    }

    async fn verify_token(&self, raw_token_b64url: &str) -> Result<Option<String>, sqlx::Error> {
        self.token_store.verify(raw_token_b64url).await
    }

    async fn list_tokens(&self, username: &str) -> Result<Vec<TokenInfo>, sqlx::Error> {
        self.token_store.list(username).await
    }

    async fn revoke_token(&self, username: &str, token_id: &str) -> Result<bool, sqlx::Error> {
        self.token_store.revoke(username, token_id).await
    }
}

// ---------------------------------------------------------------------------
// SubscriptionStore
// ---------------------------------------------------------------------------

#[async_trait]
impl SubscriptionStore for SqlxMailStore {
    async fn subscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        self.subscription_store.subscribe(user_id, group_name).await
    }

    async fn unsubscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        self.subscription_store
            .unsubscribe(user_id, group_name)
            .await
    }

    async fn list_subscribed(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        self.subscription_store.list_subscribed(user_id).await
    }

    async fn is_subscribed(&self, user_id: i64, group_name: &str) -> Result<bool, sqlx::Error> {
        self.subscription_store
            .is_subscribed(user_id, group_name)
            .await
    }
}

// ---------------------------------------------------------------------------
// FlagsStore
// ---------------------------------------------------------------------------

#[async_trait]
impl FlagsStore for SqlxMailStore {
    async fn set_flags(
        &self,
        user_id: i64,
        cid: &Cid,
        seen: bool,
        flagged: bool,
    ) -> Result<(), sqlx::Error> {
        self.flags_store
            .set_flags(user_id, cid, seen, flagged)
            .await
    }

    async fn get_flags(&self, user_id: i64, cid: &Cid) -> Result<Option<Flags>, sqlx::Error> {
        self.flags_store.get_flags(user_id, cid).await
    }

    async fn list_cids_with_flag(
        &self,
        user_id: i64,
        seen: Option<bool>,
        flagged: Option<bool>,
    ) -> Result<Vec<Cid>, sqlx::Error> {
        self.flags_store
            .list_cids_with_flag(user_id, seen, flagged)
            .await
    }
}

// ---------------------------------------------------------------------------
// StateVersionStore
// ---------------------------------------------------------------------------

#[async_trait]
impl StateVersionStore for SqlxMailStore {
    async fn get_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error> {
        self.state_store.get_state(user_id, scope).await
    }

    async fn bump_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error> {
        self.state_store.bump_state(user_id, scope).await
    }
}

// ---------------------------------------------------------------------------
// ChangeLogStore
// ---------------------------------------------------------------------------

#[async_trait]
impl ChangeLogStore for SqlxMailStore {
    async fn record_created(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.change_log
            .record_created(user_id, scope, item_ids, seq)
            .await
    }

    async fn record_updated(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.change_log
            .record_updated(user_id, scope, item_ids, seq)
            .await
    }

    async fn record_destroyed(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        self.change_log
            .record_destroyed(user_id, scope, item_ids, seq)
            .await
    }

    async fn query_since(
        &self,
        user_id: i64,
        scope: &str,
        since_seq: i64,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), sqlx::Error> {
        self.change_log.query_since(user_id, scope, since_seq).await
    }
}

// ---------------------------------------------------------------------------
// MailboxProvisionStore
// ---------------------------------------------------------------------------

#[async_trait]
impl MailboxProvisionStore for SqlxMailStore {
    async fn provision_mailboxes(&self) -> Result<(), sqlx::Error> {
        crate::mailbox::provision::provision_mailboxes(&self.pool).await
    }

    async fn list_mailboxes(&self) -> Result<Vec<SpecialMailbox>, sqlx::Error> {
        crate::mailbox::provision::list_mailboxes(&self.pool).await
    }
}

// ---------------------------------------------------------------------------
// SmtpMessageStore
// ---------------------------------------------------------------------------

#[async_trait]
impl SmtpMessageStore for SqlxMailStore {
    async fn mailbox_exists(&self, mailbox_id: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM mailboxes WHERE mailbox_id = ?)")
            .bind(mailbox_id)
            .fetch_one(self.pool.as_ref())
            .await
    }

    async fn count_messages_in_mailbox(&self, mailbox_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?")
            .bind(mailbox_id)
            .fetch_one(self.pool.as_ref())
            .await
    }

    async fn list_message_ids_in_mailbox(
        &self,
        mailbox_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, sqlx::Error> {
        sqlx::query_scalar::<_, i64>(
            "SELECT id FROM messages WHERE mailbox_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(mailbox_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.as_ref())
        .await
    }

    async fn fetch_smtp_messages_batch(
        &self,
        row_ids: &[i64],
    ) -> Result<Vec<(i64, Vec<u8>, String, String)>, sqlx::Error> {
        if row_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: sqlx::QueryBuilder<sqlx::Any> = sqlx::QueryBuilder::new(
            "SELECT id, raw_message, mailbox_id, received_at FROM messages WHERE id IN (",
        );
        let mut sep = qb.separated(", ");
        for rid in row_ids {
            sep.push_bind(*rid);
        }
        sep.push_unseparated(")");
        qb.build_query_as::<(i64, Vec<u8>, String, String)>()
            .fetch_all(self.pool.as_ref())
            .await
    }
}

// ---------------------------------------------------------------------------
// FollowerStore
// ---------------------------------------------------------------------------

#[async_trait]
impl FollowerStore for SqlxMailStore {
    async fn add_follower(
        &self,
        group_name: &str,
        actor_url: &str,
        inbox_url: &str,
    ) -> Result<(), sqlx::Error> {
        self.follower_store
            .add(group_name, actor_url, inbox_url)
            .await
    }

    async fn remove_follower(&self, group_name: &str, actor_url: &str) -> Result<(), sqlx::Error> {
        self.follower_store.remove(group_name, actor_url).await
    }

    async fn list_followers(&self, group_name: &str) -> Result<Vec<Follower>, sqlx::Error> {
        self.follower_store.list(group_name).await
    }

    async fn is_follower(&self, group_name: &str, actor_url: &str) -> Result<bool, sqlx::Error> {
        self.follower_store.is_follower(group_name, actor_url).await
    }
}

// ---------------------------------------------------------------------------
// ReceivedActivityStore
// ---------------------------------------------------------------------------

#[async_trait]
impl ReceivedActivityStore for SqlxMailStore {
    async fn record_if_new(&self, activity_id: &str) -> Result<bool, sqlx::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let rows_affected = sqlx::query(
            "INSERT OR IGNORE INTO activitypub_received (activity_id, received_at) VALUES (?, ?)",
        )
        .bind(activity_id)
        .bind(now)
        .execute(self.pool.as_ref())
        .await?
        .rows_affected();
        Ok(rows_affected > 0)
    }
}
