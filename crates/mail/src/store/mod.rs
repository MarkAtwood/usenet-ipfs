//! `MailStore` trait and sub-traits — the database abstraction boundary for stoa-mail.
//!
//! All SQL is concentrated in [`SqlxMailStore`] which implements every sub-trait
//! by delegating to the concrete store structs in `state/`, `token_store`, etc.
//! Business logic receives `Arc<dyn MailStore + Send + Sync>` and calls methods
//! through the trait, with no knowledge of the underlying driver.
//!
//! # Sub-traits
//!
//! | Trait | Domain |
//! |---|---|
//! | [`UserStore`] | Resolve username → user_id |
//! | [`BearerTokenStore`] | Issue, verify, list, revoke bearer tokens |
//! | [`SubscriptionStore`] | Per-user newsgroup subscriptions |
//! | [`FlagsStore`] | Per-user article flags (`\Seen`, `\Flagged`) |
//! | [`StateVersionStore`] | JMAP opaque state strings (monotonic version) |
//! | [`ChangeLogStore`] | JMAP change log for incremental sync |
//! | [`MailboxProvisionStore`] | Special-use mailbox provisioning |
//! | [`SmtpMessageStore`] | SMTP-delivered message queries |
//! | [`FollowerStore`] | ActivityPub group followers |
//! | [`ReceivedActivityStore`] | ActivityPub deduplication |
//! | [`MailStore`] | Supertrait combining all of the above |
//!
//! # Oracle note
//!
//! An `OracleMailStore` stub lives in [`oracle`] — it compiles but all methods
//! return `Err(not_implemented)`.  It exists to prove the trait boundary is
//! sufficient for an Oracle integration and to document the required surface.

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;

use crate::{
    activitypub::follower_store::Follower, mailbox::types::SpecialMailbox, state::flags::Flags,
    token_store::TokenInfo,
};

pub mod oracle;
pub mod sqlx_impl;

pub use sqlx_impl::SqlxMailStore;

// ---------------------------------------------------------------------------
// Sub-traits
// ---------------------------------------------------------------------------

/// Resolve a username to its database `user_id`.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Look up `username` in the `users` table.
    ///
    /// Returns `Some(user_id)` if found.  Returns `Some(SINGLETON_USER_ID)` when
    /// the table has no row for the username (demo / single-user fallback).
    /// Returns `Err` only for database failures.
    async fn resolve_user_id(&self, username: &str) -> Result<Option<i64>, sqlx::Error>;
}

/// Issue, verify, list, and revoke bearer tokens.
#[async_trait]
pub trait BearerTokenStore: Send + Sync {
    /// Issue a new bearer token for `username`.
    ///
    /// Returns `(raw_token_base64url, id, expires_at_unix_secs)`.
    async fn issue_token(
        &self,
        username: &str,
        label: Option<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, String, Option<i64>), sqlx::Error>;

    /// Verify a raw base64url-encoded token.
    ///
    /// Returns `Some(username)` if valid and unexpired; `Ok(None)` otherwise.
    async fn verify_token(&self, raw_token_b64url: &str) -> Result<Option<String>, sqlx::Error>;

    /// List all tokens for `username` (without raw values or hashes).
    async fn list_tokens(&self, username: &str) -> Result<Vec<TokenInfo>, sqlx::Error>;

    /// Revoke the token with `token_id` owned by `username`.
    ///
    /// Returns `true` if deleted, `false` if not found or wrong owner.
    async fn revoke_token(&self, username: &str, token_id: &str) -> Result<bool, sqlx::Error>;
}

/// Per-user newsgroup subscriptions.
#[async_trait]
pub trait SubscriptionStore: Send + Sync {
    /// Subscribe `user_id` to `group_name` (idempotent).
    async fn subscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error>;

    /// Unsubscribe `user_id` from `group_name` (idempotent).
    async fn unsubscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error>;

    /// Return all group names `user_id` is subscribed to.
    async fn list_subscribed(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error>;

    /// Return `true` if `user_id` is subscribed to `group_name`.
    async fn is_subscribed(&self, user_id: i64, group_name: &str) -> Result<bool, sqlx::Error>;
}

/// Per-user article flags (`\Seen`, `\Flagged`).
#[async_trait]
pub trait FlagsStore: Send + Sync {
    /// Set `\Seen` and `\Flagged` for `(user_id, cid)`.  Creates row if absent.
    async fn set_flags(
        &self,
        user_id: i64,
        cid: &Cid,
        seen: bool,
        flagged: bool,
    ) -> Result<(), sqlx::Error>;

    /// Get flags for `(user_id, cid)`.  Returns `None` if no row exists.
    async fn get_flags(&self, user_id: i64, cid: &Cid) -> Result<Option<Flags>, sqlx::Error>;

    /// Return CIDs matching the given flag values for `user_id`.
    async fn list_cids_with_flag(
        &self,
        user_id: i64,
        seen: Option<bool>,
        flagged: Option<bool>,
    ) -> Result<Vec<Cid>, sqlx::Error>;
}

/// JMAP opaque state strings (monotonically increasing version numbers).
#[async_trait]
pub trait StateVersionStore: Send + Sync {
    /// Return the current state string for `(user_id, scope)`.
    /// Returns `"0"` if the scope has never been written.
    async fn get_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error>;

    /// Atomically increment the version for `(user_id, scope)` and return the new state string.
    async fn bump_state(&self, user_id: i64, scope: &str) -> Result<String, sqlx::Error>;
}

/// JMAP change log for incremental sync (`/changes` methods).
#[async_trait]
pub trait ChangeLogStore: Send + Sync {
    /// Record a batch of created item IDs at `seq`.
    async fn record_created(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error>;

    /// Record a batch of updated item IDs at `seq`.
    async fn record_updated(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error>;

    /// Record a batch of destroyed item IDs at `seq`.
    async fn record_destroyed(
        &self,
        user_id: i64,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error>;

    /// Return `(created, updated, destroyed)` item ID lists for `(user_id, scope)` since `since_seq`.
    async fn query_since(
        &self,
        user_id: i64,
        scope: &str,
        since_seq: i64,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), sqlx::Error>;
}

/// Special-use mailbox provisioning (RFC 6154 roles: Inbox, Sent, Drafts, …).
#[async_trait]
pub trait MailboxProvisionStore: Send + Sync {
    /// Create the six RFC 6154 special-use mailboxes if they don't exist (idempotent).
    async fn provision_mailboxes(&self) -> Result<(), sqlx::Error>;

    /// Return the provisioned special-use mailboxes ordered by `sort_order`.
    async fn list_mailboxes(&self) -> Result<Vec<SpecialMailbox>, sqlx::Error>;
}

/// SMTP-delivered message queries (special-mailbox path in JMAP Email).
#[async_trait]
pub trait SmtpMessageStore: Send + Sync {
    /// Return `true` if a mailbox with `mailbox_id` exists in the `mailboxes` table.
    async fn mailbox_exists(&self, mailbox_id: &str) -> Result<bool, sqlx::Error>;

    /// Count messages in `mailbox_id`.
    async fn count_messages_in_mailbox(&self, mailbox_id: &str) -> Result<i64, sqlx::Error>;

    /// Return a page of message IDs from `mailbox_id`, ordered by `id DESC`.
    async fn list_message_ids_in_mailbox(
        &self,
        mailbox_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, sqlx::Error>;

    /// Batch-fetch SMTP emails by row ID.  Missing IDs are silently omitted.
    ///
    /// Returns `Vec<(row_id, raw_message, mailbox_id, received_at)>`.
    async fn fetch_smtp_messages_batch(
        &self,
        row_ids: &[i64],
    ) -> Result<Vec<(i64, Vec<u8>, String, String)>, sqlx::Error>;
}

/// ActivityPub group followers.
#[async_trait]
pub trait FollowerStore: Send + Sync {
    /// Add or update a follower for `group_name`.
    async fn add_follower(
        &self,
        group_name: &str,
        actor_url: &str,
        inbox_url: &str,
    ) -> Result<(), sqlx::Error>;

    /// Remove a follower from `group_name`.
    async fn remove_follower(&self, group_name: &str, actor_url: &str) -> Result<(), sqlx::Error>;

    /// List all followers for `group_name`.
    async fn list_followers(&self, group_name: &str) -> Result<Vec<Follower>, sqlx::Error>;

    /// Return `true` if `actor_url` follows `group_name`.
    async fn is_follower(&self, group_name: &str, actor_url: &str) -> Result<bool, sqlx::Error>;
}

/// ActivityPub inbound deduplication: records received activity IDs.
#[async_trait]
pub trait ReceivedActivityStore: Send + Sync {
    /// Record `activity_id` if new.  Returns `true` if new, `false` if duplicate.
    async fn record_if_new(&self, activity_id: &str) -> Result<bool, sqlx::Error>;
}

// ---------------------------------------------------------------------------
// Supertrait
// ---------------------------------------------------------------------------

/// Combined database abstraction for stoa-mail.
///
/// Business logic should accept `Arc<dyn MailStore + Send + Sync>` and call
/// methods from the sub-traits.  `SqlxMailStore` is the production
/// implementation; `OracleMailStore` is a stub for Oracle.
pub trait MailStore:
    UserStore
    + BearerTokenStore
    + SubscriptionStore
    + FlagsStore
    + StateVersionStore
    + ChangeLogStore
    + MailboxProvisionStore
    + SmtpMessageStore
    + FollowerStore
    + ReceivedActivityStore
    + Send
    + Sync
{
}

/// Blanket impl: any type implementing all sub-traits automatically implements `MailStore`.
impl<T> MailStore for T where
    T: UserStore
        + BearerTokenStore
        + SubscriptionStore
        + FlagsStore
        + StateVersionStore
        + ChangeLogStore
        + MailboxProvisionStore
        + SmtpMessageStore
        + FollowerStore
        + ReceivedActivityStore
        + Send
        + Sync
{
}

// ---------------------------------------------------------------------------
// Helper: build a SqlxMailStore wrapped in Arc<dyn MailStore>
// ---------------------------------------------------------------------------

/// Construct a `SqlxMailStore` from `pool` and return it as `Arc<dyn MailStore + Send + Sync>`.
pub fn new_sqlx_mail_store(pool: Arc<sqlx::AnyPool>) -> Arc<dyn MailStore + Send + Sync> {
    Arc::new(SqlxMailStore::new(pool))
}
