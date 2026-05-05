//! `OracleMailStore` — stub implementation of [`MailStore`] for Oracle (OCI).
//!
//! All methods return `Err(sqlx::Error::Protocol("not implemented".into()))`.
//! This stub exists to:
//! 1. Prove the [`MailStore`] trait boundary is sufficient for an Oracle integration.
//! 2. Document the full required surface for an Oracle implementer.
//!
//! # Oracle integration notes
//!
//! Oracle is not supported by `sqlx` (no Oracle driver exists in the `sqlx`
//! ecosystem as of 2026).  A real `OracleMailStore` would use:
//! - The `oracle` crate (Rust OCI bindings via `libclntsh`) or
//! - An ODBC bridge (`odbc-api` crate)
//!
//! Key dialect differences to be aware of:
//! - `INSERT OR IGNORE` → `INSERT INTO … WHERE NOT EXISTS (…)` or MERGE
//! - `ON CONFLICT … DO UPDATE` → MERGE statement
//! - `RETURNING` clause → Oracle supports it in 12c+
//! - `?` bind placeholders → `:1`, `:2`, … in OCI
//! - `AUTOINCREMENT` → Oracle sequences / `GENERATED ALWAYS AS IDENTITY`
//! - `BOOLEAN` columns → Oracle uses `NUMBER(1)` or char `'Y'`/`'N'`
//!
//! A full Oracle implementation is deferred until a concrete customer
//! requirement exists.  Track progress under epic stoa-jom01.

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

/// Stub Oracle implementation — all methods return `Err(not_implemented)`.
pub struct OracleMailStore;

fn not_implemented() -> sqlx::Error {
    sqlx::Error::Protocol("OracleMailStore: not implemented".into())
}

#[async_trait]
impl UserStore for OracleMailStore {
    async fn resolve_user_id(&self, _username: &str) -> Result<Option<i64>, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl BearerTokenStore for OracleMailStore {
    async fn issue_token(
        &self,
        _username: &str,
        _label: Option<String>,
        _expires_in_days: Option<i64>,
    ) -> Result<(String, String, Option<i64>), sqlx::Error> {
        Err(not_implemented())
    }

    async fn verify_token(&self, _raw: &str) -> Result<Option<String>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_tokens(&self, _username: &str) -> Result<Vec<TokenInfo>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn revoke_token(&self, _username: &str, _id: &str) -> Result<bool, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl SubscriptionStore for OracleMailStore {
    async fn subscribe(&self, _user_id: i64, _group: &str) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn unsubscribe(&self, _user_id: i64, _group: &str) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_subscribed(&self, _user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn is_subscribed(&self, _user_id: i64, _group: &str) -> Result<bool, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl FlagsStore for OracleMailStore {
    async fn set_flags(
        &self,
        _user_id: i64,
        _cid: &Cid,
        _seen: bool,
        _flagged: bool,
    ) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn get_flags(&self, _user_id: i64, _cid: &Cid) -> Result<Option<Flags>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_cids_with_flag(
        &self,
        _user_id: i64,
        _seen: Option<bool>,
        _flagged: Option<bool>,
    ) -> Result<Vec<Cid>, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl StateVersionStore for OracleMailStore {
    async fn get_state(&self, _user_id: i64, _scope: &str) -> Result<String, sqlx::Error> {
        Err(not_implemented())
    }

    async fn bump_state(&self, _user_id: i64, _scope: &str) -> Result<String, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl ChangeLogStore for OracleMailStore {
    async fn record_created(
        &self,
        _user_id: i64,
        _scope: &str,
        _ids: &[String],
        _seq: i64,
    ) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn record_updated(
        &self,
        _user_id: i64,
        _scope: &str,
        _ids: &[String],
        _seq: i64,
    ) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn record_destroyed(
        &self,
        _user_id: i64,
        _scope: &str,
        _ids: &[String],
        _seq: i64,
    ) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn query_since(
        &self,
        _user_id: i64,
        _scope: &str,
        _since_seq: i64,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl MailboxProvisionStore for OracleMailStore {
    async fn provision_mailboxes(&self) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_mailboxes(&self) -> Result<Vec<SpecialMailbox>, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl SmtpMessageStore for OracleMailStore {
    async fn mailbox_exists(&self, _id: &str) -> Result<bool, sqlx::Error> {
        Err(not_implemented())
    }

    async fn count_messages_in_mailbox(&self, _id: &str) -> Result<i64, sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_message_ids_in_mailbox(
        &self,
        _id: &str,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<i64>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn fetch_smtp_messages_batch(
        &self,
        _row_ids: &[i64],
    ) -> Result<Vec<(i64, Vec<u8>, String, String)>, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl FollowerStore for OracleMailStore {
    async fn add_follower(
        &self,
        _group: &str,
        _actor: &str,
        _inbox: &str,
    ) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn remove_follower(&self, _group: &str, _actor: &str) -> Result<(), sqlx::Error> {
        Err(not_implemented())
    }

    async fn list_followers(&self, _group: &str) -> Result<Vec<Follower>, sqlx::Error> {
        Err(not_implemented())
    }

    async fn is_follower(&self, _group: &str, _actor: &str) -> Result<bool, sqlx::Error> {
        Err(not_implemented())
    }
}

#[async_trait]
impl ReceivedActivityStore for OracleMailStore {
    async fn record_if_new(&self, _activity_id: &str) -> Result<bool, sqlx::Error> {
        Err(not_implemented())
    }
}

// Compile-time check: OracleMailStore must implement every sub-trait that
// makes up MailStore.  If a new sub-trait is added to MailStore but its impl
// is omitted here, this line will produce a clear "OracleMailStore does not
// implement <NewTrait>" error rather than a distant blanket-impl failure.
const _: fn() = || {
    fn assert_mail_store<T: super::MailStore + Send + Sync>() {}
    assert_mail_store::<OracleMailStore>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oracle_store_returns_not_implemented() {
        let store = OracleMailStore;
        let err = store.resolve_user_id("alice").await.unwrap_err();
        assert!(
            err.to_string().contains("not implemented"),
            "unexpected error: {err}"
        );
    }
}
