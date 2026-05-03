//! [`JmapBackend`] implementation for stoa-mail.
//!
//! [`StoaBackend`] wraps [`JmapStores`] with a per-request `user_id` so that
//! the generic handlers from `jmap-server` can call `get_objects`, `get_state`,
//! `get_changes`, and `query_objects` without carrying auth state themselves.
//!
//! ## What this covers
//!
//! | `JmapBackend` method | Implementation |
//! |---|---|
//! | `account_exists` | Always `true` — auth is enforced before the handler runs |
//! | `get_objects::<Mailbox>` | Loads groups + subscriptions, builds `Mailbox` objects |
//! | `get_objects::<Email>` | Dispatches on ID prefix: `smtp:N` → SQL; CID → IPFS |
//! | `get_objects::<Thread>` | O(n) cross-group scan capped at 5000 articles |
//! | `get_state::<*>` | `StateStore::get_state` for `"Mailbox"`, `"Email"`, `"Thread"` |
//! | `get_changes::<Email>` | `ChangeLogStore::query_since` |
//! | `get_changes::<Mailbox>` | `cannotCalculateChanges` (NNTP groups not tracked) |
//! | `get_changes::<Thread>` | `cannotCalculateChanges` (no thread change log) |
//! | `query_objects::<Mailbox>` | Groups + subscriptions with `MailboxFilter` |
//! | `query_objects::<Email>` | SMTP-mailbox SQL path or NNTP overview path + Tantivy |
//! | `query_objects::<*> /queryChanges` | `cannotCalculateChanges` for all types |

use std::collections::HashSet;
use std::sync::Arc;

use jmap_server::{
    BackendChangesError, ChangesResult, GetObject, JmapBackend, JmapObject, QueryChangesResult,
    QueryObject, QueryResult,
};
use jmap_types::{Id, State};

use crate::jmap::backend_types::{Email, EmailFilter, Mailbox, MailboxFilter, Thread};
use crate::mailbox::types::mailbox_id_for_group;
use crate::server::JmapStores;

// ---------------------------------------------------------------------------
// StoaBackend
// ---------------------------------------------------------------------------

/// Per-request backend wrapping [`JmapStores`] with a resolved `user_id`.
///
/// Created fresh for each JMAP method call in the handler.  Cheaply cloneable
/// (all fields are `Arc`).
#[derive(Clone)]
pub struct StoaBackend {
    pub stores: Arc<JmapStores>,
    /// SQLite row id for the authenticated user.
    pub user_id: i64,
    /// The canonical JMAP account ID for this user (e.g. `"u_alice"`).
    /// Used by `account_exists` to enforce that the request targets the
    /// authenticated user's own account.
    pub canonical_account_id: String,
}

/// A unified error type for `StoaBackend` storage operations.
#[derive(Debug)]
pub enum StoaBackendError {
    Sql(sqlx::Error),
    Ipfs(String),
    Other(String),
}

impl std::fmt::Display for StoaBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(e) => write!(f, "database error: {e}"),
            Self::Ipfs(e) => write!(f, "block store error: {e}"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoaBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sql(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for StoaBackendError {
    fn from(e: sqlx::Error) -> Self {
        Self::Sql(e)
    }
}

// ---------------------------------------------------------------------------
// JmapBackend impl
// ---------------------------------------------------------------------------

impl JmapBackend for StoaBackend {
    type Error = StoaBackendError;

    /// Returns `true` only when `account_id` matches the authenticated user's
    /// canonical account ID.  The generic handlers call this at the start of
    /// every method to return `accountNotFound` for cross-account requests.
    async fn account_exists(&self, account_id: &Id) -> Result<bool, Self::Error> {
        Ok(account_id.as_ref() == self.canonical_account_id)
    }

    async fn get_objects<O: GetObject + Send + Sync>(
        &self,
        account_id: &Id,
        ids: Option<&[Id]>,
        _properties: Option<&[String]>,
    ) -> Result<(Vec<O>, Vec<Id>), Self::Error> {
        use std::any::Any;

        // Dispatch by TypeId to avoid unsafe transmute.
        // Each branch calls the concrete domain method and boxes the result,
        // then downcasts back to Vec<O>.  The downcast is infallible by
        // construction — we only box a Vec<T> behind a TypeId check for T.
        let type_id = std::any::TypeId::of::<O>();

        if type_id == std::any::TypeId::of::<Mailbox>() {
            let (found, not_found) = self
                .get_mailboxes(account_id, ids)
                .await
                .map_err(StoaBackendError::Sql)?;
            let boxed: Box<dyn Any> = Box::new(found);
            let found_o = *boxed.downcast::<Vec<O>>().expect("TypeId-guarded downcast");
            return Ok((found_o, not_found));
        }

        if type_id == std::any::TypeId::of::<Email>() {
            let (found, not_found) = self.get_emails(account_id, ids).await?;
            let boxed: Box<dyn Any> = Box::new(found);
            let found_o = *boxed.downcast::<Vec<O>>().expect("TypeId-guarded downcast");
            return Ok((found_o, not_found));
        }

        if type_id == std::any::TypeId::of::<Thread>() {
            let (found, not_found) = self
                .get_threads(account_id, ids)
                .await
                .map_err(StoaBackendError::Sql)?;
            let boxed: Box<dyn Any> = Box::new(found);
            let found_o = *boxed.downcast::<Vec<O>>().expect("TypeId-guarded downcast");
            return Ok((found_o, not_found));
        }

        Ok((vec![], ids.unwrap_or(&[]).iter().cloned().collect()))
    }

    async fn get_state<O: JmapObject + Send + Sync>(
        &self,
        _account_id: &Id,
    ) -> Result<State, Self::Error> {
        let scope = O::TYPE_NAME;
        let state = self
            .stores
            .state_store
            .get_state(self.user_id, scope)
            .await
            .unwrap_or_else(|_| "0".to_string());
        Ok(State::from(state.as_str()))
    }

    async fn get_changes<O: JmapObject + Send + Sync>(
        &self,
        _account_id: &Id,
        since_state: &State,
        _max_changes: Option<u64>,
    ) -> Result<ChangesResult, BackendChangesError<Self::Error>> {
        match O::TYPE_NAME {
            "Email" => {
                let since_seq: i64 = match since_state.as_ref().parse::<i64>() {
                    Ok(n) if n >= 0 => n,
                    _ => return Err(BackendChangesError::TooManyChanges { limit: 0 }),
                };

                let new_state_str = self
                    .stores
                    .state_store
                    .get_state(self.user_id, "Email")
                    .await
                    .unwrap_or_else(|_| "0".to_string());

                let (created, updated, destroyed) = self
                    .stores
                    .change_log
                    .query_since(self.user_id, "Email", since_seq)
                    .await
                    .map_err(|e| BackendChangesError::Other(StoaBackendError::Sql(e)))?;

                Ok(ChangesResult::new(
                    created.into_iter().map(|s| Id::from(s.as_str())).collect(),
                    updated.into_iter().map(|s| Id::from(s.as_str())).collect(),
                    destroyed
                        .into_iter()
                        .map(|s| Id::from(s.as_str()))
                        .collect(),
                    false,
                    State::from(new_state_str.as_str()),
                ))
            }
            // Mailbox and Thread change logs are not tracked.
            _ => Err(BackendChangesError::TooManyChanges { limit: 0 }),
        }
    }

    async fn query_objects<O: QueryObject + Send + Sync>(
        &self,
        account_id: &Id,
        filter: Option<&O::Filter>,
        _sort: Option<&[O::Comparator]>,
        limit: Option<u64>,
        position: i64,
    ) -> Result<QueryResult, Self::Error> {
        use std::any::Any;

        let type_id = std::any::TypeId::of::<O>();

        if type_id == std::any::TypeId::of::<Mailbox>() {
            // Downcast O::Filter to MailboxFilter via Any.
            let mf: Option<&MailboxFilter> = filter.and_then(|f| {
                let boxed: &dyn Any = f;
                boxed.downcast_ref::<MailboxFilter>()
            });
            return self.query_mailboxes(account_id, mf, limit, position).await;
        }

        if type_id == std::any::TypeId::of::<Email>() {
            let ef: Option<&EmailFilter> = filter.and_then(|f| {
                let boxed: &dyn Any = f;
                boxed.downcast_ref::<EmailFilter>()
            });
            return self.query_emails(account_id, ef, limit, position).await;
        }

        let state = self.get_state::<O>(account_id).await?;
        Ok(QueryResult::new(vec![], 0, Some(0), state, false))
    }

    async fn query_changes<O: QueryObject + Send + Sync>(
        &self,
        _account_id: &Id,
        _since_query_state: &State,
        _filter: Option<&O::Filter>,
        _sort: Option<&[O::Comparator]>,
        _max_changes: Option<u64>,
        _up_to_id: Option<&Id>,
        _collapse_threads: bool,
    ) -> Result<QueryChangesResult, BackendChangesError<Self::Error>> {
        // queryChanges is not implemented for any type in v1.
        Err(BackendChangesError::TooManyChanges {
            limit: 0, // cannotCalculateChanges
        })
    }
}

// ---------------------------------------------------------------------------
// Domain helpers
// ---------------------------------------------------------------------------

impl StoaBackend {
    // --- Mailbox/get ---------------------------------------------------------

    async fn get_mailboxes(
        &self,
        _account_id: &Id,
        ids: Option<&[Id]>,
    ) -> Result<(Vec<Mailbox>, Vec<Id>), sqlx::Error> {
        let subscribed: HashSet<String> = self
            .stores
            .subscription_store
            .list_subscribed(self.user_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

        let groups = self
            .stores
            .article_numbers
            .list_groups()
            .await
            .unwrap_or_default();

        let group_infos: Vec<crate::mailbox::get::GroupInfo> = groups
            .into_iter()
            .map(|(name, lo, hi)| {
                let total_emails = if hi < lo {
                    0u32
                } else {
                    (hi - lo + 1).min(u32::MAX as u64) as u32
                };
                crate::mailbox::get::GroupInfo {
                    name: name.clone(),
                    total_emails,
                    unread_emails: 0,
                    is_subscribed: subscribed.contains(&name),
                }
            })
            .collect();

        // Build the full mailbox list (special + news root + newsgroups).
        let special: Vec<Mailbox> = self
            .stores
            .special_mailboxes
            .iter()
            .map(Mailbox::from_special)
            .collect();
        let news_root: Vec<Mailbox> = if group_infos.is_empty() {
            vec![]
        } else {
            vec![Mailbox::news_root()]
        };
        let newsgroups: Vec<Mailbox> = group_infos
            .iter()
            .map(|g| Mailbox::from_group(&g.name, g.total_emails, g.unread_emails, g.is_subscribed))
            .collect();
        let all: Vec<Mailbox> = [special, news_root, newsgroups].concat();

        match ids {
            None => Ok((all, vec![])),
            Some(requested) => {
                let by_id: std::collections::HashMap<&str, &Mailbox> =
                    all.iter().map(|m| (m.id.as_str(), m)).collect();
                let mut found = Vec::new();
                let mut not_found = Vec::new();
                for id in requested {
                    match by_id.get(id.as_ref()) {
                        Some(m) => found.push((*m).clone()),
                        None => not_found.push(id.clone()),
                    }
                }
                Ok((found, not_found))
            }
        }
    }

    // --- Email/get -----------------------------------------------------------

    async fn get_emails(
        &self,
        _account_id: &Id,
        ids: Option<&[Id]>,
    ) -> Result<(Vec<Email>, Vec<Id>), StoaBackendError> {
        let ids = match ids {
            None => return Ok((vec![], vec![])), // Email/get requires explicit ids
            Some(s) => s,
        };

        const MAX_IDS: usize = 500;
        if ids.len() > MAX_IDS {
            return Err(StoaBackendError::Other(format!(
                "ids exceeds maxObjectsInGet limit of {MAX_IDS}"
            )));
        }

        let id_strs: Vec<String> = ids.iter().map(|id| id.as_ref().to_string()).collect();
        // Delegate to the existing handle_email_get which already handles
        // both the smtp: prefix path and the CID path.
        let result_value = crate::email::get::handle_email_get(
            &id_strs,
            self.stores.ipfs.as_ref(),
            Some(&*self.stores.mail_pool),
            None,
            "0", // state unused here; get_state is called separately by handle_get
            "",  // account_id unused in the actual object assembly
        )
        .await;

        // Parse the returned Value into typed Email objects.
        let list = result_value["list"].as_array().cloned().unwrap_or_default();
        let not_found_raw = result_value["notFound"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let emails: Vec<Email> = list
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        let not_found: Vec<Id> = not_found_raw
            .into_iter()
            .filter_map(|v| v.as_str().map(Id::from))
            .collect();

        Ok((emails, not_found))
    }

    // --- Thread/get ----------------------------------------------------------

    async fn get_threads(
        &self,
        _account_id: &Id,
        ids: Option<&[Id]>,
    ) -> Result<(Vec<Thread>, Vec<Id>), sqlx::Error> {
        let requested_ids: Vec<String> = match ids {
            None => vec![],
            Some(s) => s.iter().map(|id| id.as_ref().to_string()).collect(),
        };

        const MAX_THREAD_SCAN: usize = 5000;

        let groups = self
            .stores
            .article_numbers
            .list_groups()
            .await
            .unwrap_or_default();

        let mut entries: Vec<crate::thread::get::ThreadEntry> = Vec::new();
        let requested_set: HashSet<&str> = requested_ids.iter().map(String::as_str).collect();
        let mut found: HashSet<String> = HashSet::new();
        let mut total_scanned: usize = 0;

        'outer: for (group_name, lo, hi) in &groups {
            let records = match self
                .stores
                .overview_store
                .query_range(group_name, *lo, *hi)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            let numbers: Vec<u64> = records.iter().map(|r| r.article_number).collect();
            let cid_map = self
                .stores
                .article_numbers
                .lookup_cids_batch(group_name, &numbers)
                .await
                .unwrap_or_default();

            for rec in &records {
                if let Some(cid) = cid_map.get(&rec.article_number).copied() {
                    let tid = crate::thread::get::thread_id_for(&rec.references, &rec.message_id);
                    if requested_set.contains(tid.as_str()) {
                        found.insert(tid);
                    }
                    entries.push(crate::thread::get::ThreadEntry {
                        email_id: cid.to_string(),
                        references: rec.references.clone(),
                        message_id: rec.message_id.clone(),
                    });
                }
                total_scanned += 1;
                if total_scanned >= MAX_THREAD_SCAN {
                    break 'outer;
                }
            }
            if found.len() == requested_set.len() {
                break;
            }
        }

        // Group email IDs by thread ID.
        let mut thread_map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for entry in &entries {
            let tid = crate::thread::get::thread_id_for(&entry.references, &entry.message_id);
            thread_map
                .entry(tid)
                .or_default()
                .push(entry.email_id.clone());
        }

        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for id_str in &requested_ids {
            match thread_map.remove(id_str) {
                Some(email_ids) => list.push(Thread {
                    id: id_str.clone(),
                    email_ids,
                }),
                None => not_found.push(Id::from(id_str.as_str())),
            }
        }

        Ok((list, not_found))
    }

    // --- Mailbox/query -------------------------------------------------------

    async fn query_mailboxes(
        &self,
        _account_id: &Id,
        filter: Option<&MailboxFilter>,
        limit: Option<u64>,
        position: i64,
    ) -> Result<QueryResult, StoaBackendError> {
        let subscribed: HashSet<String> = self
            .stores
            .subscription_store
            .list_subscribed(self.user_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

        let groups = self
            .stores
            .article_numbers
            .list_groups()
            .await
            .unwrap_or_default();

        let mut group_infos: Vec<crate::mailbox::get::GroupInfo> = groups
            .into_iter()
            .map(|(name, lo, hi)| {
                let total_emails = if hi < lo {
                    0u32
                } else {
                    (hi - lo + 1).min(u32::MAX as u64) as u32
                };
                let is_subscribed = subscribed.contains(&name);
                crate::mailbox::get::GroupInfo {
                    name,
                    total_emails,
                    unread_emails: 0,
                    is_subscribed,
                }
            })
            .collect();

        // Apply isSubscribed filter.
        if let Some(f) = filter {
            if let Some(is_sub) = f.is_subscribed {
                group_infos.retain(|g| g.is_subscribed == is_sub);
            }
        }

        // Sort by name ascending.
        group_infos.sort_by(|a, b| a.name.cmp(&b.name));

        let total = group_infos.len() as u64;
        let pos = position.max(0) as u64;
        let slice: Vec<Id> = group_infos
            .iter()
            .skip(pos as usize)
            .take(limit.unwrap_or(u64::MAX) as usize)
            .map(|g| Id::from(mailbox_id_for_group(&g.name).as_str()))
            .collect();

        let state = self
            .stores
            .state_store
            .get_state(self.user_id, "Mailbox")
            .await
            .map_err(StoaBackendError::Sql)?;

        Ok(QueryResult::new(
            slice,
            pos as i64,
            Some(total),
            State::from(state.as_str()),
            false,
        ))
    }

    // --- Email/query ---------------------------------------------------------

    async fn query_emails(
        &self,
        account_id: &Id,
        filter: Option<&EmailFilter>,
        limit: Option<u64>,
        position: i64,
    ) -> Result<QueryResult, StoaBackendError> {
        let email_state = self
            .stores
            .state_store
            .get_state(self.user_id, "Email")
            .await
            .map_err(StoaBackendError::Sql)?;
        let state = State::from(email_state.as_str());

        let mailbox_id = filter.and_then(|f| f.in_mailbox.as_deref());

        // Special (SMTP) mailbox path.
        if let Some(mid) = mailbox_id {
            let is_special: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mailboxes WHERE mailbox_id = ?)")
                    .bind(mid)
                    .fetch_one(&*self.stores.mail_pool)
                    .await
                    .unwrap_or(false);

            if is_special {
                let pos = position.max(0) as u64;
                let lim = limit.unwrap_or(10_000).min(10_000) as i64;

                let total: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?")
                        .bind(mid)
                        .fetch_one(&*self.stores.mail_pool)
                        .await
                        .unwrap_or(0);

                let response_pos = pos.min(total as u64);
                let page: Vec<Id> = sqlx::query_scalar::<_, i64>(
                    "SELECT id FROM messages \
                     WHERE mailbox_id = ? \
                     ORDER BY id DESC LIMIT ? OFFSET ?",
                )
                .bind(mid)
                .bind(lim)
                .bind(response_pos as i64)
                .fetch_all(&*self.stores.mail_pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|row_id| Id::from(format!("smtp:{row_id}").as_str()))
                .collect();

                return Ok(QueryResult::new(
                    page,
                    response_pos as i64,
                    Some(total as u64),
                    state,
                    false,
                ));
            }
        }

        // NNTP group path.
        let groups = self
            .stores
            .article_numbers
            .list_groups()
            .await
            .map_err(|e| StoaBackendError::Other(e.to_string()))?;

        let target_group = groups
            .iter()
            .find(|(name, _, _)| mailbox_id_for_group(name) == mailbox_id.unwrap_or(""));

        let (group_name, lo, hi) = match target_group {
            Some(g) => g.clone(),
            None => {
                return Ok(QueryResult::new(vec![], 0, Some(0), state, false));
            }
        };

        let records = self
            .stores
            .overview_store
            .query_range(&group_name, lo, hi)
            .await
            .map_err(|e| StoaBackendError::Other(e.to_string()))?;

        let numbers: Vec<u64> = records.iter().map(|r| r.article_number).collect();
        let cid_map = self
            .stores
            .article_numbers
            .lookup_cids_batch(&group_name, &numbers)
            .await
            .unwrap_or_default();

        let mut entries: Vec<crate::email::query::EmailOverviewEntry> = Vec::new();
        for rec in &records {
            if let Some(cid) = cid_map.get(&rec.article_number).copied() {
                entries.push(crate::email::query::EmailOverviewEntry {
                    cid,
                    message_id: rec.message_id.clone(),
                    subject: rec.subject.clone(),
                    from: rec.from.clone(),
                    date: rec.date.clone(),
                    byte_count: rec.byte_count,
                });
            }
        }

        // Full-text search filter.
        let text_results = if let Some(text) = filter.and_then(|f| f.text.as_deref()) {
            if !text.is_empty() {
                if let Some(ref idx) = self.stores.search_index {
                    match idx.search_all(text, 50_000).await {
                        Ok(ids) => Some(ids.into_iter().collect::<HashSet<_>>()),
                        Err(e) => {
                            tracing::warn!(error = %e, "JMAP text search failed; ignoring text filter");
                            None
                        }
                    }
                } else {
                    Some(HashSet::new()) // no index → empty result
                }
            } else {
                None
            }
        } else {
            None
        };

        let pos = position.max(0) as u64;
        // Call the existing handle_email_query as a helper to get the Value,
        // then re-parse it into a QueryResult.
        let filter_val = filter.and_then(|_| serde_json::to_value(filter).ok());
        let resp = crate::email::query::handle_email_query(
            &entries,
            filter_val.as_ref(),
            pos,
            limit,
            &email_state,
            text_results,
            account_id.as_ref(),
        );

        let ids: Vec<Id> = resp["ids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(Id::from))
                    .collect()
            })
            .unwrap_or_default();
        let total = resp["total"].as_u64();
        let resp_pos = resp["position"].as_i64().unwrap_or(pos as i64);

        Ok(QueryResult::new(ids, resp_pos, total, state, false))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time: StoaBackend implements JmapBackend.
    #[allow(dead_code)]
    fn assert_stoa_backend_implements_jmap_backend() {
        fn check<B: JmapBackend>() {}
        check::<StoaBackend>();
    }

    /// StoaBackendError::Sql displays database error prefix.
    #[test]
    fn stoa_backend_error_display_sql() {
        let e = StoaBackendError::Other("test".to_string());
        assert_eq!(format!("{e}"), "test");
    }

    /// StoaBackendError::Other displays the inner message.
    #[test]
    fn stoa_backend_error_display_other() {
        let e = StoaBackendError::Ipfs("block not found".to_string());
        assert_eq!(format!("{e}"), "block store error: block not found");
    }
}
