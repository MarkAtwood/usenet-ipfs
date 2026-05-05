//! JMAP Mailbox/set handler — newsgroup subscription management.
//!
//! Creating a Mailbox whose name matches a newsgroup pattern (contains a dot,
//! no spaces) subscribes the authenticated user to that group.
//!
//! Destroying a Mailbox by its JMAP id unsubscribes the user from the
//! corresponding group.  The destroy path requires looking up the group name
//! from the article-number store (using the same mailbox_id_for_group mapping
//! used at read time).

use serde_json::{json, Value};

use stoa_core::article::GroupName;

use crate::{mailbox::types::mailbox_id_for_group, store::SubscriptionStore};
use stoa_reader::store::article_numbers::ArticleNumberStore;

/// Returns `true` when `name` is a valid newsgroup name.
///
/// Requires at least one dot (newsgroup names are hierarchical) and delegates
/// full character-level validation to `GroupName::new` for consistency with
/// the rest of the stack.
fn is_newsgroup_name(name: &str) -> bool {
    name.contains('.') && GroupName::new(name).is_ok()
}

/// Handle a Mailbox/set request.
///
/// Supported operations:
/// - `create`: subscribe to newsgroup-named mailboxes
/// - `destroy`: unsubscribe from the corresponding group
///
/// `user_id` is the authenticated user's database row id (currently hardcoded
/// to 1 everywhere pending multi-user state resolution).
pub async fn handle_mailbox_set(
    args: &Value,
    user_id: i64,
    subscription_store: &dyn SubscriptionStore,
    article_numbers: &ArticleNumberStore,
    old_state: &str,
    new_state: &str,
) -> Value {
    let mut created: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_created: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut destroyed: Vec<String> = Vec::new();
    let mut not_destroyed: serde_json::Map<String, Value> = serde_json::Map::new();

    // ── create ──────────────────────────────────────────────────────────────
    if let Some(create_map) = args.get("create").and_then(|v| v.as_object()) {
        for (client_id, props) in create_map {
            let name = match props.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => {
                    not_created.insert(
                        client_id.clone(),
                        json!({"type": "invalidArguments", "description": "name is required"}),
                    );
                    continue;
                }
            };
            if !is_newsgroup_name(name) {
                not_created.insert(
                    client_id.clone(),
                    json!({
                        "type": "invalidArguments",
                        "description": "name must be a newsgroup name (must contain a dot and no whitespace)"
                    }),
                );
                continue;
            }
            match subscription_store.subscribe(user_id, name).await {
                Ok(()) => {
                    let id = mailbox_id_for_group(name);
                    created.insert(client_id.clone(), json!({ "id": id }));
                }
                Err(e) => {
                    not_created.insert(
                        client_id.clone(),
                        json!({"type": "serverFail", "description": e.to_string()}),
                    );
                }
            }
        }
    }

    // ── destroy ─────────────────────────────────────────────────────────────
    if let Some(destroy_arr) = args.get("destroy").and_then(|v| v.as_array()) {
        // Build id→group_name reverse map from known groups.
        let groups = article_numbers.list_groups().await.unwrap_or_default();
        let id_to_name: std::collections::HashMap<String, String> = groups
            .iter()
            .map(|(name, _, _)| (mailbox_id_for_group(name), name.clone()))
            .collect();

        for id_val in destroy_arr {
            let id = match id_val.as_str() {
                Some(s) => s,
                None => {
                    // Non-string IDs are invalid; report them in notDestroyed.
                    not_destroyed.insert(
                        id_val.to_string(),
                        json!({"type": "invalidArguments", "description": "id must be a string"}),
                    );
                    continue;
                }
            };
            match id_to_name.get(id) {
                Some(group_name) => {
                    match subscription_store.unsubscribe(user_id, group_name).await {
                        Ok(()) => destroyed.push(id.to_string()),
                        Err(e) => {
                            not_destroyed.insert(
                                id.to_string(),
                                json!({"type": "serverFail", "description": e.to_string()}),
                            );
                        }
                    }
                }
                None => {
                    not_destroyed.insert(id.to_string(), json!({"type": "notFound"}));
                }
            }
        }
    }

    json!({
        "oldState": old_state,
        "newState": new_state,
        "created": created,
        "notCreated": not_created,
        "updated": null,
        "notUpdated": {},
        "destroyed": destroyed,
        "notDestroyed": not_destroyed
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::subscriptions::SubscriptionStore as ConcreteSubscriptionStore;
    use std::sync::Arc;
    use stoa_reader::store::article_numbers::ArticleNumberStore;

    async fn make_stores() -> (
        ConcreteSubscriptionStore,
        Arc<ArticleNumberStore>,
        Vec<tempfile::TempPath>,
    ) {
        let mut tmps = Vec::new();

        // Mail DB for subscriptions.
        let mail_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mail_url = format!("sqlite://{}", mail_tmp.to_str().unwrap());
        crate::migrations::run_migrations(&mail_url)
            .await
            .expect("mail migrations");
        let mail_pool = stoa_core::db_pool::try_open_any_pool(&mail_url, 1)
            .await
            .expect("mail pool");
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&mail_pool)
            .await
            .expect("insert test user");
        tmps.push(mail_tmp);

        // Reader DB for article_numbers.
        let reader_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let reader_url = format!("sqlite://{}", reader_tmp.to_str().unwrap());
        stoa_reader::migrations::run_migrations(&reader_url)
            .await
            .expect("reader migrations");
        let reader_pool = stoa_core::db_pool::try_open_any_pool(&reader_url, 1)
            .await
            .expect("reader pool");
        tmps.push(reader_tmp);

        (
            ConcreteSubscriptionStore::new(mail_pool),
            Arc::new(ArticleNumberStore::new(reader_pool)),
            tmps,
        )
    }

    #[tokio::test]
    async fn create_newsgroup_subscribes() {
        let (sub_store, article_numbers, _tmps) = make_stores().await;
        let args = serde_json::json!({
            "create": {
                "c1": { "name": "comp.lang.rust" }
            }
        });
        let result = handle_mailbox_set(&args, 1, &sub_store, &article_numbers, "0", "0").await;
        assert!(
            result["created"]["c1"]["id"].is_string(),
            "must return id: {result}"
        );
        assert!(
            sub_store.is_subscribed(1, "comp.lang.rust").await.unwrap(),
            "must be subscribed after create"
        );
    }

    #[tokio::test]
    async fn create_non_newsgroup_is_invalid() {
        let (sub_store, article_numbers, _tmps) = make_stores().await;
        let args = serde_json::json!({
            "create": {
                "c1": { "name": "Inbox" }
            }
        });
        let result = handle_mailbox_set(&args, 1, &sub_store, &article_numbers, "0", "0").await;
        assert!(
            result["notCreated"]["c1"].is_object(),
            "Inbox must be rejected: {result}"
        );
        assert_eq!(result["notCreated"]["c1"]["type"], "invalidArguments");
    }

    #[tokio::test]
    async fn create_missing_name_is_invalid() {
        let (sub_store, article_numbers, _tmps) = make_stores().await;
        let args = serde_json::json!({
            "create": {
                "c1": {}
            }
        });
        let result = handle_mailbox_set(&args, 1, &sub_store, &article_numbers, "0", "0").await;
        assert!(
            result["notCreated"]["c1"].is_object(),
            "missing name must be rejected: {result}"
        );
    }
}
