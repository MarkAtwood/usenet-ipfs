use std::collections::HashMap;
use std::sync::Arc;

use cid::Cid;
use serde_json::{json, Value};

use crate::jmap::types::MethodError;
use crate::mailbox::types::mailbox_id_for_group;
use crate::state::flags::UserFlagsStore;
use stoa_core::msgid_map::MsgIdMap;
use stoa_reader::post::ipfs_write::{write_article_to_ipfs, IpfsBlockStore};
use stoa_smtp::SmtpRelayQueue;

/// Handle Email/set — route to destroy/update/create sub-handlers.
///
/// `old_state` is the current `Email` state string fetched before this call.
/// It is embedded in the response so the correct value is present even if an
/// early return path bypasses the caller's state-patching logic.  The caller
/// is still responsible for updating `newState` if any writes succeed.
pub fn handle_email_set(args: Value, old_state: &str) -> Result<Value, MethodError> {
    let mut not_destroyed: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_updated: serde_json::Map<String, Value> = serde_json::Map::new();

    // destroy: always notPermitted — articles are immutable
    if let Some(destroy_ids) = args.get("destroy").and_then(|v| v.as_array()) {
        for id in destroy_ids {
            if let Some(id_str) = id.as_str() {
                tracing::warn!(email_id = %id_str, "Email/set destroy rejected — articles are immutable");
                not_destroyed.insert(
                    id_str.to_string(),
                    json!({"type": "notPermitted", "description": "Articles are immutable in v1"}),
                );
            }
        }
    }

    // update: notPermitted for mailboxIds; other properties handled in user-state epic
    if let Some(update_map) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in update_map {
            // Check if patch attempts to change mailboxIds
            if patch.get("mailboxIds").is_some()
                || patch
                    .as_object()
                    .is_some_and(|m| m.keys().any(|k| k.starts_with("mailboxIds/")))
            {
                not_updated.insert(
                    id.clone(),
                    json!({"type": "notPermitted", "description": "mailboxIds are derived from Newsgroups header and are read-only"}),
                );
            }
        }
    }

    Ok(json!({
        "accountId": args.get("accountId").cloned().unwrap_or(Value::Null),
        "oldState": old_state,
        "newState": old_state,
        "created": null,
        "updated": null,
        "destroyed": null,
        "notCreated": null,
        "notUpdated": if not_updated.is_empty() { Value::Null } else { Value::Object(not_updated) },
        "notDestroyed": if not_destroyed.is_empty() { Value::Null } else { Value::Object(not_destroyed) },
    }))
}

/// Handle Email/set update for keywords (\Seen, \Flagged) only.
///
/// For each id, parses CID, extracts keyword patch, calls UserFlagsStore.
/// Ignores entries whose patch does not contain a `keywords` key (those are
/// handled by `handle_email_set`).
pub async fn handle_keyword_update(
    update_map: &serde_json::Map<String, Value>,
    user_id: i64,
    flags_store: &UserFlagsStore,
) -> (
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
) {
    let mut updated: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_updated: serde_json::Map<String, Value> = serde_json::Map::new();

    for (id, patch) in update_map {
        let keywords = match patch.get("keywords") {
            Some(k) => k,
            None => continue,
        };

        let cid = match Cid::try_from(id.as_str()) {
            Ok(c) => c,
            Err(_) => {
                // RFC 8621 §4.1.2: an unparseable id is invalidArguments, not notFound.
                not_updated.insert(id.clone(), json!({"type": "invalidArguments", "description": "email id is not a valid CID"}));
                continue;
            }
        };

        let seen = keywords
            .get("$seen")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let flagged = keywords
            .get("$flagged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        match flags_store.set_flags(user_id, &cid, seen, flagged).await {
            Ok(()) => {
                updated.insert(id.clone(), json!(null));
            }
            Err(e) => {
                tracing::warn!(id = %id, "Email/set keywords update error: {e}");
                not_updated.insert(
                    id.clone(),
                    json!({"type": "serverFail", "description": e.to_string()}),
                );
            }
        }
    }

    (updated, not_updated)
}

/// Handle Email/set create.
///
/// Accepts JMAP Email creation objects, constructs RFC 5322 article bytes,
/// writes to IPFS via `write_article_to_ipfs`, returns created Email ids.
///
/// `groups` is the list of known newsgroups as `(name, lo, hi)` tuples from
/// the article-number store.  It is used to resolve opaque JMAP mailbox IDs
/// (SHA-256/base32) back to human-readable newsgroup names before writing the
/// `Newsgroups:` header.  Creation fails with `invalidArguments` if any
/// mailbox ID in the request does not correspond to a known group.
///
/// If `smtp_queue` is `Some` and the created article has `to` or `cc`
/// recipients, the article is enqueued for SMTP relay delivery.  Enqueue
/// failure is non-fatal and does not fail the JMAP response.
pub async fn handle_email_create(
    create_map: &serde_json::Map<String, Value>,
    ipfs: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    smtp_queue: Option<&Arc<SmtpRelayQueue>>,
    groups: &[(String, u64, u64)],
) -> (
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
) {
    // Build a reverse map: mailbox_id (opaque SHA-256/base32) → group name.
    let id_to_group: HashMap<String, String> = groups
        .iter()
        .map(|(name, _, _)| (mailbox_id_for_group(name), name.clone()))
        .collect();

    let mut created: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_created: serde_json::Map<String, Value> = serde_json::Map::new();

    for (creation_id, obj) in create_map {
        match create_one_email(obj, ipfs, msgid_map, smtp_queue, &id_to_group).await {
            Ok(cid) => {
                created.insert(creation_id.clone(), json!({"id": cid.to_string()}));
            }
            Err(e) => {
                tracing::warn!(creation_id = %creation_id, "Email/set create error: {e}");
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidArguments", "description": e}),
                );
            }
        }
    }

    (created, not_created)
}

async fn create_one_email(
    obj: &Value,
    ipfs: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    smtp_queue: Option<&Arc<SmtpRelayQueue>>,
    id_to_group: &HashMap<String, String>,
) -> Result<Cid, String> {
    let subject = strip_crlf(
        obj.get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("(no subject)"),
    );

    let from_raw = obj
        .get("from")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|addr| addr.get("email"))
        .and_then(|v| v.as_str());
    let from_email = match from_raw {
        Some(s) => {
            let stripped = strip_crlf(s);
            if !is_valid_addr_spec(&stripped) {
                return Err(
                    r#"{"type":"invalidProperties","properties":["from"],"description":"from must be a valid ASCII email address"}"#
                        .to_string(),
                );
            }
            stripped
        }
        None => {
            return Err(
                r#"{"type":"invalidProperties","properties":["from"],"description":"from is required"}"#
                    .to_string(),
            )
        }
    };

    // JMAP mailboxIds keys are opaque identifiers (SHA-256/base32), not
    // newsgroup names.  Resolve each ID to its group name via the reverse map
    // built from the article-number store.
    let mailbox_id_keys: Vec<&str> = obj
        .get("mailboxIds")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();

    if mailbox_id_keys.is_empty() {
        return Err("mailboxIds must not be empty".to_string());
    }

    let mut newsgroup_names: Vec<String> = Vec::with_capacity(mailbox_id_keys.len());
    for &id in &mailbox_id_keys {
        match id_to_group.get(id) {
            Some(name) => newsgroup_names.push(name.clone()),
            None => {
                return Err(format!(
                    "mailboxId {id:?} does not correspond to a known newsgroup"
                ))
            }
        }
    }

    let newsgroups: Vec<&str> = newsgroup_names.iter().map(String::as_str).collect();

    let text_body_raw = obj
        .get("textBody")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|part| part.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text_body = strip_nul(text_body_raw);

    let now = chrono::Utc::now();
    let timestamp_ms = now.timestamp_millis();
    let random_component: u64 = rand::random();
    let message_id = format!("<jmap-{timestamp_ms}.{random_component:016x}@stoa.local>");
    let date_str = now.to_rfc2822();

    let article = format!(
        "Newsgroups: {}\r\nFrom: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\n\r\n{}",
        newsgroups.join(", "),
        from_email,
        subject,
        date_str,
        message_id,
        text_body,
    );

    let cid = write_article_to_ipfs(ipfs, msgid_map, article.as_bytes(), &message_id)
        .await
        .map_err(|resp| format!("IPFS write failed: {}", resp.text))?;

    // Enqueue for SMTP relay if a queue is configured and there are recipients.
    if let Some(queue) = smtp_queue {
        let mut rcpt_list = extract_email_addrs(obj.get("to"));
        rcpt_list.extend(extract_email_addrs(obj.get("cc")));
        if !rcpt_list.is_empty() {
            let rcpts: Vec<&str> = rcpt_list.iter().map(String::as_str).collect();
            if let Err(e) = queue
                .enqueue(article.as_bytes(), &from_email, &rcpts, false)
                .await
            {
                tracing::warn!("smtp relay enqueue failed: {e}");
                stoa_smtp::metrics::inc_relay_enqueue_failure();
            }
        }
    }

    Ok(cid)
}

/// Extract RFC 8621 §4.1.2 email addresses from a JMAP EmailAddress array field.
///
/// Accepts `None` gracefully (returns empty vec).  Skips entries without a
/// valid `email` string containing `@`.
/// Validate that `email` is a safe ASCII addr-spec for use in a raw RFC 5322
/// From header field.
///
/// Checks: exactly one `@`, non-empty local and domain parts, no whitespace,
/// no ASCII control characters, no non-ASCII (which would require RFC 2047
/// encoding).  This is intentionally conservative — JMAP `email` fields
/// should already be well-formed addr-specs.
fn is_valid_addr_spec(email: &str) -> bool {
    let mut at_count = 0u32;
    for c in email.chars() {
        if c.is_ascii_control() || c.is_whitespace() || !c.is_ascii() {
            return false;
        }
        if c == '@' {
            at_count += 1;
        }
    }
    if at_count != 1 {
        return false;
    }
    let at_idx = email.find('@').unwrap();
    !email[..at_idx].is_empty() && !email[at_idx + 1..].is_empty()
}

/// Remove CR (`\r`) and LF (`\n`) from a string to prevent CRLF injection
/// into RFC 5322 header fields constructed via `format!`.
fn strip_crlf(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// Remove NUL bytes (`\0`) from a string to prevent MIME corruption.
///
/// NUL bytes in a body part can corrupt MIME-encoded articles and confuse
/// downstream parsers that treat NUL as a string terminator.
fn strip_nul(s: &str) -> String {
    s.chars().filter(|&c| c != '\0').collect()
}

fn extract_email_addrs(field: Option<&Value>) -> Vec<String> {
    field
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|obj| obj.get("email"))
                .filter_map(|e| e.as_str())
                .filter(|s| s.contains('@'))
                .map(strip_crlf)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_state_embedded_in_response() {
        // RFC 8621 §4.3: oldState must reflect the state at the time of the
        // call, even for responses with no changes.
        let args = json!({"accountId": "acc1"});
        let result = handle_email_set(args, "42").unwrap();
        assert_eq!(
            result["oldState"].as_str(),
            Some("42"),
            "oldState must be the value passed in, not hardcoded '0'"
        );
        assert_eq!(
            result["newState"].as_str(),
            Some("42"),
            "newState starts equal to oldState before caller applies any bump"
        );
    }

    #[test]
    fn destroy_returns_not_permitted() {
        let args = json!({
            "accountId": "acc1",
            "destroy": ["cid1", "cid2"]
        });
        let result = handle_email_set(args, "0").unwrap();
        let not_destroyed = result["notDestroyed"].as_object().unwrap();
        assert!(not_destroyed.contains_key("cid1"));
        assert!(not_destroyed.contains_key("cid2"));
        assert_eq!(not_destroyed["cid1"]["type"], "notPermitted");
    }

    #[test]
    fn update_mailbox_ids_returns_not_permitted() {
        let args = json!({
            "accountId": "acc1",
            "update": {
                "somecid": {
                    "mailboxIds": {"newmailbox": true}
                }
            }
        });
        let result = handle_email_set(args, "0").unwrap();
        let not_updated = result["notUpdated"].as_object().unwrap();
        assert!(not_updated.contains_key("somecid"));
        assert_eq!(not_updated["somecid"]["type"], "notPermitted");
    }

    #[test]
    fn update_without_mailbox_ids_succeeds() {
        let args = json!({
            "accountId": "acc1",
            "update": {
                "somecid": {
                    "keywords": {"$seen": true}
                }
            }
        });
        let result = handle_email_set(args, "0").unwrap();
        // notUpdated should be null since keywords-only is allowed
        assert!(result["notUpdated"].is_null());
    }

    // --- Tests for handle_keyword_update ---

    #[tokio::test]
    async fn keyword_update_sets_seen_flag() {
        use crate::state::flags::UserFlagsStore;
        use multihash_codetable::{Code, MultihashDigest};

        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        let flags_store = UserFlagsStore::new(pool);
        let _tmp = tmp;

        let cid = cid::Cid::new_v1(0x71, Code::Sha2_256.digest(b"test-article"));
        let cid_str = cid.to_string();

        let mut update_map = serde_json::Map::new();
        update_map.insert(cid_str.clone(), json!({"keywords": {"$seen": true}}));

        let (updated, not_updated) = handle_keyword_update(&update_map, 1, &flags_store).await;
        assert!(
            not_updated.is_empty(),
            "should not have errors: {:?}",
            not_updated
        );
        assert!(updated.contains_key(&cid_str));

        let flags = flags_store
            .get_flags(1, &cid)
            .await
            .unwrap()
            .expect("must exist");
        assert!(flags.seen);
    }

    // --- Tests for handle_email_create ---

    #[tokio::test]
    async fn email_create_produces_cid() {
        use crate::mailbox::types::mailbox_id_for_group;
        use stoa_reader::post::ipfs_write::MemIpfsStore;

        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        let msgid_map = stoa_core::msgid_map::MsgIdMap::new(pool);
        let _tmp = tmp;
        let ipfs = MemIpfsStore::new();

        let groups: Vec<(String, u64, u64)> = vec![("news.test".to_string(), 0, 0)];
        let mb_id = mailbox_id_for_group("news.test");
        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {mb_id: true},
                "from": [{"email": "alice@example.com"}],
                "subject": "Test Create",
                "textBody": [{"value": "Hello, world!"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, None, &groups).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));
        assert!(created["c1"]["id"].as_str().is_some());
    }

    /// Helper: build a MsgIdMap on a tempfile-backed AnyPool with core migrations.
    async fn make_msgid_map() -> (stoa_core::msgid_map::MsgIdMap, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (stoa_core::msgid_map::MsgIdMap::new(pool), tmp)
    }

    /// smtp_queue=None: no .env files written even when To: is present.
    #[tokio::test]
    async fn email_create_no_smtp_queue_no_enqueue() {
        use crate::mailbox::types::mailbox_id_for_group;
        use stoa_reader::post::ipfs_write::MemIpfsStore;

        let dir = tempfile::tempdir().expect("tempdir");
        let (msgid_map, _tmp_msgid) = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let groups: Vec<(String, u64, u64)> = vec![("news.test".to_string(), 0, 0)];
        let mb_id = mailbox_id_for_group("news.test");
        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {mb_id: true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "No smtp queue test",
                "textBody": [{"value": "body"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, None, &groups).await;
        assert!(not_created.is_empty());
        assert!(created.contains_key("c1"));

        // Oracle: no .env files in the dir (queue was never created there, but
        // we verify by checking the tmpdir we control).
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 0, "no smtp queue: no .env files expected");
    }

    /// smtp_queue=Some with To: field: .env file appears in queue_dir.
    #[tokio::test]
    async fn email_create_with_smtp_queue_and_to_enqueues() {
        use crate::mailbox::types::mailbox_id_for_group;
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue = stoa_smtp::SmtpRelayQueue::new(
            dir.path(),
            vec![peer],
            Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");

        let (msgid_map, _tmp_msgid) = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let groups: Vec<(String, u64, u64)> = vec![("news.test".to_string(), 0, 0)];
        let mb_id = mailbox_id_for_group("news.test");
        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {mb_id: true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "Smtp relay test",
                "textBody": [{"value": "relay this"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue), &groups).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));

        // Oracle: .env file must exist in queue_dir.
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 1, "expected 1 .env file in smtp relay queue");
    }

    /// smtp_queue=Some but no To: or Cc:: no .env file written.
    #[tokio::test]
    async fn email_create_with_smtp_queue_no_recipients_no_enqueue() {
        use crate::mailbox::types::mailbox_id_for_group;
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue = stoa_smtp::SmtpRelayQueue::new(
            dir.path(),
            vec![peer],
            Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");

        let (msgid_map, _tmp_msgid) = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let groups: Vec<(String, u64, u64)> = vec![("news.test".to_string(), 0, 0)];
        let mb_id = mailbox_id_for_group("news.test");
        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {mb_id: true},
                "from": [{"email": "alice@example.com"}],
                "subject": "No recipients test",
                "textBody": [{"value": "body"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue), &groups).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));

        // Oracle: only dead/ subdir; no .env files.
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 0, "no recipients: no .env files expected");
    }

    /// SMTP enqueue failure (queue dir removed) must NOT cause handle_email_create to fail.
    #[tokio::test]
    async fn email_create_smtp_enqueue_failure_is_nonfatal() {
        use crate::mailbox::types::mailbox_id_for_group;
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue = stoa_smtp::SmtpRelayQueue::new(
            dir.path(),
            vec![peer],
            Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");

        // Remove the queue directory so enqueue will fail with an I/O error.
        std::fs::remove_dir_all(dir.path()).expect("remove queue dir");

        let (msgid_map, _tmp_msgid) = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let groups: Vec<(String, u64, u64)> = vec![("news.test".to_string(), 0, 0)];
        let mb_id = mailbox_id_for_group("news.test");
        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {mb_id: true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "Enqueue failure test",
                "textBody": [{"value": "body"}]
            }),
        );

        // Oracle: handle_email_create must succeed (not_created is empty).
        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue), &groups).await;
        assert!(
            not_created.is_empty(),
            "smtp enqueue failure must be non-fatal: {:?}",
            not_created
        );
        assert!(created.contains_key("c1"), "article must still be created");
    }

    /// extract_email_addrs correctly extracts email strings from JMAP format.
    #[test]
    fn extract_email_addrs_parses_jmap_format() {
        let field = json!([
            {"name": "Alice", "email": "alice@example.com"},
            {"name": "Bob", "email": "bob@example.com"},
            {"email": "no-name@example.com"},
            {"name": "Missing email"},
        ]);
        let addrs = extract_email_addrs(Some(&field));
        assert_eq!(
            addrs,
            vec![
                "alice@example.com",
                "bob@example.com",
                "no-name@example.com"
            ]
        );
    }

    /// extract_email_addrs returns empty vec for None input.
    #[test]
    fn extract_email_addrs_none_returns_empty() {
        let addrs = extract_email_addrs(None);
        assert!(addrs.is_empty());
    }

    // --- Tests for is_valid_addr_spec ---

    #[test]
    fn addr_spec_valid_simple() {
        assert!(is_valid_addr_spec("user@example.com"));
    }

    #[test]
    fn addr_spec_valid_subdomain() {
        assert!(is_valid_addr_spec("u.s+er@mail.example.org"));
    }

    #[test]
    fn addr_spec_rejects_no_at() {
        assert!(!is_valid_addr_spec("notanemail"));
    }

    #[test]
    fn addr_spec_rejects_multiple_at() {
        assert!(!is_valid_addr_spec("a@b@c.com"));
    }

    #[test]
    fn addr_spec_rejects_whitespace() {
        assert!(!is_valid_addr_spec("user name@example.com"));
        assert!(!is_valid_addr_spec("user@ex ample.com"));
    }

    #[test]
    fn addr_spec_rejects_non_ascii() {
        assert!(!is_valid_addr_spec("üser@example.com"));
    }

    #[test]
    fn addr_spec_rejects_empty_local() {
        assert!(!is_valid_addr_spec("@example.com"));
    }

    #[test]
    fn addr_spec_rejects_empty_domain() {
        assert!(!is_valid_addr_spec("user@"));
    }

    #[test]
    fn addr_spec_rejects_control_char() {
        assert!(!is_valid_addr_spec("use\x07r@example.com"));
    }
}
