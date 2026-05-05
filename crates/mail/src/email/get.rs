//! Email/get handler.
//!
//! # ID spaces
//!
//! Two distinct ID spaces are used for Email objects, routed by prefix:
//!
//! - **CID IDs** (default): Multibase-encoded IPFS CIDs (e.g. `bafybei…`).
//!   Content-addressed, globally stable, independent of any local database.
//!   Refer to newsgroup articles stored in IPFS.
//!
//! - **`smtp:` IDs**: Synthetic IDs of the form `smtp:{row_id}` where `row_id`
//!   is a SQLite `AUTOINCREMENT` primary key from the `messages` table.
//!   **Local-only**: invalidated if the row is deleted or if the database is
//!   rebuilt. Must not be compared to CID IDs, exposed to peer servers, or
//!   treated as stable across database rebuilds.

use std::collections::HashMap;

use cid::Cid;
use serde_json::{json, Value};
use stoa_core::ipld::root_node::ArticleRootNode;
use stoa_reader::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

use super::types::Email;
use crate::store::SmtpMessageStore;

/// Handle Email/get.
///
/// For each id:
///   - If the id starts with `"smtp:"`, fetch from the `messages` table
///     in a single batched query.
///   - Otherwise, parse as a CID, fetch from IPFS, and decode DAG-CBOR.
///
/// `smtp_store` is the SMTP message store used for smtp: id lookups.
/// `account_id` is the canonical JMAP accountId string for the response.
/// `state` is the current JMAP Email state token from StateStore.
///
/// Returns JMAP EmailGet response JSON.
pub async fn handle_email_get(
    ids: &[String],
    ipfs: &dyn IpfsBlockStore,
    smtp_store: Option<&dyn SmtpMessageStore>,
    properties: Option<&[String]>,
    state: &str,
    account_id: &str,
) -> Value {
    let _ = properties; // v1: return all properties; filtering is deferred

    // Collect all smtp: row_ids for a single batch query.
    let smtp_row_ids: Vec<i64> = ids
        .iter()
        .filter(|id| id.starts_with("smtp:"))
        .filter_map(|id| id.strip_prefix("smtp:").and_then(|s| s.parse::<i64>().ok()))
        .collect();

    let smtp_map: HashMap<i64, Email> = if smtp_row_ids.is_empty() {
        HashMap::new()
    } else {
        match smtp_store {
            Some(s) => fetch_smtp_emails_batch(&smtp_row_ids, s).await,
            None => HashMap::new(),
        }
    };

    let mut list = Vec::new();
    let mut not_found = Vec::new();

    for id in ids {
        if id.starts_with("smtp:") {
            match id.strip_prefix("smtp:").and_then(|s| s.parse::<i64>().ok()) {
                Some(row_id) => match smtp_map.get(&row_id) {
                    Some(email) => list.push(serde_json::to_value(email).unwrap_or(json!({}))),
                    None => not_found.push(Value::String(id.clone())),
                },
                None => not_found.push(Value::String(id.clone())),
            }
            continue;
        }
        match fetch_email(id, ipfs).await {
            Ok(Some(email)) => list.push(serde_json::to_value(email).unwrap_or(json!({}))),
            Ok(None) => not_found.push(Value::String(id.clone())),
            Err(e) => {
                tracing::warn!(id = %id, "Email/get fetch error: {e}");
                not_found.push(Value::String(id.clone()));
            }
        }
    }

    json!({
        "accountId": account_id,
        "state": state,
        "list": list,
        "notFound": not_found,
    })
}

/// Fetch multiple smtp messages via the SmtpMessageStore trait.
///
/// Row IDs not present in the result are treated as not-found by the caller.
async fn fetch_smtp_emails_batch(
    row_ids: &[i64],
    store: &dyn SmtpMessageStore,
) -> HashMap<i64, Email> {
    match store.fetch_smtp_messages_batch(row_ids).await {
        Ok(rows) => rows
            .into_iter()
            .map(|(id, raw, mailbox_id, received_at)| {
                let smtp_id = format!("smtp:{id}");
                (
                    id,
                    Email::from_smtp_message(&smtp_id, &raw, &mailbox_id, &received_at),
                )
            })
            .collect(),
        Err(e) => {
            tracing::error!("fetch_smtp_emails_batch: DB query failed: {e}");
            HashMap::new()
        }
    }
}

async fn fetch_email(id: &str, ipfs: &dyn IpfsBlockStore) -> Result<Option<Email>, String> {
    // Parse CID.
    let cid = Cid::try_from(id).map_err(|e| format!("invalid CID: {e}"))?;

    // Fetch raw bytes from IPFS.
    let raw = match ipfs.get_raw(&cid).await {
        Ok(bytes) => bytes,
        Err(IpfsWriteError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };

    // Decode DAG-CBOR to ArticleRootNode.
    let root: ArticleRootNode =
        serde_ipld_dagcbor::from_slice(&raw).map_err(|e| format!("CBOR decode error: {e}"))?;

    // Map to Email (no header_map in v1 — DAG-CBOR of root doesn't include headers inline).
    let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
    Ok(Some(email))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};
    use stoa_core::ipld::root_node::{ArticleMetadata, ArticleRootNode};
    use stoa_reader::post::ipfs_write::IpfsWriteError;

    struct MemIpfs {
        blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl MemIpfs {
        fn new() -> Self {
            Self {
                blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl IpfsBlockStore for MemIpfs {
        async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
            let digest = Code::Sha2_256.digest(data);
            let cid = Cid::new_v1(0x71, digest);
            self.blocks
                .write()
                .await
                .insert(cid.to_bytes(), data.to_vec());
            Ok(cid)
        }
        async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
            self.blocks.write().await.insert(cid.to_bytes(), data);
            Ok(())
        }
        async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
            self.blocks
                .read()
                .await
                .get(&cid.to_bytes())
                .cloned()
                .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
        }
    }

    fn dummy_cid_v1(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn insert_root_node(ipfs: &MemIpfs, newsgroups: Vec<String>, byte_count: u64) -> Cid {
        let header_cid = dummy_cid_v1(b"header");
        let body_cid = dummy_cid_v1(b"body");
        let root = ArticleRootNode {
            schema_version: 1,
            header_cid,
            header_map_cid: None,
            body_cid,
            mime_cid: None,
            metadata: ArticleMetadata {
                message_id: "<test@example.com>".to_string(),
                newsgroups,
                hlc_timestamp: 1_714_560_000_000,
                operator_signature: vec![],
                byte_count,
                line_count: 1,
                content_type_summary: "text/plain".to_string(),
            },
        };
        let cbor = serde_ipld_dagcbor::to_vec(&root).expect("encode");
        ipfs.put_raw(&cbor).await.expect("insert")
    }

    #[tokio::test]
    async fn get_existing_email() {
        let ipfs = MemIpfs::new();
        let cid = insert_root_node(&ipfs, vec!["comp.test".to_string()], 512).await;

        let resp = handle_email_get(&[cid.to_string()], &ipfs, None, None, "0", "u_test").await;
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 1, "should find 1 email");
        assert_eq!(list[0]["id"].as_str().unwrap(), cid.to_string());
        assert_eq!(list[0]["size"].as_u64().unwrap(), 512);
        let not_found = resp["notFound"].as_array().unwrap();
        assert!(not_found.is_empty());
        assert_eq!(resp["accountId"].as_str().unwrap(), "u_test");
    }

    #[tokio::test]
    async fn get_missing_cid_returns_not_found() {
        let ipfs = MemIpfs::new();
        let fake_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp =
            handle_email_get(&[fake_cid.to_string()], &ipfs, None, None, "0", "u_test").await;
        let list = resp["list"].as_array().unwrap();
        assert!(list.is_empty());
        let not_found = resp["notFound"].as_array().unwrap();
        assert_eq!(not_found.len(), 1);
    }

    #[tokio::test]
    async fn get_invalid_cid_returns_not_found() {
        let ipfs = MemIpfs::new();
        let resp =
            handle_email_get(&["not-a-cid".to_string()], &ipfs, None, None, "0", "u_test").await;
        let not_found = resp["notFound"].as_array().unwrap();
        assert_eq!(not_found.len(), 1);
    }

    #[tokio::test]
    async fn get_multiple_emails() {
        let ipfs = MemIpfs::new();
        let cid1 = insert_root_node(&ipfs, vec!["comp.test".to_string()], 100).await;
        let cid2 = insert_root_node(&ipfs, vec!["alt.test".to_string()], 200).await;
        let resp = handle_email_get(
            &[cid1.to_string(), cid2.to_string()],
            &ipfs,
            None,
            None,
            "0",
            "u_test",
        )
        .await;
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 2);
    }
}
