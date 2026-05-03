//! Background task: publish a signed IPNS record after each article ingestion.
//!
//! The record points to a JSON index block that maps every active newsgroup to
//! its most-recently-ingested article CID.  The stable IPNS address is the
//! Kubo node's libp2p peer identity key (one address per node).
//!
//! Resolvers: IPNS → index CID → fetch JSON block → look up group by name.
//!
//! Rate limiting: a minimum interval between consecutive publishes prevents
//! excessive DHT traffic on high-volume ingestion nodes.
//!
//! Multi-instance single-writer (ky62.5): when `pg_lock` is `Some(pool)`
//! (PostgreSQL deployment), only the instance that holds
//! `pg_try_advisory_lock(IPNS_ADVISORY_LOCK_ID)` actually publishes to IPNS.
//! Others drain events and update their local group map but skip the actual
//! publish, so they remain ready to take over if the lock-holder dies.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::AnyPool;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use stoa_core::ipfs::KuboHttpClient;

/// PostgreSQL advisory lock ID reserved for the IPNS publisher.
///
/// Only the instance that holds this lock publishes to IPNS.
pub const IPNS_ADVISORY_LOCK_ID: i64 = 6_200_000_002;

/// Event sent by the drain task each time an article is successfully ingested.
pub struct IpnsEvent {
    /// Primary newsgroup the article was appended to.
    pub group: String,
    /// Article block CID (the most-recently-ingested CID for this group).
    pub cid: Cid,
}

/// Background worker that maintains a per-group CID index and publishes it via IPNS.
pub struct IpnsPublisher {
    client: KuboHttpClient,
    /// Most-recently-seen CID per group, in alphabetical order.
    groups: BTreeMap<String, Cid>,
    /// Minimum milliseconds between consecutive IPNS publishes.
    republish_interval_ms: u64,
    /// Wall-clock time of the last successful publish (ms since UNIX epoch).
    last_publish_ms: u64,
    /// When `Some`, use `pg_try_advisory_lock` before each publish so only
    /// one transit instance publishes IPNS in a multi-instance deployment.
    pg_lock: Option<AnyPool>,
}

impl IpnsPublisher {
    pub fn new(client: KuboHttpClient, republish_interval_secs: u64) -> Self {
        Self {
            client,
            groups: BTreeMap::new(),
            republish_interval_ms: republish_interval_secs.saturating_mul(1000),
            last_publish_ms: 0,
            pg_lock: None,
        }
    }

    /// Enable PostgreSQL advisory lock for single-writer IPNS publishing.
    ///
    /// Call this before `.run()` for PostgreSQL deployments.  When set, only
    /// the instance that can acquire `IPNS_ADVISORY_LOCK_ID` will actually
    /// publish; others silently drain events without publishing.
    pub fn with_pg_lock(mut self, pool: AnyPool) -> Self {
        self.pg_lock = Some(pool);
        self
    }

    /// Receive ingestion events and publish the IPNS index on each one,
    /// subject to the configured rate limit and advisory lock.
    pub async fn run(mut self, mut rx: mpsc::Receiver<IpnsEvent>) {
        info!("IPNS publisher started");
        while let Some(event) = rx.recv().await {
            self.groups.insert(event.group.clone(), event.cid);
            let now_ms = now_ms();
            if now_ms.saturating_sub(self.last_publish_ms) >= self.republish_interval_ms {
                if self.can_publish().await {
                    // ORDERING: release_lock MUST be called after every successful
                    // can_publish() to avoid advisory lock accumulation.
                    // update_and_publish is designed to be panic-free (all error
                    // paths return rather than panic), so the lock is always released.
                    self.update_and_publish().await;
                    self.release_lock().await;
                    self.last_publish_ms = now_ms;
                } else {
                    debug!(group = %event.group, "IPNS publish skipped (advisory lock held by another instance)");
                }
            } else {
                debug!(group = %event.group, "IPNS publish skipped (rate limit)");
            }
        }
        info!("IPNS publisher stopped");
    }

    /// Returns `true` if this instance is allowed to publish.
    ///
    /// When `pg_lock` is `None` (SQLite / single-instance), always returns `true`.
    /// When `pg_lock` is `Some`, attempts `pg_try_advisory_lock`; returns whether
    /// the lock was acquired.
    async fn can_publish(&self) -> bool {
        let pool = match &self.pg_lock {
            Some(p) => p,
            None => return true,
        };
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(?)")
            .bind(IPNS_ADVISORY_LOCK_ID)
            .fetch_one(pool)
            .await
            .unwrap_or(false)
    }

    /// Release the PostgreSQL advisory lock acquired by `can_publish`.
    ///
    /// Must be called after each successful publish so the lock does not
    /// accumulate across publish cycles.  No-op when `pg_lock` is `None`.
    async fn release_lock(&self) {
        let pool = match &self.pg_lock {
            Some(p) => p,
            None => return,
        };
        if let Err(e) = sqlx::query("SELECT pg_advisory_unlock(?)")
            .bind(IPNS_ADVISORY_LOCK_ID)
            .execute(pool)
            .await
        {
            warn!("IPNS publisher: failed to release advisory lock: {e}");
        }
    }

    /// Build the JSON index, store it as an IPFS block in Kubo, then publish IPNS.
    async fn update_and_publish(&self) {
        let json_bytes = build_index_json(&self.groups);
        let digest = Code::Sha2_256.digest(&json_bytes);
        let index_cid = Cid::new_v1(0x55, digest);

        if let Err(e) = self.client.block_put(&json_bytes, 0x55).await {
            warn!("IPNS publisher: failed to store index block: {e}");
            return;
        }

        match self.client.name_publish(&index_cid).await {
            Ok(ipns_path) => {
                info!(
                    groups = self.groups.len(),
                    ipns = %ipns_path,
                    index_cid = %index_cid,
                    "IPNS index published"
                );
            }
            Err(e) => {
                warn!("IPNS publisher: name/publish failed: {e}");
            }
        }
    }
}

/// Build the JSON group index as UTF-8 bytes.
///
/// Format: `{"version":1,"groups":{"comp.lang.rust":"<cid>",...}}`
///
/// Keys are sorted because `BTreeMap` iterates in alphabetical order, which
/// produces a deterministic byte sequence for the same group/CID set.
/// Determinism matters because the CID of the index block is content-addressed.
pub fn build_index_json(groups: &BTreeMap<String, Cid>) -> Vec<u8> {
    let mut out = String::from(r#"{"version":1,"groups":{"#);
    let mut first = true;
    for (group, cid) in groups {
        if !first {
            out.push(',');
        }
        first = false;
        // JSON-encode the group name via serde_json so that any unexpected
        // special characters (from a peer that bypassed GroupName validation)
        // produce valid JSON rather than a corrupt byte sequence.
        // For well-formed newsgroup names this produces identical output to
        // the naive push_str approach.
        // serde_json::to_string on a &str cannot fail; use unwrap_or_default as
        // a belt-and-suspenders guard so this function is unconditionally panic-free.
        let key = serde_json::to_string(group.as_str()).unwrap_or_default();
        out.push_str(&key);
        out.push_str(r#":""#);
        out.push_str(&cid.to_string());
        out.push('"');
    }
    out.push_str("}}");
    out.into_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, digest)
    }

    /// Empty group map produces a fixed known byte sequence.
    ///
    /// Oracle: hand-constructed JSON string.
    #[test]
    fn build_index_json_empty_groups() {
        let groups = BTreeMap::new();
        let json = build_index_json(&groups);
        assert_eq!(
            json,
            br#"{"version":1,"groups":{}}"#.to_vec(),
            "empty groups must produce exactly the expected JSON bytes"
        );
    }

    /// Single group produces correct JSON with version and groups keys.
    ///
    /// Oracle: hand-constructed expected string.
    #[test]
    fn build_index_json_single_group() {
        let mut groups = BTreeMap::new();
        // Use a known CID by constructing it from known data.
        let cid = make_cid(b"test block");
        groups.insert("comp.lang.rust".to_string(), cid);

        let json = build_index_json(&groups);
        let s = std::str::from_utf8(&json).unwrap();

        assert!(
            s.starts_with(r#"{"version":1,"groups":{"#),
            "JSON must start with correct prefix"
        );
        assert!(s.ends_with("}}"), "JSON must end with double closing brace");
        assert!(
            s.contains(r#""comp.lang.rust":""#),
            "JSON must contain the group name as key"
        );
        assert!(
            s.contains(&cid.to_string()),
            "JSON must contain the CID string"
        );
    }

    /// Two groups produce alphabetically-ordered keys (BTreeMap ordering).
    ///
    /// Oracle: hand-constructed expected JSON; "alt.test" < "comp.lang.rust" alphabetically.
    #[test]
    fn build_index_json_key_order_is_alphabetical() {
        let mut groups = BTreeMap::new();
        let cid_comp = make_cid(b"comp block");
        let cid_alt = make_cid(b"alt block");
        // Insert in reverse alphabetical order to test BTreeMap sorting.
        groups.insert("comp.lang.rust".to_string(), cid_comp);
        groups.insert("alt.test".to_string(), cid_alt);

        let json = build_index_json(&groups);
        let s = std::str::from_utf8(&json).unwrap();

        let alt_pos = s.find("alt.test").expect("alt.test must appear in output");
        let comp_pos = s
            .find("comp.lang.rust")
            .expect("comp.lang.rust must appear in output");
        assert!(
            alt_pos < comp_pos,
            "alt.test must appear before comp.lang.rust (alphabetical ordering)"
        );
    }

    /// JSON output is valid UTF-8 and can be parsed by serde_json.
    ///
    /// Oracle: serde_json parse of the known structure.
    #[test]
    fn build_index_json_is_valid_json() {
        let mut groups = BTreeMap::new();
        groups.insert("sci.math".to_string(), make_cid(b"sci block"));
        groups.insert("comp.test".to_string(), make_cid(b"comp block"));

        let json = build_index_json(&groups);
        let v: serde_json::Value =
            serde_json::from_slice(&json).expect("build_index_json must produce valid JSON");

        assert_eq!(v["version"], 1, "version must be 1");
        assert!(v["groups"].is_object(), "groups must be a JSON object");
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            2,
            "groups must have 2 entries"
        );
    }
}
