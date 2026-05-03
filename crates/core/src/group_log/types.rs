use crate::article::GroupName;
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte identifier for a log entry, typically the SHA-256 of its
/// canonical serialization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogEntryId([u8; 32]);

impl LogEntryId {
    /// Construct a `LogEntryId` from raw bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        LogEntryId(b)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl LogEntryId {
    /// Convert this `LogEntryId` to a CIDv1 (codec 0x71 DAG-CBOR, SHA-256 multihash = self).
    ///
    /// The 32-byte `LogEntryId` is wrapped directly as the multihash digest.
    /// Used for tip advertisements and the XCID protocol.
    pub fn to_cid(&self) -> cid::Cid {
        use multihash_codetable::Multihash;
        // SHA2-256 multihash code = 0x12; 32 bytes is always valid.
        let mh =
            Multihash::wrap(0x12, self.as_bytes()).expect("32 bytes is always valid for SHA-256");
        cid::Cid::new_v1(0x71, mh)
    }

    /// Derive the `LogEntryId` from a `LogEntry`'s canonical byte representation.
    ///
    /// Mirrors the computation in `append::compute_entry_id`; used by the XCID
    /// client to verify that a fetched entry matches the requested ID.
    pub fn from_entry(entry: &LogEntry) -> Self {
        use crate::canonical::entry_id_bytes;
        use multihash_codetable::{Code, MultihashDigest};
        let input = entry_id_bytes(
            entry.hlc_timestamp,
            &entry.article_cid,
            &entry.operator_signature,
            &entry.parent_cids,
        );
        let digest = Code::Sha2_256.digest(&input);
        LogEntryId::from_bytes(
            digest
                .digest()
                .try_into()
                .expect("SHA2-256 digest is always 32 bytes"),
        )
    }
}

impl fmt::Display for LogEntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for LogEntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogEntryId({})", hex::encode(self.0))
    }
}

/// One entry in the per-group Merkle-CRDT append-only log.
///
/// `parent_cids` holds the CIDs of the parent entries in the DAG. An entry
/// with no parents is a root (genesis) entry. Multiple parents represent a
/// merge of concurrent branches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Hybrid Logical Clock timestamp (milliseconds since Unix epoch).
    pub hlc_timestamp: u64,
    /// CID of the article stored in IPFS.
    pub article_cid: Cid,
    /// Ed25519 signature by the operator key over the canonical entry bytes.
    pub operator_signature: Vec<u8>,
    /// CIDs of parent log entries; empty for the genesis entry.
    pub parent_cids: Vec<Cid>,
}

/// The current tip of a group's Merkle-CRDT log as known to this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHead {
    /// The group this head belongs to.
    pub group_name: GroupName,
    /// CID of the current tip entry.
    pub tip_cid: Cid,
    /// Total number of entries in the log at this tip (approximate for DAGs
    /// with concurrent branches; exact after full merge).
    pub entry_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        // DAG-CBOR codec = 0x71
        Cid::new_v1(0x71, digest)
    }

    #[test]
    fn log_entry_id_hex_display() {
        let id = LogEntryId::from_bytes([0u8; 32]);
        assert_eq!(
            id.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn log_entry_id_hex_display_nonzero() {
        let mut raw = [0u8; 32];
        raw[0] = 0xab;
        raw[31] = 0xcd;
        let id = LogEntryId::from_bytes(raw);
        let s = id.to_string();
        assert!(s.starts_with("ab"), "expected ab prefix, got {s}");
        assert!(s.ends_with("cd"), "expected cd suffix, got {s}");
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn log_entry_id_debug_format() {
        let id = LogEntryId::from_bytes([0u8; 32]);
        let debug = format!("{id:?}");
        assert!(debug.starts_with("LogEntryId("));
    }

    #[test]
    fn log_entry_construction() {
        let cid = test_cid(b"article-data");
        let entry = LogEntry {
            hlc_timestamp: 1_700_000_000_000,
            article_cid: cid.clone(),
            operator_signature: vec![1, 2, 3, 4],
            parent_cids: vec![],
        };
        assert_eq!(entry.hlc_timestamp, 1_700_000_000_000);
        assert_eq!(entry.article_cid, cid);
        assert_eq!(entry.operator_signature, vec![1, 2, 3, 4]);
        assert!(entry.parent_cids.is_empty());
    }

    #[test]
    fn log_entry_with_parents() {
        let parent1 = test_cid(b"parent1");
        let parent2 = test_cid(b"parent2");
        let article = test_cid(b"article");
        let entry = LogEntry {
            hlc_timestamp: 42,
            article_cid: article,
            operator_signature: vec![],
            parent_cids: vec![parent1.clone(), parent2.clone()],
        };
        assert_eq!(entry.parent_cids.len(), 2);
        assert_eq!(entry.parent_cids[0], parent1);
        assert_eq!(entry.parent_cids[1], parent2);
    }

    #[test]
    fn log_head_construction() {
        let group = GroupName::new("comp.lang.rust").expect("valid group name");
        let cid = test_cid(b"tip-entry");
        let head = LogHead {
            group_name: group.clone(),
            tip_cid: cid.clone(),
            entry_count: 42,
        };
        assert_eq!(head.group_name, group);
        assert_eq!(head.tip_cid, cid);
        assert_eq!(head.entry_count, 42);
    }
}
