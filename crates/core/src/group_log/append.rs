use crate::article::GroupName;
use crate::canonical::entry_id_bytes;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::group_log::verify::VerifiedEntry;
use multihash_codetable::{Code, MultihashDigest};

/// Error returned by [`append`].
#[non_exhaustive]
#[derive(Debug)]
pub enum AppendError {
    /// A storage operation failed.
    Storage(StorageError),
    /// A parent CID referenced in the entry is not present in storage,
    /// violating the tip-set invariant.  The inner string is the hex CID.
    MissingParent(String),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::MissingParent(cid) => write!(f, "parent entry not found: {cid}"),
        }
    }
}

impl std::error::Error for AppendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::MissingParent(_) => None,
        }
    }
}

impl From<StorageError> for AppendError {
    fn from(e: StorageError) -> Self {
        AppendError::Storage(e)
    }
}

impl From<AppendError> for StorageError {
    fn from(e: AppendError) -> Self {
        StorageError::Database(format!("group log append error: {e}"))
    }
}

/// Compute the [`LogEntryId`] for `entry` from its canonical byte representation.
///
/// The input is:
/// - `hlc_timestamp` as 8 big-endian bytes
/// - `article_cid` as its full CID bytes
/// - `operator_signature` bytes
/// - each `parent_cid` bytes, sorted lexicographically before hashing
///
/// Sorting the parents ensures the ID is the same regardless of the order
/// they appear in the slice.
fn compute_entry_id(entry: &LogEntry) -> LogEntryId {
    let input = entry_id_bytes(
        entry.hlc_timestamp.wall_ms,
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

/// Append a verified log entry to the group log.
///
/// The caller must verify the entry's signature via
/// [`crate::group_log::verify::verify_signature`] before calling this
/// function.  The [`VerifiedEntry`] wrapper enforces this at the type level —
/// only signed entries can be stored.
///
/// The entry's `parent_cids` must be set to the CURRENT tip set before
/// calling.  After a successful append:
/// - The entry is persisted to storage.
/// - The tip set for `group` is replaced with `{new_entry_id}`.
///
/// If an entry with the same ID already exists (idempotent re-append),
/// returns `Ok(existing_id)` without modifying the tip set.
///
/// Returns `Err(AppendError::MissingParent)` if any parent CID is not found
/// in storage (tip-set invariant violated), or `Err(AppendError::Storage)`
/// for storage failures.
pub async fn append<S: LogStorage>(
    storage: &S,
    group: &GroupName,
    verified: VerifiedEntry,
) -> Result<LogEntryId, AppendError> {
    let entry = verified.into_inner();
    let entry_id = compute_entry_id(&entry);

    // Idempotent: if already stored, return the existing ID unchanged.
    if storage.has_entry(&entry_id).await? {
        return Ok(entry_id);
    }

    // Verify that every declared parent exists in storage.  A parent CID
    // carries the SHA-256 of that parent entry as its multihash digest; we
    // extract those 32 bytes to form the LogEntryId we look up.
    // Save the parent LogEntryIds here — they are needed for advance_tips
    // after the entry is moved into insert_entry.
    let mut parent_ids = Vec::with_capacity(entry.parent_cids.len());
    for parent_cid in &entry.parent_cids {
        let digest_bytes = parent_cid.hash().digest();
        let raw: [u8; 32] = digest_bytes.try_into().map_err(|_| {
            AppendError::MissingParent(format!(
                "parent CID {} has a non-32-byte digest (length {})",
                parent_cid,
                digest_bytes.len()
            ))
        })?;
        let parent_id = LogEntryId::from_bytes(raw);
        if !storage.has_entry(&parent_id).await? {
            return Err(AppendError::MissingParent(parent_cid.to_string()));
        }
        parent_ids.push(parent_id);
    }

    // Atomically insert the entry and advance the tip set in a single
    // operation.  SqliteLogStorage wraps both in one transaction, eliminating
    // the crash window that would leave an orphaned log entry (stored but
    // never a tip).  If a concurrent caller won the race, DuplicateEntry is
    // returned — treat as the idempotent success case without re-advancing.
    match storage
        .insert_entry_and_advance_tips(entry_id, entry, group, &parent_ids, &entry_id)
        .await
    {
        Ok(()) => {}
        Err(StorageError::DuplicateEntry(_)) => return Ok(entry_id),
        Err(e) => return Err(AppendError::Storage(e)),
    }

    Ok(entry_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::article::GroupName;
    use crate::group_log::mem_storage::MemLogStorage;
    use crate::group_log::verify::VerifiedEntry;
    use crate::hlc::HlcTimestamp;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_group() -> GroupName {
        GroupName::new("comp.lang.rust").unwrap()
    }

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    /// Convert a LogEntryId back to a Cid so it can be used as a parent_cid
    /// in a subsequent entry.  The CID uses DAG-CBOR (0x71) codec and the
    /// SHA-256 of the entry's canonical bytes as its multihash.
    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        use multihash_codetable::Multihash;
        // Wrap the raw 32 bytes in a SHA2-256 multihash.
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    // ── single_node_chain ─────────────────────────────────────────────────────

    /// Append three entries in sequence, each pointing to the previous one as
    /// its parent.  After each append the tip must be the newly appended entry.
    #[tokio::test]
    async fn single_node_chain() {
        let storage = MemLogStorage::new();
        let group = test_group();

        // Genesis entry — no parents.
        let e1 = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-1"),
            operator_signature: vec![0xaa],
            parent_cids: vec![],
        };
        let id1 = append(&storage, &group, VerifiedEntry::new_for_test(e1))
            .await
            .expect("append e1");

        let tips = storage.list_tips(&group).await.unwrap();
        assert_eq!(tips, vec![id1.clone()], "tip after e1");

        // Second entry: parent is the first entry's ID, expressed as a CID.
        let e2 = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-2"),
            operator_signature: vec![0xbb],
            parent_cids: vec![entry_id_to_cid(&id1)],
        };
        let id2 = append(&storage, &group, VerifiedEntry::new_for_test(e2))
            .await
            .expect("append e2");

        let tips = storage.list_tips(&group).await.unwrap();
        assert_eq!(tips, vec![id2.clone()], "tip after e2");
        assert_ne!(id1, id2);

        // Third entry: parent is the second entry's ID.
        let e3 = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 3_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-3"),
            operator_signature: vec![0xcc],
            parent_cids: vec![entry_id_to_cid(&id2)],
        };
        let id3 = append(&storage, &group, VerifiedEntry::new_for_test(e3))
            .await
            .expect("append e3");

        let tips = storage.list_tips(&group).await.unwrap();
        assert_eq!(tips, vec![id3.clone()], "tip after e3");
        assert_ne!(id2, id3);

        // All three entries must be present in storage.
        assert!(storage.has_entry(&id1).await.unwrap());
        assert!(storage.has_entry(&id2).await.unwrap());
        assert!(storage.has_entry(&id3).await.unwrap());
    }

    // ── idempotent_reappend ───────────────────────────────────────────────────

    /// Appending the same entry twice must succeed on both calls and leave
    /// exactly one entry in storage.
    #[tokio::test]
    async fn idempotent_reappend() {
        let storage = MemLogStorage::new();
        let group = test_group();

        let entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 42,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"idempotent-article"),
            operator_signature: vec![0x01, 0x02],
            parent_cids: vec![],
        };

        let id_first = append(&storage, &group, VerifiedEntry::new_for_test(entry.clone()))
            .await
            .expect("first append");
        let id_second = append(&storage, &group, VerifiedEntry::new_for_test(entry.clone()))
            .await
            .expect("second append (idempotent)");

        assert_eq!(
            id_first, id_second,
            "idempotent re-append must return same ID"
        );

        // Storage must contain exactly the one entry we appended.
        let stored = storage.get_entry(&id_first).await.unwrap();
        assert!(
            stored.is_some(),
            "entry must be present after idempotent append"
        );
    }

    // ── missing_parent_rejected ───────────────────────────────────────────────

    /// An entry whose parent_cids references a non-existent entry must be
    /// rejected with AppendError::MissingParent.
    #[tokio::test]
    async fn missing_parent_rejected() {
        let storage = MemLogStorage::new();
        let group = test_group();

        // Invent a LogEntryId for a non-existent entry and wrap it as a CID.
        let phantom_id = LogEntryId::from_bytes([0xde; 32]);
        let phantom_cid = entry_id_to_cid(&phantom_id);

        let entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 100,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"orphan-article"),
            operator_signature: vec![],
            parent_cids: vec![phantom_cid.clone()],
        };

        let result = append(&storage, &group, VerifiedEntry::new_for_test(entry)).await;
        assert!(
            matches!(result, Err(AppendError::MissingParent(_))),
            "expected MissingParent, got {result:?}"
        );
    }

    // ── concurrent_appends_both_survive ──────────────────────────────────────

    /// Two appends that share the same genesis parent (concurrent POST scenario)
    /// must both survive as tips after advance_tips.
    ///
    /// Oracle: the tip set must contain both new entry IDs. Neither may be lost.
    #[tokio::test]
    async fn concurrent_appends_both_survive() {
        let storage = MemLogStorage::new();
        let group = test_group();

        // Genesis entry.
        let genesis = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"genesis"),
            operator_signature: vec![0x00],
            parent_cids: vec![],
        };
        let genesis_id = append(&storage, &group, VerifiedEntry::new_for_test(genesis))
            .await
            .expect("genesis");

        // Two concurrent appends, both with genesis as parent.
        let genesis_cid = entry_id_to_cid(&genesis_id);
        let ea = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-a"),
            operator_signature: vec![0xaa],
            parent_cids: vec![genesis_cid.clone()],
        };
        let eb = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 2_001,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-b"),
            operator_signature: vec![0xbb],
            parent_cids: vec![genesis_cid.clone()],
        };

        let id_a = append(&storage, &group, VerifiedEntry::new_for_test(ea))
            .await
            .expect("append A");
        let id_b = append(&storage, &group, VerifiedEntry::new_for_test(eb))
            .await
            .expect("append B");

        let tips = storage.list_tips(&group).await.unwrap();
        let tip_bytes: Vec<[u8; 32]> = tips.iter().map(|id| *id.as_bytes()).collect();

        assert!(
            tip_bytes.contains(id_a.as_bytes()),
            "entry A must be in tip set; tips = {tips:?}"
        );
        assert!(
            tip_bytes.contains(id_b.as_bytes()),
            "entry B must be in tip set; tips = {tips:?}"
        );
        assert!(
            !tip_bytes.contains(genesis_id.as_bytes()),
            "genesis must not be a tip"
        );
        assert_eq!(tips.len(), 2, "must have exactly 2 tips");
    }

    // ── concurrent_replicas_diverge ───────────────────────────────────────────

    /// Two independent MemLogStorage instances each start from an empty state
    /// and append different genesis entries.  Each ends up with one tip.
    /// This exercises the divergence case; merge/reconciliation is out of scope.
    #[tokio::test]
    async fn concurrent_replicas_diverge() {
        let storage_a = MemLogStorage::new();
        let storage_b = MemLogStorage::new();
        let group = test_group();

        let entry_a = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"replica-a-article"),
            operator_signature: vec![0xa1],
            parent_cids: vec![],
        };
        let entry_b = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 1_001,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"replica-b-article"),
            operator_signature: vec![0xb1],
            parent_cids: vec![],
        };

        let id_a = append(&storage_a, &group, VerifiedEntry::new_for_test(entry_a))
            .await
            .expect("append on replica A");
        let id_b = append(&storage_b, &group, VerifiedEntry::new_for_test(entry_b))
            .await
            .expect("append on replica B");

        // Both replicas have exactly one tip after their independent genesis.
        let tips_a = storage_a.list_tips(&group).await.unwrap();
        let tips_b = storage_b.list_tips(&group).await.unwrap();

        assert_eq!(tips_a.len(), 1, "replica A must have one tip");
        assert_eq!(tips_b.len(), 1, "replica B must have one tip");
        assert_eq!(tips_a[0], id_a);
        assert_eq!(tips_b[0], id_b);

        // The two tips are different — the replicas diverged.
        assert_ne!(id_a, id_b, "diverged replicas must have distinct tip IDs");
    }
}
