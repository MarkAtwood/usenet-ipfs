// DECISION (rbe3.37): BFS visits and result count are bounded to prevent unbounded work
//
// A group log DAG may have millions of entries. Without caps, a single
// reconciliation round would walk the entire DAG, consuming O(N) memory and
// blocking indefinitely. MAX_BFS_VISITS limits per-round traversal work;
// MAX_HAVE limits the result set. `partial_have = true` signals callers to
// schedule a follow-up round. Do NOT remove these limits — they are the only
// safeguard against a malicious or very large remote log exhausting memory.

use std::collections::{HashSet, VecDeque};

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::LogEntryId;

/// Maximum number of entries returned in the `have` list per reconciliation
/// round.  Groups with more divergent history converge over multiple rounds.
/// Bounds memory and IHAVE message size regardless of group log depth.
const MAX_HAVE: usize = 1000;

/// Maximum number of BFS node visits during the `have` traversal.
/// Set to 5× `MAX_HAVE` so that the traversal terminates in bounded work even
/// when the local DAG has millions of entries.  When the limit is hit,
/// `partial_have` is set to `true` so callers can schedule a follow-up round.
const MAX_BFS_VISITS: usize = 5_000;

/// Result of reconciling two tip sets.
#[derive(Debug, Clone)]
pub struct ReconcileResult {
    /// Entry IDs we want from the remote (remote has them, we don't).
    pub want: Vec<LogEntryId>,
    /// Entry IDs we have to offer the remote (we have them, remote doesn't).
    /// Capped at [`MAX_HAVE`] entries; further convergence happens in subsequent rounds.
    pub have: Vec<LogEntryId>,
    /// `true` when the BFS was cut short before the local DAG was fully traversed.
    ///
    /// Two conditions set this flag:
    /// - The BFS visit count reached [`MAX_BFS_VISITS`] (5 000) — the DAG is too large
    ///   to traverse in a single round.
    /// - `have.len()` reached [`MAX_HAVE`] (1 000) with entries still in the queue.
    ///
    /// In either case the caller should schedule a follow-up reconciliation round.
    pub partial_have: bool,
}

/// Reconcile local and remote tip sets.
///
/// Compares tips and transitively finds all entries reachable from each side
/// but not the other.
///
/// Since we cannot traverse remote storage directly, the algorithm is:
///
/// - `want`: remote tip IDs not present in local storage.  The remote knows
///   its own ancestry, so we only need to name the tips themselves.
/// - `have`: all entries reachable from local tips via BFS through
///   `parent_cids`, minus any that appear in `remote_tips`.
pub async fn reconcile<S: LogStorage>(
    storage: &S,
    group: &GroupName,
    remote_tips: &[LogEntryId],
) -> Result<ReconcileResult, StorageError> {
    // ── want ─────────────────────────────────────────────────────────────────
    let mut want: Vec<LogEntryId> = Vec::new();
    for tip_id in remote_tips {
        if !storage.has_entry(tip_id).await? {
            want.push(*tip_id);
        }
    }

    // ── have ─────────────────────────────────────────────────────────────────
    // Build a set of remote tip bytes for O(1) membership tests.
    let remote_set: HashSet<[u8; 32]> = remote_tips.iter().map(|id| *id.as_bytes()).collect();

    let mut have: Vec<LogEntryId> = Vec::new();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: VecDeque<LogEntryId> = storage.list_tips(group).await?.into();

    let mut partial_have = false;
    let mut visits: usize = 0;

    while let Some(entry_id) = queue.pop_front() {
        let key = *entry_id.as_bytes();
        if visited.contains(&key) {
            continue;
        }
        visited.insert(key);

        visits += 1;
        if visits >= MAX_BFS_VISITS {
            partial_have = true;
            break;
        }

        if !remote_set.contains(&key) {
            have.push(entry_id);
            if have.len() >= MAX_HAVE {
                partial_have = !queue.is_empty();
                break;
            }
        }

        if let Some(parent_cids) = storage.get_parent_cids(&entry_id).await? {
            for parent_cid in &parent_cids {
                let digest_bytes = parent_cid.hash().digest();
                if let Ok(raw) = <[u8; 32]>::try_from(digest_bytes) {
                    queue.push_back(LogEntryId::from_bytes(raw));
                }
            }
        }
    }

    Ok(ReconcileResult {
        want,
        have,
        partial_have,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, Multihash, MultihashDigest};

    use crate::article::GroupName;
    use crate::group_log::mem_storage::MemLogStorage;
    use crate::group_log::storage::LogStorage;
    use crate::group_log::types::{LogEntry, LogEntryId};
    use crate::hlc::HlcTimestamp;

    fn test_group() -> GroupName {
        GroupName::new("comp.lang.rust").unwrap()
    }

    /// Derive a `LogEntryId` by SHA-256 hashing an arbitrary seed.
    fn make_entry_id(seed: &[u8]) -> LogEntryId {
        let digest = Code::Sha2_256.digest(seed);
        LogEntryId::from_bytes(
            digest
                .digest()
                .try_into()
                .expect("SHA2-256 digest is always 32 bytes"),
        )
    }

    /// Build a minimal `LogEntry`.  `parents` are CIDs whose multihash digest
    /// encodes the parent `LogEntryId` bytes (matching the convention in
    /// `append.rs`).
    fn make_entry(hlc: u64, article_seed: &[u8], parents: Vec<Cid>) -> LogEntry {
        LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: hlc,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: Cid::new_v1(0x71, Code::Sha2_256.digest(article_seed)),
            operator_signature: vec![],
            parent_cids: parents,
        }
    }

    /// Wrap a `LogEntryId` as a CID so it can appear in `parent_cids`.
    /// Uses SHA2-256 multihash code (0x12) and DAG-CBOR codec (0x71),
    /// matching the convention in `append.rs`.
    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    // ── identical_tip_sets ────────────────────────────────────────────────────

    /// When local and remote have the same single tip, want and have are both empty.
    #[tokio::test]
    async fn identical_tip_sets() {
        let storage = MemLogStorage::new();
        let group = test_group();
        let id = make_entry_id(b"genesis");

        storage
            .insert_entry(id.clone(), make_entry(1_000, b"article-1", vec![]))
            .await
            .unwrap();
        storage.set_tips(&group, &[id.clone()]).await.unwrap();

        let result = reconcile(&storage, &group, &[id.clone()]).await.unwrap();

        assert!(
            result.want.is_empty(),
            "want must be empty: {:?}",
            result.want
        );
        assert!(
            result.have.is_empty(),
            "have must be empty: {:?}",
            result.have
        );
        assert!(!result.partial_have, "small graph must not be truncated");
    }

    // ── remote_has_new_tip ────────────────────────────────────────────────────

    /// Remote has an entry the local node doesn't — it should appear in `want`.
    #[tokio::test]
    async fn remote_has_new_tip() {
        let storage = MemLogStorage::new();
        let group = test_group();

        // Local has one genesis entry and has it as the tip.
        let local_id = make_entry_id(b"local-genesis");
        storage
            .insert_entry(local_id.clone(), make_entry(1_000, b"local-art", vec![]))
            .await
            .unwrap();
        storage.set_tips(&group, &[local_id.clone()]).await.unwrap();

        // Remote claims a tip we have never seen.
        let remote_id = make_entry_id(b"remote-genesis");

        let result = reconcile(&storage, &group, &[remote_id.clone()])
            .await
            .unwrap();

        assert_eq!(
            result.want,
            vec![remote_id],
            "remote tip must appear in want"
        );
        // local_id is not in remote_tips → appears in have
        assert_eq!(result.have, vec![local_id]);
        assert!(!result.partial_have, "small graph must not be truncated");
    }

    // ── local_has_extra_entries ───────────────────────────────────────────────

    /// Local has entries the remote doesn't know — they should appear in `have`.
    #[tokio::test]
    async fn local_has_extra_entries() {
        let storage = MemLogStorage::new();
        let group = test_group();

        // Genesis entry — both sides know it.
        let genesis_id = make_entry_id(b"shared-genesis");
        storage
            .insert_entry(genesis_id.clone(), make_entry(1_000, b"art-0", vec![]))
            .await
            .unwrap();

        // Local appends a second entry on top of genesis.
        let extra_id = make_entry_id(b"local-extra");
        storage
            .insert_entry(
                extra_id.clone(),
                make_entry(2_000, b"art-1", vec![entry_id_to_cid(&genesis_id)]),
            )
            .await
            .unwrap();
        storage.set_tips(&group, &[extra_id.clone()]).await.unwrap();

        // Remote only knows the genesis tip.
        let result = reconcile(&storage, &group, &[genesis_id.clone()])
            .await
            .unwrap();

        assert!(
            result.want.is_empty(),
            "want must be empty: {:?}",
            result.want
        );

        // extra_id is local and not in remote_tips → in have.
        // genesis_id is in remote_tips → NOT in have.
        assert!(
            result.have.contains(&extra_id),
            "extra entry must appear in have: {:?}",
            result.have,
        );
        assert!(
            !result.have.contains(&genesis_id),
            "genesis is known to remote, must not appear in have: {:?}",
            result.have,
        );
        assert!(!result.partial_have, "small graph must not be truncated");
    }

    // ── symmetric_divergence ──────────────────────────────────────────────────

    /// Both sides have unique entries; want and have are both non-empty.
    #[tokio::test]
    async fn symmetric_divergence() {
        let storage = MemLogStorage::new();
        let group = test_group();

        let local_id = make_entry_id(b"local-only");
        storage
            .insert_entry(local_id.clone(), make_entry(1_000, b"art-local", vec![]))
            .await
            .unwrap();
        storage.set_tips(&group, &[local_id.clone()]).await.unwrap();

        let remote_id = make_entry_id(b"remote-only");

        let result = reconcile(&storage, &group, &[remote_id.clone()])
            .await
            .unwrap();

        assert_eq!(result.want, vec![remote_id], "remote entry must be in want");
        assert_eq!(result.have, vec![local_id], "local entry must be in have");
        assert!(!result.partial_have, "small graph must not be truncated");
    }

    // ── commutativity ─────────────────────────────────────────────────────────

    /// The v1 algorithm uses direct-tip-only `want` (no recursive ancestry
    /// traversal), so the exact equality `have(A→B) == want(B→A)` does not
    /// hold when the `have` side has deeper chains.  The property that holds
    /// under the simplified algorithm is:
    ///
    ///   want(A→B) ⊆ have(B→A)   and   want(B→A) ⊆ have(A→B)
    ///
    /// i.e. every ID that A needs to request from B is something B actually
    /// has (and vice versa), even though B may have additional ancestors it
    /// would also send.
    #[tokio::test]
    async fn commutativity() {
        let storage_a = MemLogStorage::new();
        let storage_b = MemLogStorage::new();
        let group = test_group();

        // Peer A has two entries: genesis + one child.
        let a_genesis_id = make_entry_id(b"a-genesis");
        storage_a
            .insert_entry(a_genesis_id.clone(), make_entry(1_000, b"art-a0", vec![]))
            .await
            .unwrap();

        let a_child_id = make_entry_id(b"a-child");
        storage_a
            .insert_entry(
                a_child_id.clone(),
                make_entry(2_000, b"art-a1", vec![entry_id_to_cid(&a_genesis_id)]),
            )
            .await
            .unwrap();
        storage_a
            .set_tips(&group, &[a_child_id.clone()])
            .await
            .unwrap();

        // Peer B has one entry: its own genesis.
        let b_genesis_id = make_entry_id(b"b-genesis");
        storage_b
            .insert_entry(b_genesis_id.clone(), make_entry(1_001, b"art-b0", vec![]))
            .await
            .unwrap();
        storage_b
            .set_tips(&group, &[b_genesis_id.clone()])
            .await
            .unwrap();

        // A reconciles against B's tips; B reconciles against A's tips.
        let a_tips = storage_a.list_tips(&group).await.unwrap();
        let b_tips = storage_b.list_tips(&group).await.unwrap();

        let result_a = reconcile(&storage_a, &group, &b_tips).await.unwrap();
        let result_b = reconcile(&storage_b, &group, &a_tips).await.unwrap();

        // Every ID A wants must be in B's have set.
        let have_b_set: HashSet<[u8; 32]> = result_b.have.iter().map(|id| *id.as_bytes()).collect();
        for id in &result_a.want {
            assert!(
                have_b_set.contains(id.as_bytes()),
                "want(A→B) entry {id} must be in have(B→A)"
            );
        }

        // Every ID B wants must be in A's have set.
        let have_a_set: HashSet<[u8; 32]> = result_a.have.iter().map(|id| *id.as_bytes()).collect();
        for id in &result_b.want {
            assert!(
                have_a_set.contains(id.as_bytes()),
                "want(B→A) entry {id} must be in have(A→B)"
            );
        }

        // Sanity: A wants b_genesis (it doesn't have it), B wants a_child (its tip).
        assert!(
            result_a.want.contains(&b_genesis_id),
            "A must want b_genesis_id"
        );
        assert!(
            result_b.want.contains(&a_child_id),
            "B must want a_child_id"
        );
    }
}
