use std::collections::{HashSet, VecDeque};

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::group_log::verify::VerifiedEntry;

/// Maximum number of entries fetched in a single backfill BFS traversal.
///
/// Matches the order of magnitude of `MAX_BFS_VISITS` in `reconcile.rs`
/// (5 000) but is set higher (50 000) because backfill must retrieve the full
/// ancestry of a tip, not just build a `have` list.  An adversarial peer
/// serving more entries than this limit will trigger [`BackfillError::Truncated`]
/// rather than causing unbounded heap growth.
const MAX_BACKFILL_ENTRIES: usize = 50_000;

/// Error returned by [`backfill`].
#[non_exhaustive]
#[derive(Debug)]
pub enum BackfillError {
    /// A storage operation failed.
    Storage(StorageError),
    /// The fetch callback returned an error for the given entry ID.
    FetchFailed(String),
    /// A fetched entry contains a parent CID whose multihash digest is not 32
    /// bytes.  Storing this entry would silently disconnect the DAG, so the
    /// operation is aborted instead.
    MalformedParentCid(String),
    /// The BFS traversal fetched more than [`MAX_BACKFILL_ENTRIES`] entries
    /// without exhausting the remote DAG.  The partial result is stored and the
    /// caller should schedule a follow-up backfill from the same tip.
    Truncated {
        /// Number of entries fetched and inserted before the limit was hit.
        fetched: usize,
    },
}

impl std::fmt::Display for BackfillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::FetchFailed(msg) => write!(f, "fetch failed: {msg}"),
            Self::MalformedParentCid(msg) => write!(f, "malformed parent CID: {msg}"),
            Self::Truncated { fetched } => write!(
                f,
                "backfill truncated after {fetched} entries (limit {MAX_BACKFILL_ENTRIES}); \
                 schedule a follow-up backfill to retrieve remaining ancestors"
            ),
        }
    }
}

impl std::error::Error for BackfillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::FetchFailed(_) | Self::MalformedParentCid(_) | Self::Truncated { .. } => None,
        }
    }
}

impl From<StorageError> for BackfillError {
    fn from(e: StorageError) -> Self {
        BackfillError::Storage(e)
    }
}

/// Backfill a DAG starting from `want_id`, fetching all ancestors not already
/// in local storage.
///
/// `fetch` is a callback that retrieves and **verifies** a `LogEntry` by its
/// `LogEntryId` from a remote source, returning a [`VerifiedEntry`].  Returns
/// the number of entries fetched and inserted.
///
/// If `want_id` is already present in local storage the function returns
/// `Ok(0)` immediately without issuing any fetch calls.
///
/// After inserting the new entries the tip set for `group` is advanced:
/// `want_id` is added as a new tip and its direct parents are removed from
/// the tip set (CRDT-correct semantics, same as [`crate::group_log::append`]).
///
/// # Signature verification is enforced by type
///
/// The callback must return a [`VerifiedEntry`], which can only be constructed
/// via [`crate::group_log::verify::verify_signature`].  This makes it
/// impossible for callers to insert unverified entries: the type system
/// enforces the invariant that every entry stored here has a valid operator
/// Ed25519 signature.
///
/// Algorithm (BFS):
/// 1. If `want_id` already in storage: return `Ok(0)`.
/// 2. Add `want_id` to the queue.
/// 3. While queue non-empty:
///    a. Pop an entry ID.
///    b. If already in storage or visited: skip.
///    c. Mark as visited.
///    d. Call `fetch(entry_id)` — propagates `BackfillError::FetchFailed` on error.
///    e. Insert the entry into storage (treat `DuplicateEntry` as idempotent).
///    f. Enqueue parents not yet in local storage (via CID multihash digest).
/// 4. Advance the tip set: add `want_id`, remove its parents.
/// 5. Return `Ok(entries_fetched_count)`.
pub async fn backfill<S, F, Fut>(
    storage: &S,
    group: &GroupName,
    want_id: LogEntryId,
    fetch: F,
) -> Result<usize, BackfillError>
where
    S: LogStorage,
    F: Fn(LogEntryId) -> Fut,
    Fut: std::future::Future<Output = Result<VerifiedEntry, String>>,
{
    if storage.has_entry(&want_id).await? {
        // The entry is already present locally.  Verify it is also a current
        // tip; if not, advance the tip set so that consumers see it as
        // reachable.  Without this check a caller can believe it is fully
        // synced while tips remain stale (the entry exists but is not
        // advertised as a DAG frontier).
        let tips = storage.list_tips(group).await?;
        let want_key = *want_id.as_bytes();
        let already_tip = tips.iter().any(|t| *t.as_bytes() == want_key);
        if !already_tip {
            // Retrieve the entry's parents so advance_tips can retire them.
            let parent_ids = if let Some(entry) = storage.get_entry(&want_id).await? {
                parent_ids_from_entry(&entry)
            } else {
                // Entry disappeared between has_entry and get_entry (race).
                // Fall through to BFS path by returning without advancing tips.
                return Ok(0);
            };
            storage.advance_tips(group, &parent_ids, &want_id).await?;
        }
        return Ok(0);
    }

    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: VecDeque<LogEntryId> = VecDeque::new();
    let mut fetched_count: usize = 0;
    // Captured from the first BFS iteration.  The queue starts with exactly
    // want_id and nothing else, so the first pop_front always yields want_id.
    // The debug assertion below enforces this invariant explicitly so that any
    // future refactor that adds pre-queued entries fails fast rather than
    // silently capturing the wrong entry's parents.
    let mut want_parent_ids: Option<Vec<LogEntryId>> = None;

    queue.push_back(want_id.clone());

    while let Some(entry_id) = queue.pop_front() {
        let key = *entry_id.as_bytes();

        if visited.contains(&key) {
            continue;
        }

        // Do NOT check has_entry here: checking then fetching is a TOCTOU race.
        // A concurrent writer may insert between our has_entry check and our
        // fetch, causing advance_tips to be skipped for that CID.  Instead we
        // always fetch and attempt an unconditional insert; the DuplicateEntry
        // arm below makes this idempotent.  The visited set above prevents
        // re-fetching the same CID within this BFS traversal.

        visited.insert(key);

        let verified = fetch(entry_id)
            .await
            .map_err(BackfillError::FetchFailed)?;
        let entry = verified.into_inner();

        // Verify the returned entry's computed ID matches the requested ID.
        // A peer can return any valid signed entry for a given request; without
        // this check an attacker can substitute a different entry and cause us
        // to store it under the wrong ID.
        let computed_id = LogEntryId::from_entry(&entry);
        if computed_id != entry_id {
            return Err(BackfillError::FetchFailed(format!(
                "entry ID mismatch: requested {entry_id}, peer returned entry with ID {computed_id}"
            )));
        }

        // Capture want_id's parent IDs on the first fetch.
        // Assert that the first entry dequeued is always want_id: the queue
        // starts with only want_id, so this fires on the very first iteration.
        // This guards against ordering bugs introduced by future refactors.
        if want_parent_ids.is_none() {
            debug_assert_eq!(
                *entry_id.as_bytes(),
                *want_id.as_bytes(),
                "backfill BFS invariant violated: first dequeued entry must be want_id"
            );
            want_parent_ids = Some(parent_ids_from_entry(&entry));
        }

        match storage.insert_entry(entry_id.clone(), entry.clone()).await {
            Ok(()) => {
                fetched_count += 1;
            }
            // Concurrent insert beat us: treat as idempotent success.
            // Do NOT count as fetched — the entry was not newly stored.
            Err(StorageError::DuplicateEntry(_)) => {}
            Err(e) => return Err(BackfillError::Storage(e)),
        }

        // Use visited.len() for the truncation guard (not fetched_count) so
        // that DuplicateEntry collisions count toward the BFS visit budget.
        // This prevents an adversarial peer from bypassing the limit by serving
        // entries that are already present locally.
        if visited.len() >= MAX_BACKFILL_ENTRIES {
            return Err(BackfillError::Truncated {
                fetched: fetched_count,
            });
        }

        for parent_cid in &entry.parent_cids {
            let digest_bytes = parent_cid.hash().digest();
            let raw: [u8; 32] = <[u8; 32]>::try_from(digest_bytes).map_err(|_| {
                BackfillError::MalformedParentCid(format!(
                    "parent CID {} has {}-byte digest (expected 32)",
                    parent_cid,
                    digest_bytes.len()
                ))
            })?;
            let parent_id = LogEntryId::from_bytes(raw);
            // Enqueue parent unconditionally; the visited-set check at the top
            // of the BFS loop skips entries already processed in this session,
            // and the DuplicateEntry handler makes storage inserts idempotent.
            // A has_entry() check here would be a TOCTOU race: a concurrent
            // writer could insert after the check but before we enqueue,
            // causing us to skip fetching a parent we don't actually have.
            if !visited.contains(parent_id.as_bytes()) {
                queue.push_back(parent_id);
            }
        }
    }

    // Advance the tip set so reconcile can see the new entries.  This mirrors
    // what `append` does: add want_id as a tip and retire its direct parents.
    if let Some(parent_ids) = want_parent_ids {
        storage.advance_tips(group, &parent_ids, &want_id).await?;
    }

    Ok(fetched_count)
}

/// Extract LogEntryIds from the parent_cids of a LogEntry.
/// Parent CIDs with non-32-byte digests are silently skipped (they will be
/// caught later by the per-parent MalformedParentCid check in the BFS loop).
fn parent_ids_from_entry(entry: &LogEntry) -> Vec<LogEntryId> {
    entry
        .parent_cids
        .iter()
        .filter_map(|cid| {
            <[u8; 32]>::try_from(cid.hash().digest())
                .ok()
                .map(LogEntryId::from_bytes)
        })
        .collect()
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

    fn test_group() -> GroupName {
        GroupName::new("comp.test".to_owned()).unwrap()
    }

    /// Wrap a `LogEntryId` as a CID so it can appear in `parent_cids`.
    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    /// Build a minimal `LogEntry` with the given HLC timestamp, article seed, and
    /// parent CIDs, then compute its true content-derived `LogEntryId`.
    ///
    /// The ID is derived from the entry content via `LogEntryId::from_entry` so
    /// that the backfill ID-verification check (`from_entry(returned) == requested`)
    /// passes for entries built with this helper.
    fn make_entry(hlc: u64, article_seed: &[u8], parents: Vec<Cid>) -> (LogEntryId, LogEntry) {
        let entry = LogEntry {
            hlc_timestamp: hlc,
            article_cid: Cid::new_v1(0x71, Code::Sha2_256.digest(article_seed)),
            operator_signature: vec![],
            parent_cids: parents,
        };
        let id = LogEntryId::from_entry(&entry);
        (id, entry)
    }

    /// Build `n` entries in a chain: genesis → e1 → e2 → … → e_{n-1}.
    /// Each entry (except genesis) has one parent.
    ///
    /// Returns `(storage, vec_of_entry_ids)` where index 0 is the genesis and
    /// index `n-1` is the tip.
    async fn make_chain(n: usize) -> (MemLogStorage, Vec<LogEntryId>) {
        assert!(n >= 1, "chain must have at least one entry");
        let storage = MemLogStorage::new();
        let mut ids: Vec<LogEntryId> = Vec::with_capacity(n);

        for i in 0..n {
            let parents = if i == 0 {
                vec![]
            } else {
                vec![entry_id_to_cid(&ids[i - 1])]
            };

            let (id, entry) =
                make_entry(i as u64 * 1_000, format!("article-{i}").as_bytes(), parents);
            storage
                .insert_entry(id.clone(), entry)
                .await
                .expect("insert chain entry");

            ids.push(id);
        }

        (storage, ids)
    }

    // ── backfill_single_entry ─────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_single_entry() {
        let (remote, ids) = make_chain(1).await;
        let local = MemLogStorage::new();

        let tip_id = ids[0].clone();

        let count = backfill(&local, &test_group(), tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(count, 1, "expected 1 entry fetched");
        assert!(
            local.has_entry(&tip_id).await.unwrap(),
            "entry must be in local storage after backfill"
        );
    }

    // ── backfill_chain_100 ────────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_chain_100() {
        let (remote, ids) = make_chain(100).await;
        let local = MemLogStorage::new();

        let tip_id = ids[99].clone();

        let count = backfill(&local, &test_group(), tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(count, 100, "expected all 100 entries fetched");
        for id in &ids {
            assert!(
                local.has_entry(id).await.unwrap(),
                "entry {id} must be in local storage"
            );
        }
    }

    // ── backfill_idempotent ───────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_idempotent() {
        let (remote, ids) = make_chain(5).await;
        let local = MemLogStorage::new();

        let tip_id = ids[4].clone();

        let count_first = backfill(&local, &test_group(), tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("first backfill should succeed");

        assert_eq!(count_first, 5, "first backfill must fetch 5 entries");

        let count_second = backfill(&local, &test_group(), tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("second backfill should succeed");

        assert_eq!(
            count_second, 0,
            "second backfill must return 0 (already have tip)"
        );
    }

    // ── backfill_diamond_dag ──────────────────────────────────────────────────
    //
    //  A (genesis, no parents)
    //  ├── B (parent: A)
    //  └── C (parent: A)
    //       └── D (parents: B, C)
    //
    //  Backfill D from an empty local store.  All four entries must be fetched
    //  exactly once.

    #[tokio::test]
    async fn backfill_diamond_dag() {
        let remote = MemLogStorage::new();

        // Build entries bottom-up, deriving each ID from content so that the
        // backfill ID-verification check passes.
        let (id_a, entry_a) = make_entry(1_000, b"art-A", vec![]);
        let (id_b, entry_b) = make_entry(2_000, b"art-B", vec![entry_id_to_cid(&id_a)]);
        let (id_c, entry_c) = make_entry(2_001, b"art-C", vec![entry_id_to_cid(&id_a)]);
        let (id_d, entry_d) = make_entry(
            3_000,
            b"art-D",
            vec![entry_id_to_cid(&id_b), entry_id_to_cid(&id_c)],
        );

        remote.insert_entry(id_a.clone(), entry_a).await.unwrap();
        remote.insert_entry(id_b.clone(), entry_b).await.unwrap();
        remote.insert_entry(id_c.clone(), entry_c).await.unwrap();
        remote.insert_entry(id_d.clone(), entry_d).await.unwrap();

        let local = MemLogStorage::new();
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetch_count_clone = fetch_count.clone();

        let count = backfill(&local, &test_group(), id_d.clone(), |id| {
            let remote_ref = &remote;
            let counter = fetch_count_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                remote_ref
                    .get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("diamond backfill should succeed");

        assert_eq!(count, 4, "all 4 diamond entries must be fetched");
        assert_eq!(
            fetch_count.load(Ordering::SeqCst),
            4,
            "fetch callback must be called exactly 4 times (no duplicates)"
        );
        for (label, id) in [("A", &id_a), ("B", &id_b), ("C", &id_c), ("D", &id_d)] {
            assert!(
                local.has_entry(id).await.unwrap(),
                "entry {label} must be in local storage"
            );
        }
    }

    // ── backfill_count_excludes_duplicate_entries ─────────────────────────────
    //
    //  When a concurrent writer has already inserted some entries into local
    //  storage, backfill encounters DuplicateEntry for those entries.  The
    //  returned count must only reflect entries actually newly inserted, not
    //  the number of BFS visits.

    #[tokio::test]
    async fn backfill_count_excludes_duplicate_entries() {
        // Remote has a chain: 0 → 1 → 2 → 3 → 4
        let (remote, ids) = make_chain(5).await;
        let local = MemLogStorage::new();

        // Pre-populate local with entries 2 and 3 (simulating a concurrent writer).
        for i in [2usize, 3usize] {
            let entry = remote
                .get_entry(&ids[i])
                .await
                .unwrap()
                .expect("entry exists in remote");
            local
                .insert_entry(ids[i].clone(), entry)
                .await
                .expect("pre-insert");
        }

        let tip_id = ids[4].clone();
        let count = backfill(&local, &test_group(), tip_id, |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("backfill should succeed");

        // Entries 0, 1, and 4 were newly inserted; 2 and 3 were DuplicateEntry.
        assert_eq!(count, 3, "count must exclude DuplicateEntry collisions");
    }

    // ── backfill_fetch_failure ────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_fetch_failure() {
        let local = MemLogStorage::new();
        // Use a content-derived ID for an entry that does not exist in the
        // remote store so the fetch callback is invoked and returns an error.
        let (missing_id, _) = make_entry(999, b"does-not-exist", vec![]);

        let result = backfill(&local, &test_group(), missing_id, |id| async move {
            Err::<VerifiedEntry, _>(format!("remote has no entry {id}"))
        })
        .await;

        assert!(
            matches!(result, Err(BackfillError::FetchFailed(_))),
            "expected BackfillError::FetchFailed, got {result:?}"
        );
    }

    // ── backfill_malformed_parent_cid_errors ─────────────────────────────────
    //
    //  If a fetched entry contains a parent CID whose multihash digest is not
    //  32 bytes, backfill must return MalformedParentCid, not silently skip it.
    //  A silent skip would store an entry with a broken ancestry pointer.

    #[tokio::test]
    async fn backfill_malformed_parent_cid_errors() {
        // Build a parent CID with a 20-byte digest instead of 32.
        // Multihash::wrap(0x12, bytes) sets code=SHA2-256 but uses whatever
        // byte slice we give it, so 20 bytes produces a structurally valid
        // Multihash that is nonetheless the wrong size for a LogEntryId.
        let short_digest = [0xABu8; 20];
        let short_mh = Multihash::wrap(0x12, &short_digest).expect("valid multihash wrap");
        let bad_parent_cid = Cid::new_v1(0x71, short_mh);

        let remote = MemLogStorage::new();
        // Build the tip entry with the malformed parent CID, then store it
        // under its content-derived ID so the backfill ID check passes and
        // backfill proceeds to the parent-CID validation step.
        let (tip_id, tip_entry) = make_entry(1_000, b"art-tip", vec![bad_parent_cid]);
        remote
            .insert_entry(tip_id.clone(), tip_entry)
            .await
            .unwrap();

        let local = MemLogStorage::new();
        let result = backfill(&local, &test_group(), tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await;

        assert!(
            matches!(result, Err(BackfillError::MalformedParentCid(_))),
            "expected BackfillError::MalformedParentCid, got {result:?}"
        );
    }

    // ── backfill_already_local_returns_zero ───────────────────────────────────

    #[tokio::test]
    async fn backfill_already_local_returns_zero() {
        let local = MemLogStorage::new();
        let (id, entry) = make_entry(42, b"art-local", vec![]);

        local.insert_entry(id.clone(), entry).await.unwrap();

        let count = backfill(&local, &test_group(), id.clone(), |_id| async move {
            Err::<VerifiedEntry, _>("fetch must not be called".to_string())
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(
            count, 0,
            "entry already in local storage: must return Ok(0)"
        );
    }

    // ── backfill_truncated_at_limit ───────────────────────────────────────────
    //
    // An adversarial peer serves a chain longer than MAX_BACKFILL_ENTRIES.
    // backfill() must return BackfillError::Truncated rather than exhausting
    // memory by fetching all entries.
    //
    // We build a remote chain of MAX_BACKFILL_ENTRIES + 2 entries and verify
    // that Truncated is returned with fetched == MAX_BACKFILL_ENTRIES.

    #[tokio::test]
    async fn backfill_truncated_at_limit() {
        let chain_len = MAX_BACKFILL_ENTRIES + 2;
        let (remote, ids) = make_chain(chain_len).await;
        let local = MemLogStorage::new();

        let tip_id = ids[chain_len - 1].clone();

        let result = backfill(&local, &test_group(), tip_id, |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await;

        match result {
            Err(BackfillError::Truncated { fetched }) => {
                assert_eq!(
                    fetched, MAX_BACKFILL_ENTRIES,
                    "Truncated must report exactly MAX_BACKFILL_ENTRIES fetched"
                );
            }
            other => panic!("expected BackfillError::Truncated, got {other:?}"),
        }
    }

    // ── backfill_advances_tip_when_entry_present_but_not_tip ──────────────────
    //
    // If want_id is already in local storage but is NOT in the current tip set,
    // backfill must advance the tip set so that consumers see it as reachable.
    // This exercises the Bug 4 fix: the old code returned Ok(0) without
    // touching tips, leaving the caller believing it was fully synced while
    // the tip set pointed at a stale ancestor.

    #[tokio::test]
    async fn backfill_advances_tip_when_entry_present_but_not_tip() {
        let local = MemLogStorage::new();
        let group = test_group();

        // Build a two-entry chain: parent → child, using content-derived IDs.
        let (parent_id, parent_entry) = make_entry(1_000, b"art-parent", vec![]);
        let (child_id, child_entry) =
            make_entry(2_000, b"art-child", vec![entry_id_to_cid(&parent_id)]);

        local
            .insert_entry(parent_id.clone(), parent_entry)
            .await
            .unwrap();
        local
            .insert_entry(child_id.clone(), child_entry)
            .await
            .unwrap();

        // Manually set the tip to parent only — child is present but not a tip.
        local.set_tips(&group, &[parent_id.clone()]).await.unwrap();

        // Backfill for child_id: it's already present so no fetch calls.
        let count = backfill(&local, &group, child_id.clone(), |_id| async move {
            Err::<VerifiedEntry, _>("fetch must not be called".to_string())
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(count, 0, "no new entries fetched");

        // The tip set must now include child_id and must not include parent_id
        // (parent was retired by advance_tips).
        let tips = local.list_tips(&group).await.unwrap();
        let tip_keys: Vec<[u8; 32]> = tips.iter().map(|t| *t.as_bytes()).collect();
        assert!(
            tip_keys.contains(child_id.as_bytes()),
            "child_id must be a tip after backfill"
        );
        assert!(
            !tip_keys.contains(parent_id.as_bytes()),
            "parent_id must be retired from tips after backfill"
        );
    }
}
