//! Property-based tests for the group log CRDT.
//!
//! Uses proptest to generate arbitrary diverged group logs and verify
//! reconciliation properties.
//!
//! # DECISION (rbe3.70): property-based testing is mandatory for CRDT commutativity
//!
//! The commutativity property (want(A→B) ⊆ have(B→A) and vice versa) cannot
//! be adequately verified with hand-crafted unit tests: there are too many edge
//! cases (empty sets, full overlap, partial overlap, duplicate seeds).  Proptest
//! generates 1000 randomly-shaped diverged log pairs and shrinks counter-examples
//! automatically.  Do NOT replace this with example-based tests — they cannot
//! explore the state space exhaustively and have historically missed CRDT edge cases.

use std::collections::HashSet;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use proptest::prelude::*;
use stoa_core::{
    group_log::{
        mem_storage::MemLogStorage,
        reconcile::reconcile,
        storage::LogStorage,
        types::{LogEntry, LogEntryId},
    },
    hlc::HlcTimestamp,
    GroupName,
};

fn make_entry_id(seed: u8) -> LogEntryId {
    let digest = Code::Sha2_256.digest(&[seed]);
    LogEntryId::from_bytes(digest.digest().try_into().expect("SHA2-256 is 32 bytes"))
}

fn make_entry(hlc: u64) -> LogEntry {
    LogEntry {
        hlc_timestamp: HlcTimestamp {
            wall_ms: hlc,
            logical: 0,
            node_id: [0; 8],
        },
        article_cid: Cid::new_v1(0x71, Code::Sha2_256.digest(&[hlc as u8])),
        operator_signature: vec![],
        parent_cids: vec![],
    }
}

fn test_group() -> GroupName {
    GroupName::new("comp.test").unwrap()
}

/// Generate a vec of 0–8 distinct entry seeds (u8 values 0–127).
fn entry_seeds() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=127u8, 0..=8).prop_map(|mut v| {
        v.sort();
        v.dedup();
        v
    })
}

/// A pair of diverged entry seed sets (A and B may overlap partially).
fn diverged_logs() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
    (entry_seeds(), entry_seeds())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Commutativity: want(A→B) ⊆ have(B→A) and want(B→A) ⊆ have(A→B).
    ///
    /// The v1 algorithm uses direct-tip-only `want`, so the property is
    /// containment rather than equality: every ID A requests from B is
    /// something B actually has to offer, and vice versa.
    #[test]
    fn reconcile_commutativity((seeds_a, seeds_b) in diverged_logs()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (violation_a, violation_b) = rt.block_on(async {
            let storage_a = MemLogStorage::new();
            let storage_b = MemLogStorage::new();
            let group = test_group();

            let mut tips_a = Vec::new();
            for (i, &seed) in seeds_a.iter().enumerate() {
                let id = make_entry_id(seed);
                storage_a.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_a.push(id);
            }
            if !tips_a.is_empty() {
                storage_a.set_tips(&group, &tips_a).await.unwrap();
            }

            let mut tips_b = Vec::new();
            for (i, &seed) in seeds_b.iter().enumerate() {
                let id = make_entry_id(seed);
                storage_b.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_b.push(id);
            }
            if !tips_b.is_empty() {
                storage_b.set_tips(&group, &tips_b).await.unwrap();
            }

            let result_a = reconcile(&storage_a, &group, &tips_b).await.unwrap();
            let result_b = reconcile(&storage_b, &group, &tips_a).await.unwrap();

            // want(A→B) ⊆ have(B→A)
            let have_b: HashSet<[u8; 32]> =
                result_b.have.iter().map(|id| *id.as_bytes()).collect();
            let violation_a = result_a
                .want
                .iter()
                .find(|id| !have_b.contains(id.as_bytes()))
                .cloned();

            // want(B→A) ⊆ have(A→B)
            let have_a: HashSet<[u8; 32]> =
                result_a.have.iter().map(|id| *id.as_bytes()).collect();
            let violation_b = result_b
                .want
                .iter()
                .find(|id| !have_a.contains(id.as_bytes()))
                .cloned();

            (violation_a, violation_b)
        });

        prop_assert!(
            violation_a.is_none(),
            "commutativity violation: A wants {} but B does not have it",
            violation_a.unwrap()
        );
        prop_assert!(
            violation_b.is_none(),
            "commutativity violation: B wants {} but A does not have it",
            violation_b.unwrap()
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Setting the same tip ID twice leaves exactly one copy in the tip list.
    ///
    /// `set_tips` is a replace-not-append operation, so calling it with
    /// `[id]` twice must produce the same single-element result as calling it
    /// once.  This guards against accidental accumulation.
    #[test]
    fn set_tips_idempotent(seed in 0u8..=127u8) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (tips_after_one, tips_after_two) = rt.block_on(async {
            let storage = MemLogStorage::new();
            let group = test_group();
            let id = make_entry_id(seed);
            storage.insert_entry(id.clone(), make_entry(seed as u64)).await.unwrap();

            storage.set_tips(&group, &[id.clone()]).await.unwrap();
            let tips_after_one = storage.list_tips(&group).await.unwrap();

            storage.set_tips(&group, &[id.clone()]).await.unwrap();
            let tips_after_two = storage.list_tips(&group).await.unwrap();

            (tips_after_one, tips_after_two)
        });
        prop_assert_eq!(
            tips_after_one.len(),
            tips_after_two.len(),
            "tip count changed after setting the same tip twice: {} vs {}",
            tips_after_one.len(),
            tips_after_two.len(),
        );
        prop_assert_eq!(
            tips_after_two.len(),
            1,
            "expected exactly one tip, got {}",
            tips_after_two.len(),
        );
    }
}

fn n_entries() -> impl Strategy<Value = usize> {
    1usize..=20usize
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Two partitioned nodes with disjoint entries converge after reconciliation rounds.
    ///
    /// Node A holds entries with even seeds; Node B holds entries with odd seeds.
    /// Rounds of reconcile-then-transfer must drain both `want` sets within a
    /// bounded number of iterations, leaving identical tip sets on both sides.
    #[test]
    fn convergence_after_partition(n in n_entries()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let violation = rt.block_on(async {
            let storage_a = MemLogStorage::new();
            let storage_b = MemLogStorage::new();
            let group = test_group();

            // Node A gets n entries with even seeds.
            let mut tips_a = Vec::new();
            for i in 0..n {
                let seed = (i * 2) as u8;
                let id = make_entry_id(seed);
                storage_a.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_a.push(id);
            }
            if !tips_a.is_empty() {
                storage_a.set_tips(&group, &tips_a).await.unwrap();
            }

            // Node B gets n entries with odd seeds.
            let mut tips_b = Vec::new();
            for i in 0..n {
                let seed = (i * 2 + 1) as u8;
                let id = make_entry_id(seed);
                storage_b.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_b.push(id);
            }
            if !tips_b.is_empty() {
                storage_b.set_tips(&group, &tips_b).await.unwrap();
            }

            // Simulate reconciliation rounds until both want sets are empty.
            let max_rounds = n + 5;
            for _round in 0..max_rounds {
                let curr_tips_a = storage_a.list_tips(&group).await.unwrap();
                let curr_tips_b = storage_b.list_tips(&group).await.unwrap();

                let result_a = reconcile(&storage_a, &group, &curr_tips_b).await.unwrap();
                let result_b = reconcile(&storage_b, &group, &curr_tips_a).await.unwrap();

                if result_a.want.is_empty() && result_b.want.is_empty() {
                    break;
                }

                // Transfer: A fetches what it wants from B.
                for id in &result_a.want {
                    if let Ok(Some(entry)) = storage_b.get_entry(id).await {
                        let _ = storage_a.insert_entry(id.clone(), entry).await;
                    }
                }

                // Transfer: B fetches what it wants from A.
                for id in &result_b.want {
                    if let Ok(Some(entry)) = storage_a.get_entry(id).await {
                        let _ = storage_b.insert_entry(id.clone(), entry).await;
                    }
                }

                // Update A's tip set to include newly received entries.
                let mut new_tips_a = storage_a.list_tips(&group).await.unwrap();
                for id in &result_a.want {
                    if storage_a.has_entry(id).await.unwrap_or(false) && !new_tips_a.contains(id) {
                        new_tips_a.push(id.clone());
                    }
                }
                if !new_tips_a.is_empty() {
                    storage_a.set_tips(&group, &new_tips_a).await.unwrap();
                }

                // Update B's tip set to include newly received entries.
                let mut new_tips_b = storage_b.list_tips(&group).await.unwrap();
                for id in &result_b.want {
                    if storage_b.has_entry(id).await.unwrap_or(false) && !new_tips_b.contains(id) {
                        new_tips_b.push(id.clone());
                    }
                }
                if !new_tips_b.is_empty() {
                    storage_b.set_tips(&group, &new_tips_b).await.unwrap();
                }
            }

            // Final check: both nodes must have empty want sets.
            let final_tips_a = storage_a.list_tips(&group).await.unwrap();
            let final_tips_b = storage_b.list_tips(&group).await.unwrap();
            let final_result_a = reconcile(&storage_a, &group, &final_tips_b).await.unwrap();
            let final_result_b = reconcile(&storage_b, &group, &final_tips_a).await.unwrap();

            if !final_result_a.want.is_empty() {
                Some(format!(
                    "A still wants {:?} after reconciliation",
                    final_result_a.want
                ))
            } else if !final_result_b.want.is_empty() {
                Some(format!(
                    "B still wants {:?} after reconciliation",
                    final_result_b.want
                ))
            } else {
                None
            }
        });
        prop_assert!(violation.is_none(), "convergence failed: {:?}", violation);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Reconciling a node against its own tip set produces empty want and have.
    #[test]
    fn reconcile_against_self_is_empty(seeds in entry_seeds()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (want, have) = rt.block_on(async {
            let storage = MemLogStorage::new();
            let group = test_group();

            let mut tips = Vec::new();
            for (i, &seed) in seeds.iter().enumerate() {
                let id = make_entry_id(seed);
                storage.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips.push(id);
            }
            if !tips.is_empty() {
                storage.set_tips(&group, &tips).await.unwrap();
            }

            let current_tips = storage.list_tips(&group).await.unwrap();
            let result = reconcile(&storage, &group, &current_tips).await.unwrap();
            (result.want, result.have)
        });

        prop_assert!(
            want.is_empty(),
            "reconciling against self must have empty want: {:?}",
            want
        );
        prop_assert!(
            have.is_empty(),
            "reconciling against self must have empty have: {:?}",
            have
        );
    }
}
