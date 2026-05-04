/// Shared test helpers for `LogStorage` implementations.
///
/// These are plain async functions (not `#[test]`). Each concrete storage
/// module calls them from its own `#[tokio::test]` wrappers so both
/// `MemLogStorage` and `SqliteLogStorage` exercise the same contract.
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::hlc::HlcTimestamp;

// ── helpers ──────────────────────────────────────────────────────────────────

fn test_cid(data: &[u8]) -> Cid {
    let digest = Code::Sha2_256.digest(data);
    Cid::new_v1(0x71, digest)
}

fn make_entry(seed: &[u8]) -> LogEntry {
    LogEntry {
        hlc_timestamp: HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 0,
            node_id: [0; 8],
        },
        article_cid: test_cid(seed),
        operator_signature: vec![0xde, 0xad, 0xbe, 0xef],
        parent_cids: vec![],
    }
}

fn make_id(byte: u8) -> LogEntryId {
    LogEntryId::from_bytes([byte; 32])
}

fn make_group(name: &str) -> GroupName {
    GroupName::new(name).expect("valid group name")
}

// ── test functions ────────────────────────────────────────────────────────────

pub async fn test_insert_and_get(storage: &impl LogStorage) {
    let id = make_id(0x01);
    let entry = make_entry(b"article-a");

    storage
        .insert_entry(id.clone(), entry.clone())
        .await
        .expect("insert should succeed");

    let fetched = storage
        .get_entry(&id)
        .await
        .expect("get should not error")
        .expect("entry should be present");

    assert_eq!(fetched.hlc_timestamp, entry.hlc_timestamp);
    assert_eq!(fetched.article_cid, entry.article_cid);
    assert_eq!(fetched.operator_signature, entry.operator_signature);
}

pub async fn test_get_missing_returns_none(storage: &impl LogStorage) {
    let id = make_id(0xfe);
    let result = storage.get_entry(&id).await.expect("get should not error");
    assert!(result.is_none(), "expected None for missing entry");
}

pub async fn test_has_entry(storage: &impl LogStorage) {
    let id = make_id(0x02);
    let absent = storage
        .has_entry(&id)
        .await
        .expect("has_entry should not error");
    assert!(!absent, "entry should be absent before insert");

    storage
        .insert_entry(id.clone(), make_entry(b"article-b"))
        .await
        .expect("insert should succeed");

    let present = storage
        .has_entry(&id)
        .await
        .expect("has_entry should not error");
    assert!(present, "entry should be present after insert");
}

pub async fn test_set_and_list_tips(storage: &impl LogStorage) {
    let group = make_group("comp.lang.rust");
    let id1 = make_id(0x10);
    let id2 = make_id(0x11);

    // Initially no tips.
    let tips = storage
        .list_tips(&group)
        .await
        .expect("list_tips should not error");
    assert!(tips.is_empty(), "expected empty tips before set");

    // Set two tips.
    storage
        .set_tips(&group, &[id1.clone(), id2.clone()])
        .await
        .expect("set_tips should succeed");

    let tips = storage
        .list_tips(&group)
        .await
        .expect("list_tips should not error");
    assert_eq!(tips.len(), 2, "expected 2 tips");

    let tip_bytes: Vec<[u8; 32]> = tips.iter().map(|id| *id.as_bytes()).collect();
    assert!(tip_bytes.contains(id1.as_bytes()), "id1 should be in tips");
    assert!(tip_bytes.contains(id2.as_bytes()), "id2 should be in tips");

    // Replace tips — atomic overwrite.
    let id3 = make_id(0x12);
    storage
        .set_tips(&group, std::slice::from_ref(&id3))
        .await
        .expect("set_tips replace should succeed");

    let tips = storage
        .list_tips(&group)
        .await
        .expect("list_tips should not error");
    assert_eq!(tips.len(), 1, "expected 1 tip after replace");
    assert_eq!(*tips[0].as_bytes(), *id3.as_bytes());
}

pub async fn test_tip_count(storage: &impl LogStorage) {
    let group = make_group("sci.math");

    let count = storage
        .tip_count(&group)
        .await
        .expect("tip_count should not error");
    assert_eq!(count, 0, "expected 0 before any tips set");

    let id1 = make_id(0x20);
    let id2 = make_id(0x21);
    storage
        .set_tips(&group, &[id1, id2])
        .await
        .expect("set_tips should succeed");

    let count = storage
        .tip_count(&group)
        .await
        .expect("tip_count should not error");
    assert_eq!(count, 2, "expected 2 after setting 2 tips");
}

pub async fn test_duplicate_insert_rejected(storage: &impl LogStorage) {
    let id = make_id(0x30);
    storage
        .insert_entry(id.clone(), make_entry(b"first"))
        .await
        .expect("first insert should succeed");

    let result = storage
        .insert_entry(id.clone(), make_entry(b"second"))
        .await;
    assert!(
        matches!(result, Err(StorageError::DuplicateEntry(_))),
        "duplicate insert should return DuplicateEntry, got: {result:?}"
    );
}

/// `advance_tips` removes the specified parents and adds the new tip.
pub async fn test_advance_tips_basic(storage: &impl LogStorage) {
    let group = make_group("comp.advance");
    let old1 = make_id(0x50);
    let old2 = make_id(0x51);
    let new_tip = make_id(0x52);

    // Set two initial tips.
    storage
        .set_tips(&group, &[old1.clone(), old2.clone()])
        .await
        .expect("set_tips initial");

    // Advance: remove old1, keep old2, add new_tip.
    storage
        .advance_tips(&group, std::slice::from_ref(&old1), &new_tip)
        .await
        .expect("advance_tips should succeed");

    let tips = storage.list_tips(&group).await.expect("list_tips");
    let tip_bytes: Vec<[u8; 32]> = tips.iter().map(|id| *id.as_bytes()).collect();
    assert!(!tip_bytes.contains(old1.as_bytes()), "old1 must be removed");
    assert!(tip_bytes.contains(old2.as_bytes()), "old2 must survive");
    assert!(
        tip_bytes.contains(new_tip.as_bytes()),
        "new_tip must be added"
    );
    assert_eq!(tips.len(), 2, "must have exactly 2 tips: old2 and new_tip");
}

/// Concurrent appends sharing the same parent both survive as tips.
pub async fn test_advance_tips_concurrent(storage: &impl LogStorage) {
    let group = make_group("comp.concurrent");
    let parent = make_id(0x60);
    let tip_a = make_id(0x61);
    let tip_b = make_id(0x62);

    storage
        .set_tips(&group, std::slice::from_ref(&parent))
        .await
        .expect("set_tips parent");

    // Simulate two concurrent appends that both remove `parent`.
    storage
        .advance_tips(&group, std::slice::from_ref(&parent), &tip_a)
        .await
        .expect("advance_tips A");
    storage
        .advance_tips(&group, std::slice::from_ref(&parent), &tip_b)
        .await
        .expect("advance_tips B");

    let tips = storage.list_tips(&group).await.expect("list_tips");
    let tip_bytes: Vec<[u8; 32]> = tips.iter().map(|id| *id.as_bytes()).collect();
    assert!(
        !tip_bytes.contains(parent.as_bytes()),
        "parent must be gone"
    );
    assert!(tip_bytes.contains(tip_a.as_bytes()), "tip_a must survive");
    assert!(tip_bytes.contains(tip_b.as_bytes()), "tip_b must survive");
    assert_eq!(tips.len(), 2, "both concurrent tips must be present");
}

pub async fn test_tips_are_group_scoped(storage: &impl LogStorage) {
    let group_a = make_group("alt.test");
    let group_b = make_group("misc.test");
    let id_a = make_id(0x40);
    let id_b = make_id(0x41);

    storage
        .set_tips(&group_a, std::slice::from_ref(&id_a))
        .await
        .expect("set_tips group_a");
    storage
        .set_tips(&group_b, std::slice::from_ref(&id_b))
        .await
        .expect("set_tips group_b");

    let tips_a = storage
        .list_tips(&group_a)
        .await
        .expect("list_tips group_a");
    let tips_b = storage
        .list_tips(&group_b)
        .await
        .expect("list_tips group_b");

    assert_eq!(tips_a.len(), 1);
    assert_eq!(*tips_a[0].as_bytes(), *id_a.as_bytes());
    assert_eq!(tips_b.len(), 1);
    assert_eq!(*tips_b[0].as_bytes(), *id_b.as_bytes());
}
