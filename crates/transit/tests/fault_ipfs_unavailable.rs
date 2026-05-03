//! Fault injection integration tests for IPFS unavailability in the transit pipeline.
//!
//! Verifies that:
//! - A pipeline run returns a transient error when IPFS is unavailable.
//! - No partial state (msgid_map entry, group log entry) is left on failure.
//! - Restoring IPFS availability allows subsequent ingestion to succeed.
//! - The NNTP IHAVE response for a transient pipeline error is 436.
//!
//! Independent oracles: RFC 977 §3.8 (IHAVE 436 = transient failure, retry later),
//! RFC 3977 §9.3.9.2 (436 Transfer not possible; try again later).

use async_trait::async_trait;
use cid::Cid;
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use stoa_core::{
    group_log::{LogStorage, MemLogStorage},
    hlc::HlcTimestamp,
    msgid_map::MsgIdMap,
};
use stoa_transit::peering::{
    ingestion::{ihave_response, IngestResult},
    pipeline::{run_pipeline, IpfsError, IpfsStore, MemIpfsStore, PipelineCtx, PipelineError},
};

// ── FailingIpfsStore ──────────────────────────────────────────────────────────

/// An `IpfsStore` that fails all writes while `should_fail` is `true`.
///
/// When `should_fail` is `false`, it delegates to an inner `MemIpfsStore`.
/// The `Arc<AtomicBool>` is shared with the caller so the fault can be cleared
/// between pipeline invocations to test recovery.
struct FailingIpfsStore {
    should_fail: Arc<AtomicBool>,
    inner: MemIpfsStore,
}

impl FailingIpfsStore {
    /// Construct a store that starts in the failing state.
    ///
    /// Returns the store and the shared flag; set the flag to `false` to
    /// restore normal operation.
    fn new() -> (Self, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(true));
        let store = Self {
            should_fail: Arc::clone(&flag),
            inner: MemIpfsStore::new(),
        };
        (store, flag)
    }
}

#[async_trait]
impl IpfsStore for FailingIpfsStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        if self.should_fail.load(Ordering::SeqCst) {
            Err(IpfsError::WriteFailed(
                "simulated IPFS unavailable".to_string(),
            ))
        } else {
            self.inner.put_raw(data).await
        }
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        if self.should_fail.load(Ordering::SeqCst) {
            Err(IpfsError::WriteFailed(
                "simulated IPFS unavailable".to_string(),
            ))
        } else {
            self.inner.get_raw(cid).await
        }
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url).await.unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (MsgIdMap::new(pool), tmp)
}

async fn make_transit_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_transit::migrations::run_migrations(&url)
        .await
        .unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (pool, tmp)
}

fn make_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn make_timestamp() -> HlcTimestamp {
    HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        node_id: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

fn make_ctx(key: &SigningKey) -> PipelineCtx<'static> {
    PipelineCtx {
        timestamp: make_timestamp(),
        operator_signing_key: Arc::new(key.clone()),
        local_hostname: "test.local",
        verify_store: None,
        trusted_keys: std::sync::Arc::from(vec![]),
        dkim_auth: None,
        group_filter: None,
    }
}

fn make_article(msgid: &str, group: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         Newsgroups: {group}\r\n\
         Subject: Fault injection test\r\n\
         \r\n\
         Article body.\r\n"
    )
    .into_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// When IPFS is unavailable, `run_pipeline` must return `Err` and the error
/// message must mention IPFS so that callers can map it to a transient NNTP
/// response (436 / 431) rather than a hard rejection.
#[tokio::test]
async fn ipfs_unavailable_returns_error() {
    let (map, _tmp) = make_msgid_map().await;
    let log_storage = MemLogStorage::new();
    let (ipfs, _flag) = FailingIpfsStore::new(); // starts in fail mode
    let key = make_signing_key();

    let article = make_article("<ipfs-fail@test.com>", "comp.test");

    let (transit_pool, _tmp_transit) = make_transit_pool().await;
    let result = run_pipeline(
        &article,
        &ipfs,
        &map,
        &log_storage,
        &transit_pool,
        make_ctx(&key),
    )
    .await;

    assert!(
        result.is_err(),
        "pipeline must return Err when IPFS is unavailable"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, PipelineError::Transient(_)),
        "IPFS write failure must be a transient (not permanent) error: {err}"
    );
}

/// When the IPFS write fails, neither the msgid_map nor the group log must
/// contain any record of the article. The pipeline must be atomic from the
/// caller's perspective: nothing is committed unless the IPFS write succeeds.
#[tokio::test]
async fn ipfs_unavailable_leaves_no_state() {
    let (map, _tmp) = make_msgid_map().await;
    let log_storage = MemLogStorage::new();
    let (ipfs, _flag) = FailingIpfsStore::new();
    let key = make_signing_key();

    let msgid = "<no-state@test.com>";
    let article = make_article(msgid, "comp.test");

    let (transit_pool, _tmp_transit) = make_transit_pool().await;
    let _ = run_pipeline(
        &article,
        &ipfs,
        &map,
        &log_storage,
        &transit_pool,
        make_ctx(&key),
    )
    .await;

    // msgid_map must have no entry for this article.
    let lookup = map.lookup_by_msgid(msgid).await.unwrap();
    assert!(
        lookup.is_none(),
        "msgid must not be stored in the map after an IPFS write failure"
    );

    // Group log must be empty.
    let group = stoa_core::article::GroupName::new("comp.test").unwrap();
    let tips = log_storage.list_tips(&group).await.unwrap();
    assert!(
        tips.is_empty(),
        "group log must be empty after an IPFS write failure"
    );
}

/// After a transient IPFS failure, restoring IPFS availability must allow the
/// same article to be ingested successfully on the next attempt.
///
/// This validates that the pipeline leaves no corrupt half-committed state that
/// would prevent a retry (e.g., no orphaned msgid_map entry that would trigger
/// a spurious duplicate rejection).
#[tokio::test]
async fn ipfs_restored_succeeds() {
    let (map, _tmp) = make_msgid_map().await;
    let log_storage = MemLogStorage::new();
    let (ipfs, fail_flag) = FailingIpfsStore::new();
    let key = make_signing_key();

    let msgid = "<restored@test.com>";
    let article = make_article(msgid, "comp.test");

    let (transit_pool, _tmp_transit) = make_transit_pool().await;

    // First attempt: IPFS unavailable, must fail.
    let first = run_pipeline(
        &article,
        &ipfs,
        &map,
        &log_storage,
        &transit_pool,
        make_ctx(&key),
    )
    .await;
    assert!(
        first.is_err(),
        "first pipeline run must fail while IPFS is unavailable"
    );

    // Restore IPFS availability.
    fail_flag.store(false, Ordering::SeqCst);

    // Second attempt: must succeed now that IPFS is back.
    let second = run_pipeline(
        &article,
        &ipfs,
        &map,
        &log_storage,
        &transit_pool,
        make_ctx(&key),
    )
    .await;
    assert!(
        second.is_ok(),
        "pipeline must succeed after IPFS is restored: {:?}",
        second
    );

    // Article must now be recorded in the msgid_map.
    let lookup = map.lookup_by_msgid(msgid).await.unwrap();
    assert!(
        lookup.is_some(),
        "msgid must be stored in the map after successful ingestion"
    );
    let (pr, _metrics) = second.unwrap();
    assert_eq!(
        lookup.unwrap(),
        pr.cid,
        "stored CID must match the CID returned by the pipeline"
    );
}

/// When the pipeline returns an error (mapped to `IngestResult::TransientError`
/// by the IHAVE handler), the NNTP response must be 436.
///
/// Independent oracle: RFC 977 §3.8 — "436 Transfer failed, try again later"
/// is the correct response when the server experiences a transient failure.
#[test]
fn ihave_transient_error_response_is_436() {
    let result = IngestResult::TransientError("IPFS write failed".to_string());
    let resp = ihave_response(&result);
    assert!(
        resp.starts_with("436"),
        "IHAVE response for TransientError must be 436 (RFC 977 §3.8), got: {resp}"
    );
}
