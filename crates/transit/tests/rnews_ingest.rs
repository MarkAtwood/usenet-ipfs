//! Integration test: parse a 2-article rnews batch and ingest both articles
//! through the check_ingest + run_pipeline path.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stoa_core::{group_log::MemLogStorage, hlc::HlcTimestamp, msgid_map::MsgIdMap};
use stoa_transit::{
    import::rnews::parse_rnews_batch,
    peering::{
        ingestion::{check_ingest, extract_body_msgid, IngestResult},
        pipeline::{run_pipeline, IpfsStore, MemIpfsStore, PipelineCtx},
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn make_core_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url).await.unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (pool, tmp)
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

fn make_article(from: &str, newsgroups: &str, msgid: &str, subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\n\
         Newsgroups: {newsgroups}\r\n\
         Message-ID: {msgid}\r\n\
         Subject: {subject}\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         \r\n\
         {body}\r\n"
    )
    .into_bytes()
}

fn make_batch(articles: &[Vec<u8>]) -> Vec<u8> {
    let mut batch = Vec::new();
    for art in articles {
        let header = format!("#! rnews {}\n", art.len());
        batch.extend_from_slice(header.as_bytes());
        batch.extend_from_slice(art);
    }
    batch
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Parse a 2-article rnews batch and ingest both through the full pipeline.
/// Asserts that both articles have valid CIDs recorded in msgid_map.
#[tokio::test]
async fn test_rnews_ingest_two_articles_e2e() {
    sqlx::any::install_default_drivers();

    let (core_pool, _core_tmp) = make_core_pool().await;
    let (transit_pool, _transit_tmp) = make_transit_pool().await;

    let msgid_map = MsgIdMap::new(core_pool.clone());
    let log_storage = MemLogStorage::new();
    let ipfs = MemIpfsStore::new();
    let key = Arc::new(make_signing_key());

    // Build 2 minimal valid articles.
    let art1 = make_article(
        "alice@example.com",
        "misc.test",
        "<rnews-001@example.com>",
        "Test 1",
        "Body of article 1.",
    );
    let art2 = make_article(
        "bob@example.com",
        "misc.test",
        "<rnews-002@example.com>",
        "Test 2",
        "Body of article 2.",
    );

    // Construct and parse the batch.
    let batch = make_batch(&[art1, art2]);
    let articles = parse_rnews_batch(&batch).expect("batch must parse without error");
    assert_eq!(articles.len(), 2, "must parse exactly 2 articles");

    let mut accepted = 0usize;

    for (i, article_bytes) in articles.iter().enumerate() {
        // Extract Message-ID (folding-aware, matches production path).
        let msgid = extract_body_msgid(article_bytes)
            .unwrap_or_else(|| panic!("article {i} must have a Message-ID"));

        // check_ingest — should accept both.
        let result = check_ingest(&msgid, article_bytes, &msgid_map).await;
        assert_eq!(
            result,
            IngestResult::Accepted,
            "article {i} (msgid={msgid:?}) must be accepted, got {result:?}"
        );

        // run_pipeline — should succeed for both.
        let ts = {
            let mut ts = make_timestamp();
            ts.logical = i as u32;
            ts
        };
        let ctx = PipelineCtx {
            timestamp: ts,
            operator_signing_key: Arc::clone(&key),
            local_hostname: "test.example.com",
            verify_store: None,
            trusted_keys: Arc::from(vec![]),
            dkim_auth: None,
            group_filter: None,
        };

        let (pr, _metrics) = run_pipeline(
            article_bytes,
            &ipfs,
            &msgid_map,
            &log_storage,
            &transit_pool,
            ctx,
        )
        .await
        .unwrap_or_else(|e| panic!("pipeline must succeed for article {i}: {e:?}"));

        // Verify that the CID is recorded in msgid_map.
        let stored_cid = msgid_map
            .lookup_by_msgid(&msgid)
            .await
            .unwrap_or_else(|e| panic!("msgid_map lookup failed for article {i}: {e}"))
            .unwrap_or_else(|| panic!("CID must be recorded for article {i} (msgid={msgid:?})"));

        assert_eq!(
            stored_cid, pr.cid,
            "stored CID must match pipeline result for article {i}"
        );

        // Verify stored bytes contain the expected article content (independent oracle).
        // This catches bugs in prepend_path_header that might corrupt the article.
        // Message-ID and Newsgroups are unaffected by the Path: mutation.
        let stored_bytes = ipfs
            .get_raw(&pr.cid)
            .await
            .unwrap_or_else(|e| panic!("get_raw failed for article {i}: {e}"))
            .unwrap_or_else(|| panic!("block must exist in MemIpfsStore for article {i}"));
        let stored_text = String::from_utf8_lossy(&stored_bytes);
        let expected_msgid = if i == 0 {
            "<rnews-001@example.com>"
        } else {
            "<rnews-002@example.com>"
        };
        assert!(
            stored_text.contains(&format!("Message-ID: {expected_msgid}")),
            "article {i}: stored bytes must contain Message-ID: {expected_msgid}"
        );
        assert!(
            stored_text.contains("Newsgroups: misc.test"),
            "article {i}: stored bytes must contain Newsgroups: misc.test"
        );

        accepted += 1;
    }

    assert_eq!(accepted, 2, "both articles must be accepted and ingested");
}

/// Parse and ingest an article whose Message-ID header is RFC 5322 folded
/// (value on a continuation line starting with whitespace).
/// Verifies that the production folding-aware extractor accepts the article
/// and records its CID in msgid_map.
#[tokio::test]
async fn test_rnews_ingest_folded_message_id() {
    sqlx::any::install_default_drivers();

    let (core_pool, _core_tmp) = make_core_pool().await;
    let (transit_pool, _transit_tmp) = make_transit_pool().await;

    let msgid_map = MsgIdMap::new(core_pool.clone());
    let log_storage = MemLogStorage::new();
    let ipfs = MemIpfsStore::new();
    let key = Arc::new(make_signing_key());

    // Article with RFC 5322 folded Message-ID header
    // (continuation line starting with space).
    // Written as a flat concat so that no source indentation leaks in.
    let article: Vec<u8> = [
        b"From: test@example.com\r\n".as_ref(),
        b"Newsgroups: misc.test\r\n",
        b"Message-ID:\r\n",
        b" <folded-001@example.com>\r\n",
        b"Subject: Folded header test\r\n",
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n",
        b"\r\n",
        b"Body text.\r\n",
    ]
    .concat();

    let batch = make_batch(&[article]);
    let articles = parse_rnews_batch(&batch).expect("batch must parse without error");
    assert_eq!(articles.len(), 1, "must parse exactly 1 article");

    let article_bytes = &articles[0];

    // extract_body_msgid must unfold the continuation and return the bare Message-ID.
    let msgid = extract_body_msgid(article_bytes).expect("folded Message-ID must be extracted");
    assert_eq!(
        msgid, "<folded-001@example.com>",
        "extracted msgid must match the folded value"
    );

    // check_ingest must accept the article.
    let result = check_ingest(&msgid, article_bytes, &msgid_map).await;
    assert_eq!(
        result,
        IngestResult::Accepted,
        "article with folded Message-ID must be accepted, got {result:?}"
    );

    // run_pipeline must succeed.
    let ctx = PipelineCtx {
        timestamp: make_timestamp(),
        operator_signing_key: Arc::clone(&key),
        local_hostname: "test.example.com",
        verify_store: None,
        trusted_keys: Arc::from(vec![]),
        dkim_auth: None,
        group_filter: None,
    };

    let (pr, _metrics) = run_pipeline(
        article_bytes,
        &ipfs,
        &msgid_map,
        &log_storage,
        &transit_pool,
        ctx,
    )
    .await
    .expect("pipeline must succeed for folded-header article");

    // CID must be recorded in msgid_map.
    let stored_cid = msgid_map
        .lookup_by_msgid(&msgid)
        .await
        .expect("msgid_map lookup must not fail")
        .expect("CID must be recorded for folded-header article");

    assert_eq!(
        stored_cid, pr.cid,
        "stored CID must match pipeline result for folded-header article"
    );
}
