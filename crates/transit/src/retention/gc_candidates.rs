//! GC candidate selection: queries the article metadata store for CIDs
//! eligible for unpinning.

use cid::Cid;
use sqlx::AnyPool;
use stoa_core::error::StorageError;

use crate::retention::policy::{ArticleMeta, PinPolicy};

/// A CID and its associated metadata, ready for GC evaluation.
#[derive(Debug)]
pub struct GcArticleRecord {
    pub cid: Cid,
    pub group: String,
    pub ingested_at_ms: u64,
    pub byte_count: usize,
}

/// Query the database for articles that are GC candidates.
///
/// Returns articles that:
/// - Are stored in the local article store
/// - Are older than `grace_period_ms` milliseconds from `now_ms`
/// - Are NOT covered by any pinning policy rule (policy.should_pin returns false)
///
/// The caller passes in the current time and the grace period. The policy
/// is evaluated in-process using ArticleMeta built from the row data.
///
/// # DECISION (rbe3.2): policy evaluation stays in Rust, not SQL
///
/// The primary age predicate (`ingested_at_ms < cutoff_ms`) is pushed to
/// SQL and uses the `idx_articles_ingested_at` index, so the query is not
/// a full table scan.  The remaining policy predicates (group glob patterns,
/// `max_article_bytes`, first-rule-wins semantics, cross-posting) cannot be
/// expressed as a single SQL predicate because:
/// - Glob patterns (`comp.*`, `all`) are not a SQL built-in.
/// - Cross-posted articles list multiple groups in one field; SQL cannot
///   split on commas and match each independently against a rule set.
/// - First-rule-wins semantics across an ordered rule list have no SQL
///   equivalent without a recursive CTE or application-side logic.
///
/// The result set is already bounded to `now - grace_period` rows, which
/// is typically a small fraction of the total `articles` table, so the
/// in-process evaluation adds negligible overhead.
///
/// Do NOT inline the policy into a SQL WHERE clause; the semantics would
/// be incorrect for cross-posted articles and multi-rule policies.
pub async fn select_gc_candidates(
    pool: &AnyPool,
    policy: &PinPolicy,
    now_ms: u64,
    grace_period_ms: u64,
) -> Result<Vec<GcArticleRecord>, StorageError> {
    let cutoff_ms = now_ms.saturating_sub(grace_period_ms) as i64;

    // pinned_cids is created by the migration; no DDL here.
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT cid, group_name, ingested_at_ms, byte_count
         FROM articles
         WHERE ingested_at_ms < ?
           AND cid NOT IN (SELECT cid FROM pinned_cids)",
    )
    .bind(cutoff_ms)
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let ms_per_day: u64 = 24 * 60 * 60 * 1000;
    let mut candidates = Vec::new();

    for (cid_str, group_name, ingested_at_ms_raw, byte_count_raw) in rows {
        let cid = cid_str
            .parse::<Cid>()
            .map_err(|e| StorageError::Database(format!("invalid CID in database: {e}")))?;

        let ingested_at_ms = ingested_at_ms_raw as u64;
        let byte_count = byte_count_raw as usize;
        let group = if group_name.is_empty() {
            "unknown".to_string()
        } else {
            group_name
        };

        let age_days = now_ms.saturating_sub(ingested_at_ms) / ms_per_day;
        let meta = ArticleMeta {
            group: group.clone(),
            size_bytes: byte_count,
            age_days,
        };

        if !policy.should_pin(&meta) {
            candidates.push(GcArticleRecord {
                cid,
                group,
                ingested_at_ms,
                byte_count,
            });
        }
    }

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::retention::policy::{PinAction, PinRule};
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        run_migrations(&url).await.expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (pool, tmp)
    }

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn insert_article(
        pool: &AnyPool,
        cid: &Cid,
        group: &str,
        ingested_at_ms: i64,
        byte_count: i64,
    ) {
        let cid_str = cid.to_string();
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) VALUES (?, ?, ?, ?)",
        )
        .bind(cid_str)
        .bind(group)
        .bind(ingested_at_ms)
        .bind(byte_count)
        .execute(pool)
        .await
        .expect("insert article");
    }

    const NOW_MS: u64 = 1_700_000_000_000;
    const GRACE_MS: u64 = 1_000_000;

    #[tokio::test]
    async fn gc_candidates_empty_db_returns_empty() {
        let (pool, _tmp) = make_pool().await;
        let policy = PinPolicy::new(vec![]);
        let result = select_gc_candidates(&pool, &policy, NOW_MS, GRACE_MS)
            .await
            .expect("query");
        assert!(result.is_empty(), "empty db should return no candidates");
    }

    #[tokio::test]
    async fn gc_candidates_within_grace_excluded() {
        let (pool, _tmp) = make_pool().await;
        let cid = make_cid(b"within-grace");
        // Article ingested right at now_ms — well within the grace period
        insert_article(&pool, &cid, "comp.lang.rust", NOW_MS as i64, 512).await;

        let policy = PinPolicy::new(vec![]);
        let result = select_gc_candidates(&pool, &policy, NOW_MS, GRACE_MS)
            .await
            .expect("query");
        assert_eq!(
            result.len(),
            0,
            "article within grace period must be excluded"
        );
    }

    #[tokio::test]
    async fn gc_candidates_pinned_excluded() {
        let (pool, _tmp) = make_pool().await;
        let old_ms = NOW_MS - GRACE_MS * 2;
        for i in 0u8..2 {
            let cid = make_cid(&[i]);
            insert_article(&pool, &cid, "comp.lang.rust", old_ms as i64, 512).await;
        }

        let policy = PinPolicy::new(vec![PinRule {
            groups: "all".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        }]);
        let result = select_gc_candidates(&pool, &policy, NOW_MS, GRACE_MS)
            .await
            .expect("query");
        assert_eq!(result.len(), 0, "pinned articles must not be GC candidates");
    }

    async fn insert_pinned_cid(pool: &AnyPool, cid: &Cid) {
        let cid_str = cid.to_string();
        sqlx::query("INSERT INTO pinned_cids (cid, pinned_at_ms) VALUES (?, 0)")
            .bind(cid_str)
            .execute(pool)
            .await
            .expect("insert pinned_cid");
    }

    #[tokio::test]
    async fn gc_candidates_db_pinned_excluded() {
        let (pool, _tmp) = make_pool().await;
        let old_ms = NOW_MS - GRACE_MS * 2;
        let pinned_cid = make_cid(b"pinned");
        let free_cid = make_cid(b"free");

        insert_article(&pool, &pinned_cid, "comp.lang.rust", old_ms as i64, 512).await;
        insert_article(&pool, &free_cid, "comp.lang.rust", old_ms as i64, 512).await;
        insert_pinned_cid(&pool, &pinned_cid).await;

        let policy = PinPolicy::new(vec![]);
        let result = select_gc_candidates(&pool, &policy, NOW_MS, GRACE_MS)
            .await
            .expect("query");
        assert_eq!(
            result.len(),
            1,
            "only the non-pinned article must be returned"
        );
        assert_eq!(
            result[0].cid, free_cid,
            "the returned candidate must be the unpinned CID"
        );
    }

    #[tokio::test]
    async fn gc_candidates_unpinned_returned() {
        let (pool, _tmp) = make_pool().await;
        let old_ms = NOW_MS - GRACE_MS * 2;
        for i in 0u8..3 {
            let cid = make_cid(&[i]);
            insert_article(&pool, &cid, "comp.lang.rust", old_ms as i64, 512).await;
        }

        let policy = PinPolicy::new(vec![]);
        let result = select_gc_candidates(&pool, &policy, NOW_MS, GRACE_MS)
            .await
            .expect("query");
        assert_eq!(
            result.len(),
            3,
            "all 3 unpinned old articles must be returned"
        );
    }
}
