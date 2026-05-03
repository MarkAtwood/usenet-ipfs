//! Periodic sampler for per-group Prometheus gauges.
//!
//! Queries the `articles` table once per interval and updates three gauges:
//!
//! | Metric                          | Source                              |
//! |---------------------------------|-------------------------------------|
//! | `group_log_entries_total{group}`| `COUNT(*)` from `articles`          |
//! | `group_storage_bytes{group}`    | `SUM(byte_count)` from `articles`   |
//! | `group_last_activity_timestamp` | `MAX(ingested_at_ms)` from `articles`|
//!
//! Note: `group_log_lag{group,peer}` is not yet implemented; it requires
//! per-session peer-state tracking that was removed with gossipsub.
//!
//! **High-cardinality guard**: if more than [`HIGH_CARDINALITY_LIMIT`] distinct
//! groups are active, the gauges are not updated and a warning is emitted.
//! This prevents unbounded Prometheus label explosion.

use sqlx::AnyPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Maximum number of distinct groups before per-group gauges are suppressed.
pub const HIGH_CARDINALITY_LIMIT: usize = 500;

/// Spawn-and-forget background task: samples per-group metrics every `interval`.
pub async fn run_group_metrics_sampler(pool: Arc<AnyPool>, interval: Duration) {
    let mut prev_groups: HashSet<String> = HashSet::new();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match sample_group_metrics(&pool, &prev_groups).await {
            Ok(current_groups) => {
                prev_groups = current_groups;
            }
            Err(e) => {
                tracing::warn!("group metrics sampling failed: {e}");
            }
        }
    }
}

/// Run one sampling pass.
///
/// `prev_groups` is the set of group names seen in the previous tick.  Any
/// group that was in `prev_groups` but is absent from the current query result
/// has had all its articles removed (e.g. by GC); its Prometheus label is
/// removed so it stops appearing in dashboards.
///
/// Returns the set of group names seen in this tick; the caller should pass
/// that back in as `prev_groups` on the next tick.
///
/// Returns `Err` only on a database error.  The high-cardinality guard
/// cleans up stale labels and returns `Ok(HashSet::new())`; the caller
/// should update `prev_groups` to that empty set so the stale-label
/// removal loop is a no-op on subsequent high-cardinality ticks.
pub async fn sample_group_metrics(
    pool: &AnyPool,
    prev_groups: &HashSet<String>,
) -> Result<HashSet<String>, String> {
    // Single query for all three metrics; GROUP BY is O(articles) either way.
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT group_name,
                COUNT(*),
                COALESCE(SUM(byte_count), 0),
                COALESCE(MAX(ingested_at_ms), 0)
         FROM articles
         GROUP BY group_name
         ORDER BY group_name",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("articles GROUP BY query failed: {e}"))?;

    let group_count = rows.len();

    if group_count > HIGH_CARDINALITY_LIMIT {
        tracing::warn!(
            group_count,
            limit = HIGH_CARDINALITY_LIMIT,
            "per-group metrics suppressed: active group count exceeds limit"
        );
        // Remove stale labels from the previous tick before returning.  Without
        // this, any group that was labelled before cardinality spiked would be
        // retained in Prometheus indefinitely (the normal stale-label removal
        // below only runs when cardinality is within the limit).
        for gone in prev_groups.iter() {
            let _ = crate::metrics::GROUP_LOG_ENTRIES_TOTAL.remove_label_values(&[gone]);
            let _ = crate::metrics::GROUP_STORAGE_BYTES.remove_label_values(&[gone]);
            let _ = crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP.remove_label_values(&[gone]);
        }
        // Return empty set; the caller updates prev_groups to empty so the
        // stale-label loop above is a no-op on subsequent high-cardinality ticks.
        return Ok(HashSet::new());
    }

    let current_groups: HashSet<String> = rows.iter().map(|(g, ..)| g.clone()).collect();

    for (group_name, count, total_bytes, last_at_ms) in &rows {
        crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&[group_name])
            .set(*count as f64);

        crate::metrics::GROUP_STORAGE_BYTES
            .with_label_values(&[group_name])
            .set(*total_bytes as f64);

        // Convert milliseconds to seconds for a standard Unix-epoch gauge.
        crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP
            .with_label_values(&[group_name])
            .set(*last_at_ms as f64 / 1000.0);
    }

    // Remove labels for groups that were present last tick but are gone now
    // (all articles GC'd).  Ignoring errors: remove_label_values returns Err
    // only when the label set was not registered, which is harmless here.
    for gone in prev_groups.difference(&current_groups) {
        let _ = crate::metrics::GROUP_LOG_ENTRIES_TOTAL.remove_label_values(&[gone]);
        let _ = crate::metrics::GROUP_STORAGE_BYTES.remove_label_values(&[gone]);
        let _ = crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP.remove_label_values(&[gone]);
    }

    Ok(current_groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn insert_article(
        pool: &AnyPool,
        cid: &str,
        group: &str,
        ingested_at_ms: i64,
        byte_count: i64,
    ) {
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(cid)
        .bind(group)
        .bind(ingested_at_ms)
        .bind(byte_count)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sample_empty_db_returns_zero_groups() {
        let (pool, _tmp) = make_pool().await;
        let groups = sample_group_metrics(&pool, &HashSet::new()).await.unwrap();
        assert_eq!(
            groups.len(),
            0,
            "empty articles table should return 0 groups"
        );
    }

    #[tokio::test]
    async fn sample_single_group_sets_gauges() {
        let (pool, _tmp) = make_pool().await;
        insert_article(&pool, "<a@t>", "comp.lang.rust", 1_700_000_000_000, 1024).await;
        insert_article(&pool, "<b@t>", "comp.lang.rust", 1_700_000_001_000, 2048).await;

        let groups = sample_group_metrics(&pool, &HashSet::new()).await.unwrap();
        assert_eq!(groups.len(), 1);

        let entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert_eq!(entries, 2.0, "expected 2 entries for comp.lang.rust");

        let bytes = crate::metrics::GROUP_STORAGE_BYTES
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert_eq!(bytes, 3072.0, "expected 3072 bytes for comp.lang.rust");

        let last_ts = crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert!(
            (last_ts - 1_700_000_001.0).abs() < 0.001,
            "expected last activity ~1700000001s, got {last_ts}"
        );
    }

    #[tokio::test]
    async fn sample_multiple_groups() {
        let (pool, _tmp) = make_pool().await;
        insert_article(&pool, "<c1@t>", "alt.test", 1_000_000_000_000, 512).await;
        insert_article(&pool, "<c2@t>", "sci.math", 1_000_000_002_000, 256).await;
        insert_article(&pool, "<c3@t>", "sci.math", 1_000_000_004_000, 256).await;

        let groups = sample_group_metrics(&pool, &HashSet::new()).await.unwrap();
        assert_eq!(groups.len(), 2, "expected 2 distinct groups");

        let alt_entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["alt.test"])
            .get();
        assert_eq!(alt_entries, 1.0);

        let sci_entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["sci.math"])
            .get();
        assert_eq!(sci_entries, 2.0);
    }

    #[tokio::test]
    async fn high_cardinality_guard_suppresses_updates() {
        let (pool, _tmp) = make_pool().await;

        // Insert articles in more than HIGH_CARDINALITY_LIMIT distinct groups.
        // Each group gets one article; group names are "g.0", "g.1", ..., "g.N".
        let n_groups = HIGH_CARDINALITY_LIMIT + 1;
        for i in 0..n_groups {
            let cid = format!("<hc-{i}@t>");
            let group = format!("g.{i}");
            insert_article(&pool, &cid, &group, 1_000_000_000_000 + i as i64, 100).await;
        }

        let groups = sample_group_metrics(&pool, &HashSet::new()).await.unwrap();
        // Guard fires: returns empty set (no gauges set).
        assert_eq!(
            groups.len(),
            0,
            "guard must return empty set when cardinality exceeded"
        );

        // Gauges for group "g.0" must NOT have been updated (guard suppressed).
        // They will be absent (0.0 default) because these are new label values.
        let entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["g.0"])
            .get();
        assert_eq!(
            entries, 0.0,
            "gauge must not be set when cardinality guard fires"
        );
    }

    #[tokio::test]
    async fn stale_gauge_removed_after_gc() {
        let (pool, _tmp) = make_pool().await;
        insert_article(&pool, "<d1@t>", "alt.gone", 1_000_000_000_000, 100).await;

        // First tick: alt.gone is present.
        let prev = sample_group_metrics(&pool, &HashSet::new()).await.unwrap();
        assert!(prev.contains("alt.gone"));
        assert_eq!(
            crate::metrics::GROUP_LOG_ENTRIES_TOTAL
                .with_label_values(&["alt.gone"])
                .get(),
            1.0
        );

        // Simulate GC: delete the article.
        sqlx::query("DELETE FROM articles WHERE cid = '<d1@t>'")
            .execute(&pool)
            .await
            .unwrap();

        // Second tick: alt.gone should be removed from gauges.
        let current = sample_group_metrics(&pool, &prev).await.unwrap();
        assert!(!current.contains("alt.gone"));

        // The label should have been removed; with_label_values re-creates it at 0.
        let after = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["alt.gone"])
            .get();
        assert_eq!(
            after, 0.0,
            "gauge for GC'd group must be removed (reads back as 0)"
        );
    }
}
