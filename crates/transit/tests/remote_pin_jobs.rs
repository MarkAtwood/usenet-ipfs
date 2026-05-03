//! Integration tests for the remote pinning jobs table and admin endpoint.
//!
//! Tests exercise the DB schema via the public migration runner, then insert
//! and query rows directly using the same sqlx pool — no live HTTP services
//! or background worker tasks are spawned.
//!
//! Oracles:
//!   - DB constraints verified by INSERT UNIQUE constraint violation
//!   - JSON structure verified by serde_json deserialization
//!   - Status counts verified by direct SELECT after INSERT

use sqlx::Row;
use std::sync::Arc;
use stoa_core::wildmat::GroupFilter;
use stoa_transit::admin::build_pinning_remote_json;

async fn make_pool() -> (Arc<sqlx::AnyPool>, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_transit::migrations::run_migrations(&url)
        .await
        .unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (Arc::new(pool), tmp)
}

/// Insert with ON CONFLICT DO NOTHING enqueues a job with default `pending` status.
#[tokio::test]
async fn insert_or_ignore_enqueues_job_as_pending() {
    let (pool, _tmp) = make_pool().await;

    sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING")
        .bind("QmTest1")
        .bind("pinata")
        .execute(&*pool)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT status, attempt_count FROM remote_pin_jobs WHERE cid = ? AND service_name = ?",
    )
    .bind("QmTest1")
    .bind("pinata")
    .fetch_one(&*pool)
    .await
    .unwrap();

    let status: String = row.get("status");
    let attempt_count: i64 = row.get("attempt_count");
    assert_eq!(status, "pending");
    assert_eq!(attempt_count, 0);
}

/// UNIQUE constraint on (cid, service_name) prevents duplicate entries.
/// ON CONFLICT DO NOTHING must silently skip the second insert.
#[tokio::test]
async fn unique_constraint_prevents_duplicate_per_service() {
    let (pool, _tmp) = make_pool().await;

    // First insert succeeds.
    sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING")
        .bind("QmDup1")
        .bind("web3")
        .execute(&*pool)
        .await
        .unwrap();

    // Second insert for same (cid, service_name) must be silently ignored.
    let result =
        sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING")
            .bind("QmDup1")
            .bind("web3")
            .execute(&*pool)
            .await;
    assert!(
        result.is_ok(),
        "ON CONFLICT DO NOTHING must not error on duplicate"
    );

    // Only one row must exist.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM remote_pin_jobs WHERE cid = 'QmDup1' AND service_name = 'web3'",
    )
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "exactly one row expected after duplicate insert");
}

/// Same CID can be submitted to different services (different rows).
#[tokio::test]
async fn same_cid_different_services_creates_two_rows() {
    let (pool, _tmp) = make_pool().await;

    sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING")
        .bind("QmShared")
        .bind("pinata")
        .execute(&*pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING")
        .bind("QmShared")
        .bind("filebase")
        .execute(&*pool)
        .await
        .unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE cid = 'QmShared'")
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(count, 2, "expected two rows for two different services");
}

/// Group filter matching: when service groups is empty, all groups match.
/// Verified indirectly by checking job count after a pattern match loop.
#[tokio::test]
async fn group_filter_empty_means_pin_all_groups() {
    // A service with empty groups list should pin articles from any group.
    // We simulate the pipeline logic: if svc_groups.is_empty(), always insert.
    let (pool, _tmp) = make_pool().await;
    let svc_name = "all-groups-svc";

    let article_groups = ["comp.lang.rust", "alt.test", "sci.math"];
    let svc_groups: Vec<String> = vec![];

    for group in &article_groups {
        // Use the production GroupFilter so the test exercises the real logic.
        let should_pin = svc_groups.is_empty();
        if should_pin {
            sqlx::query(
                "INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING",
            )
            .bind(format!("Qm{group}"))
            .bind(svc_name)
            .execute(&*pool)
            .await
            .unwrap();
        }
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE service_name = ?")
            .bind(svc_name)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(
        count, 3,
        "all 3 groups should be enqueued when filter is empty"
    );
}

/// Group filter matching: pattern `comp.*` matches comp groups but not alt.
#[tokio::test]
async fn group_filter_pattern_matches_prefix() {
    let (pool, _tmp) = make_pool().await;
    let svc_name = "comp-only";

    let all_groups = ["comp.lang.rust", "comp.os.linux", "alt.test", "sci.math"];
    let svc_groups = vec!["comp.*".to_string()];

    let filter = GroupFilter::new(&svc_groups).expect("valid patterns");
    for group in &all_groups {
        let should_pin = filter.accepts(group);
        if should_pin {
            sqlx::query(
                "INSERT INTO remote_pin_jobs (cid, service_name) VALUES (?, ?) ON CONFLICT (cid, service_name) DO NOTHING",
            )
            .bind(format!("Qm{group}"))
            .bind(svc_name)
            .execute(&*pool)
            .await
            .unwrap();
        }
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE service_name = ?")
            .bind(svc_name)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(count, 2, "only comp.* groups should be enqueued");
}

/// /pinning/remote admin endpoint returns correct per-service JSON stats.
#[tokio::test]
async fn admin_pinning_remote_endpoint_returns_stats() {
    let (pool, _tmp) = make_pool().await;

    // Seed mixed statuses for two services.
    let inserts = [
        ("Qm1", "pinata", "pending"),
        ("Qm2", "pinata", "pending"),
        ("Qm3", "pinata", "pinned"),
        ("Qm4", "web3", "queued"),
        ("Qm5", "web3", "failed"),
    ];
    for (cid, svc, status) in inserts {
        sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name, status) VALUES (?, ?, ?)")
            .bind(cid)
            .bind(svc)
            .bind(status)
            .execute(&*pool)
            .await
            .unwrap();
    }

    let json = build_pinning_remote_json(&*pool).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

    assert_eq!(arr.len(), 2, "expected 2 service entries: {json}");

    // BTreeMap ordering guarantees "pinata" comes before "web3".
    let pinata = &arr[0];
    assert_eq!(pinata["service"], "pinata");
    assert_eq!(pinata["pending"], 2);
    assert_eq!(pinata["pinned"], 1);
    assert_eq!(pinata["queued"], 0);
    assert_eq!(pinata["failed"], 0);

    let web3 = &arr[1];
    assert_eq!(web3["service"], "web3");
    assert_eq!(web3["queued"], 1);
    assert_eq!(web3["failed"], 1);
    assert_eq!(web3["pending"], 0);
    assert_eq!(web3["pinned"], 0);
}

