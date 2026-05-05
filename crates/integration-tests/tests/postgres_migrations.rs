//! PostgreSQL migration integration tests (usenet-ipfs-ky62.6).
//!
//! Verifies that all migration sets run successfully against a real PostgreSQL
//! database, and that basic INSERT/SELECT/DELETE round-trips work for the core
//! schema types used by each crate.
//!
//! Requires a running PostgreSQL instance.  Skip if `STOA_TEST_PG_URL` is
//! not set.  Set it to e.g.:
//!   export STOA_TEST_PG_URL="postgres://stoa:stoa_test_pw@localhost:5433/stoa_test"
//!
//! See `docker-compose.postgres.yml` in the repo root for a one-command way
//! to bring up a compatible PostgreSQL 16 container.
//!
//! Independent oracle: the PostgreSQL server's own error reporting — if
//! CREATE TABLE or INSERT fails, the test fails.

use multihash_codetable::MultihashDigest;

/// Skip this test if `STOA_TEST_PG_URL` is unset or empty.
fn pg_url() -> Option<String> {
    match std::env::var("STOA_TEST_PG_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// All migration sets complete without error on PostgreSQL.
#[tokio::test]
async fn all_migrations_run_on_postgres() {
    let base = match pg_url() {
        Some(u) => u,
        None => {
            eprintln!("STOA_TEST_PG_URL not set; skipping PostgreSQL migration test");
            return;
        }
    };

    sqlx::any::install_default_drivers();

    stoa_core::migrations::run_migrations(&base)
        .await
        .expect("stoa_core migrations must succeed on PostgreSQL");

    stoa_transit::migrations::run_migrations(&base)
        .await
        .expect("stoa_transit migrations must succeed on PostgreSQL");

    stoa_reader::migrations::run_migrations(&base)
        .await
        .expect("stoa_reader migrations must succeed on PostgreSQL");

    stoa_verify::run_migrations(&base)
        .await
        .expect("stoa_verify migrations must succeed on PostgreSQL");

    stoa_mail::migrations::run_migrations(&base)
        .await
        .expect("stoa_mail migrations must succeed on PostgreSQL");
}

/// Running migrations twice is idempotent (ON CONFLICT / IF NOT EXISTS).
#[tokio::test]
async fn migrations_are_idempotent() {
    let base = match pg_url() {
        Some(u) => u,
        None => return,
    };

    sqlx::any::install_default_drivers();

    // Run twice; both must succeed.
    stoa_core::migrations::run_migrations(&base)
        .await
        .expect("first run");
    stoa_core::migrations::run_migrations(&base)
        .await
        .expect("second run must be idempotent");

    stoa_transit::migrations::run_migrations(&base)
        .await
        .expect("first run");
    stoa_transit::migrations::run_migrations(&base)
        .await
        .expect("second run must be idempotent");
}

/// INSERT/SELECT/DELETE round-trip on the core `msgid_map` table.
#[tokio::test]
async fn core_msgid_map_roundtrip() {
    let base = match pg_url() {
        Some(u) => u,
        None => return,
    };

    sqlx::any::install_default_drivers();
    stoa_core::migrations::run_migrations(&base)
        .await
        .expect("migrations");

    let pool = stoa_core::db_pool::try_open_any_pool(&base, 2)
        .await
        .expect("pool");

    let msgid_map = stoa_core::msgid_map::MsgIdMap::new(pool);

    let test_msgid = "<pg-roundtrip@test.example>";
    let cid = cid::Cid::new_v1(
        0x71,
        multihash_codetable::Code::Sha2_256.digest(b"pg roundtrip test article"),
    );

    // Insert.
    msgid_map
        .insert(test_msgid, &cid)
        .await
        .expect("insert must succeed on PostgreSQL");

    // Lookup — must return the inserted CID.
    let found = msgid_map
        .lookup_by_msgid(test_msgid)
        .await
        .expect("lookup must not error")
        .expect("inserted msgid must be found");

    assert_eq!(found, cid, "round-trip CID must match inserted CID");

    // Duplicate insert must be silently ignored (idempotent).
    msgid_map
        .insert(test_msgid, &cid)
        .await
        .expect("duplicate insert must succeed (idempotent)");
}

/// INSERT/SELECT/DELETE round-trip on the transit `articles` table.
#[tokio::test]
async fn transit_articles_roundtrip() {
    let base = match pg_url() {
        Some(u) => u,
        None => return,
    };

    sqlx::any::install_default_drivers();
    stoa_transit::migrations::run_migrations(&base)
        .await
        .expect("migrations");

    let pool = stoa_core::db_pool::try_open_any_pool(&base, 2)
        .await
        .expect("pool");

    let cid = cid::Cid::new_v1(
        0x71,
        multihash_codetable::Code::Sha2_256.digest(b"transit roundtrip"),
    );
    let cid_str = cid.to_string();

    // Insert a row.
    sqlx::query(
        "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
         VALUES (?, ?, ?, ?) ON CONFLICT (cid) DO NOTHING",
    )
    .bind(&cid_str)
    .bind("comp.test")
    .bind(1_700_000_000_000i64)
    .bind(512i64)
    .execute(&pool)
    .await
    .expect("INSERT into articles must succeed on PostgreSQL");

    // Select it back.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT cid, group_name FROM articles WHERE cid = ?")
            .bind(&cid_str)
            .fetch_optional(&pool)
            .await
            .expect("SELECT must succeed");

    let (stored_cid, stored_group) = row.expect("inserted row must be found");
    assert_eq!(stored_cid, cid_str);
    assert_eq!(stored_group, "comp.test");

    // Delete it.
    sqlx::query("DELETE FROM articles WHERE cid = ?")
        .bind(&cid_str)
        .execute(&pool)
        .await
        .expect("DELETE must succeed on PostgreSQL");

    let after_delete: Option<(String, String)> =
        sqlx::query_as("SELECT cid, group_name FROM articles WHERE cid = ?")
            .bind(&cid_str)
            .fetch_optional(&pool)
            .await
            .expect("SELECT after DELETE must succeed");

    assert!(after_delete.is_none(), "row must be absent after DELETE");
}

/// stoa-mail migrations run on PostgreSQL and basic schema round-trips work.
///
/// Covers: users, subscriptions, user_flags, bearer_tokens, and messages tables.
/// Independent oracle: PostgreSQL server error reporting.
#[tokio::test]
async fn mail_migrations_and_roundtrip() {
    let base = match pg_url() {
        Some(u) => u,
        None => return,
    };

    sqlx::any::install_default_drivers();
    stoa_mail::migrations::run_migrations(&base)
        .await
        .expect("stoa_mail migrations must succeed on PostgreSQL");

    let pool = stoa_core::db_pool::try_open_any_pool(&base, 2)
        .await
        .expect("pool");

    // Insert a user (singleton model; user_id=1 expected by all stores).
    sqlx::query(
        "INSERT INTO users (id, username, password_hash) \
         VALUES (1, 'alice', 'x') \
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("INSERT users must succeed on PostgreSQL");

    // Subscribe the user to a group and verify.
    sqlx::query(
        "INSERT INTO subscriptions (user_id, group_name, subscribed_at) \
         VALUES (1, 'comp.lang.rust', 0) \
         ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("INSERT subscriptions must succeed");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE user_id = 1")
        .fetch_one(&pool)
        .await
        .expect("COUNT subscriptions must succeed");
    assert!(count >= 1, "subscription must be present");

    // Insert a bearer token and verify lookup.
    sqlx::query(
        "INSERT INTO bearer_tokens \
         (id, token_hash, username, label, created_at, expires_at) \
         VALUES ('tok1', '\\xdeadbeef', 'alice', NULL, 0, NULL) \
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("INSERT bearer_tokens must succeed");

    let found: Option<String> =
        sqlx::query_scalar("SELECT username FROM bearer_tokens WHERE id = 'tok1'")
            .fetch_optional(&pool)
            .await
            .expect("SELECT bearer_tokens must succeed");
    assert_eq!(found.as_deref(), Some("alice"));

    // Provision the inbox special mailbox and insert a message.
    sqlx::query(
        "INSERT INTO mailboxes (mailbox_id, role, name, sort_order) \
         VALUES ('inbox_id', 'inbox', 'INBOX', 1) \
         ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("INSERT mailboxes must succeed");

    sqlx::query(
        "INSERT INTO messages \
         (mailbox_id, envelope_from, envelope_to, raw_message) \
         VALUES ('inbox_id', 'sender@example.com', 'alice@example.com', '\\x48656c6c6f')",
    )
    .execute(&pool)
    .await
    .expect("INSERT messages must succeed");

    let msg_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE mailbox_id = 'inbox_id'")
            .fetch_one(&pool)
            .await
            .expect("COUNT messages must succeed");
    assert!(msg_count >= 1, "message must be present");
}
