//! Read-only access to the transit daemon's staging area (stoa-psd6m).
//!
//! When an article is staged in the transit daemon's write-ahead log but has
//! not yet been written to IPFS, the reader would normally return 430 No Such
//! Article.  This module provides a fallback that reads the staged article
//! directly from the transit staging table and file on disk.
//!
//! # Access model
//!
//! The reader opens a read-only SQLite connection pool to the transit daemon's
//! `transit.db`.  The pool is used only for `SELECT` queries against
//! `transit_staging(message_id, file_path)`.  No writes are performed.
//!
//! SQLite WAL mode (which the transit daemon enables) allows concurrent
//! readers without blocking writers, so the reader can safely query the
//! table while the transit drain task inserts and deletes rows.
//!
//! # Failure handling
//!
//! All errors from this module are non-fatal: a staging lookup failure causes
//! the reader to fall through to the normal 430 response rather than returning
//! 500.  The reader logs a warning so operators can diagnose misconfiguration.

use std::sync::Arc;

use sqlx::AnyPool;
use tracing::warn;

/// Result of a staging fallback lookup.
pub enum StagingResult {
    /// Article found in staging: raw wire bytes (headers + blank line + body).
    Found(Vec<u8>),
    /// Article not in the staging table (normal 430 case).
    NotStaged,
    /// Staging lookup failed (DB or I/O error); caller should treat as NotStaged.
    Error,
}

/// Look up `msgid` in the transit staging table and read its file if present.
///
/// Returns `StagingResult::Found(bytes)` when the article is staged,
/// `StagingResult::NotStaged` when no row matches, and `StagingResult::Error`
/// on any DB or file-read failure (after logging a warning).
pub async fn fetch_from_staging(pool: &Arc<AnyPool>, msgid: &str) -> StagingResult {
    let row: Option<(String,)> =
        match sqlx::query_as("SELECT file_path FROM transit_staging WHERE message_id = ?")
            .bind(msgid)
            .fetch_optional(pool.as_ref())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(msgid, "staging fallback DB error: {e}");
                return StagingResult::Error;
            }
        };

    let file_path = match row {
        None => return StagingResult::NotStaged,
        Some((p,)) => p,
    };

    match tokio::fs::read(&file_path).await {
        Ok(bytes) => StagingResult::Found(bytes),
        Err(e) => {
            warn!(msgid, file_path, "staging fallback file read error: {e}");
            StagingResult::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory SQLite pool with the minimal transit_staging schema.
    async fn make_staging_pool() -> Arc<AnyPool> {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("sqlite:file:staging_fallback_test_{n}?mode=memory&cache=shared");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        sqlx::query::<sqlx::Any>(
            "CREATE TABLE transit_staging (
                id          TEXT    NOT NULL PRIMARY KEY,
                message_id  TEXT    NOT NULL UNIQUE,
                file_path   TEXT    NOT NULL,
                received_at INTEGER NOT NULL,
                byte_size   INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("create table");
        Arc::new(pool)
    }

    #[tokio::test]
    async fn not_staged_when_table_empty() {
        let pool = make_staging_pool().await;
        let result = fetch_from_staging(&pool, "<x@y>").await;
        assert!(matches!(result, StagingResult::NotStaged));
    }

    #[tokio::test]
    async fn found_when_staged_and_file_exists() {
        let pool = make_staging_pool().await;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("testarticle");
        let content = b"From: a@b\r\nSubject: test\r\n\r\nbody\r\n";
        tokio::fs::write(&file_path, content).await.unwrap();

        let file_path_str = file_path.to_str().unwrap();
        sqlx::query(
            "INSERT INTO transit_staging (id, message_id, file_path, received_at, byte_size) \
             VALUES ('abc123', '<staged@test>', ?, 0, ?)",
        )
        .bind(file_path_str)
        .bind(content.len() as i64)
        .execute(&*pool)
        .await
        .unwrap();

        let result = fetch_from_staging(&pool, "<staged@test>").await;
        match result {
            StagingResult::Found(bytes) => assert_eq!(bytes, content),
            _ => panic!("expected Found"),
        }
    }

    #[tokio::test]
    async fn not_staged_for_different_msgid() {
        let pool = make_staging_pool().await;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("art");
        tokio::fs::write(&file_path, b"x").await.unwrap();

        sqlx::query(
            "INSERT INTO transit_staging (id, message_id, file_path, received_at, byte_size) \
             VALUES ('id1', '<one@test>', ?, 0, 1)",
        )
        .bind(file_path.to_str().unwrap())
        .execute(&*pool)
        .await
        .unwrap();

        let result = fetch_from_staging(&pool, "<two@test>").await;
        assert!(matches!(result, StagingResult::NotStaged));
    }

    #[tokio::test]
    async fn error_when_file_missing() {
        let pool = make_staging_pool().await;
        sqlx::query(
            "INSERT INTO transit_staging (id, message_id, file_path, received_at, byte_size) \
             VALUES ('id2', '<missing@test>', '/nonexistent/path/xyz', 0, 1)",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let result = fetch_from_staging(&pool, "<missing@test>").await;
        assert!(matches!(result, StagingResult::Error));
    }
}
