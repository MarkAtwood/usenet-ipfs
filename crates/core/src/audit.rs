//! Immutable audit log for security-relevant events.
//!
//! All events are written to the `audit_log` SQLite table as append-only rows.
//! No UPDATE or DELETE ever runs against this table.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::AnyPool;

use crate::error::StorageError;

/// Maximum number of audit events buffered in the channel before backpressure.
const AUDIT_CHANNEL_CAPACITY: usize = 1000;

/// Maximum number of events written in a single batch flush.
const AUDIT_BATCH_SIZE: usize = 100;

/// Interval between forced batch flushes when the channel is quiet.
const AUDIT_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Running count of audit events dropped due to channel overflow or DB failure.
///
/// Incremented atomically whenever an event is silently discarded.
/// Operators should expose this via metrics to detect sustained loss.
static AUDIT_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Return the total number of audit events dropped since process start.
///
/// Events are dropped in two cases:
/// - The internal channel is full (sustained write load exceeds flush rate).
/// - The database flush fails (pool exhausted, disk full, etc.).
pub fn dropped_event_count() -> u64 {
    AUDIT_EVENTS_DROPPED.load(Ordering::Relaxed)
}

/// A security-relevant event to be recorded in the audit log.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// An article was signed and written to IPFS by this operator.
    ArticleSigned {
        message_id: String,
        cid: String,
        key_fingerprint: String,
    },
    /// A client successfully posted an article via NNTP POST.
    ArticlePosted {
        peer_addr: String,
        username: Option<String>,
        message_id: String,
        newsgroups: String,
        cid: String,
    },
    /// A client's article was rejected during the POST pipeline.
    ArticleRejected {
        peer_addr: String,
        username: Option<String>,
        message_id: Option<String>,
        reason: String,
    },
    /// An authentication attempt from a peer or client.
    AuthAttempt {
        peer_addr: String,
        user: String,
        success: bool,
        /// Service that handled the attempt: `"nntp"`, `"jmap"`, `"smtp"`, etc.
        service: String,
        /// Authentication mechanism: `"password"`, `"client_cert"`, `"bearer_token"`.
        auth_method: String,
    },
    /// A peer was blacklisted due to repeated failures.
    PeerBlacklisted {
        peer_id: String,
        reason: String,
        duration_secs: u64,
    },
    /// A GC run completed.
    GcRun {
        articles_unpinned: u64,
        group_name: String,
    },
    /// An admin endpoint was accessed.
    AdminAccess {
        peer_addr: String,
        path: String,
        method: String,
        status_code: u16,
    },
}

impl AuditEvent {
    /// Returns the event type string used as the `event_type` column value.
    pub fn event_type(&self) -> &'static str {
        match self {
            AuditEvent::ArticleSigned { .. } => "article_signed",
            AuditEvent::ArticlePosted { .. } => "article_posted",
            AuditEvent::ArticleRejected { .. } => "article_rejected",
            AuditEvent::AuthAttempt { .. } => "auth_attempt",
            AuditEvent::PeerBlacklisted { .. } => "peer_blacklisted",
            AuditEvent::GcRun { .. } => "gc_run",
            AuditEvent::AdminAccess { .. } => "admin_access",
        }
    }

    /// Serialize the event to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"audit serialization failed: {}\"}}", e))
    }

    /// Deserialize an event from JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Append an audit event to the `audit_log` table.
pub async fn append_audit_event(
    pool: &AnyPool,
    timestamp_ms: i64,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let event_type = event.event_type();
    let event_json = event.to_json();
    sqlx::query("INSERT INTO audit_log (timestamp_ms, event_type, event_json) VALUES (?, ?, ?)")
        .bind(timestamp_ms)
        .bind(event_type)
        .bind(&event_json)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Read the N most recent audit events (all types).
pub async fn recent_audit_events(
    pool: &AnyPool,
    limit: i64,
) -> Result<Vec<(i64, AuditEvent)>, StorageError> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT timestamp_ms, event_json FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let mut events = Vec::with_capacity(rows.len());
    for (ts, json) in rows {
        match AuditEvent::from_json(&json) {
            Ok(event) => events.push((ts, event)),
            Err(e) => {
                return Err(StorageError::Database(format!(
                    "audit event deserialize: {e}"
                )))
            }
        }
    }
    Ok(events)
}

/// Handle to the background audit logger task.
///
/// Dropping the handle signals the logger to flush remaining events and shut
/// down, but does NOT wait for it to complete.  Call `shutdown().await` when
/// you need to guarantee all events have been persisted before proceeding.
pub struct AuditLoggerHandle {
    tx: tokio::sync::mpsc::Sender<(i64, AuditEvent)>,
    join: tokio::task::JoinHandle<()>,
}

impl AuditLoggerHandle {
    /// Send an audit event. Returns even if the buffer is full (event is dropped).
    /// Non-blocking: never blocks the caller.
    ///
    /// The event timestamp is captured here at send time so that events retain
    /// their actual occurrence time regardless of how long they sit in the
    /// channel before being flushed to the database.
    pub fn log(&self, event: AuditEvent) {
        // Capture wall-clock time now, before the event enters the channel.
        // Using try_from avoids the silent truncation of `as i64`; in the
        // astronomically unlikely case that millis exceed i64::MAX (year 2262)
        // we saturate to i64::MAX rather than wrap to a negative value.
        let occurred_at_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);

        match self.tx.try_send((occurred_at_ms, event)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full((_, dropped))) => {
                let total = AUDIT_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    event_type = dropped.event_type(),
                    audit_events_dropped_total = total,
                    "audit log channel full; security event dropped"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                let total = AUDIT_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    audit_events_dropped_total = total,
                    "audit logger shut down; event dropped"
                );
            }
        }
    }

    /// Close the sender and wait for the logger task to flush all remaining
    /// events and exit.  After this returns, all events that were enqueued
    /// before this call are guaranteed to have been written to SQLite.
    pub async fn shutdown(self) {
        drop(self.tx);
        if let Err(e) = self.join.await {
            tracing::error!("audit logger task panicked during shutdown: {e}");
        }
    }
}

/// Trait for all audit log backends.
///
/// Both the SQLite batch logger ([`AuditLoggerHandle`]) and the JSONL file
/// logger ([`JsonlFileLogger`]) implement this trait.  Use `Arc<dyn AuditLogger>`
/// as the storage type when the backend is chosen at runtime.
pub trait AuditLogger: Send + Sync {
    /// Record an audit event.  Implementations must be non-blocking and
    /// infallible from the caller's perspective — events may be silently
    /// dropped if the backend cannot keep up or fails.
    fn log(&self, event: AuditEvent);
}

impl AuditLogger for AuditLoggerHandle {
    fn log(&self, event: AuditEvent) {
        // Calls the inherent AuditLoggerHandle::log (method resolution prefers
        // inherent methods over trait methods, so this is not recursive).
        AuditLoggerHandle::log(self, event);
    }
}

/// Audit logger that appends one JSON object per line to a file.
///
/// The file is opened with `O_APPEND | O_CREAT`.  Concurrent writers within
/// this process are serialized by the inner `Mutex<File>`, which guarantees
/// that each JSON line is written atomically from the application's perspective
/// regardless of event size.
///
/// Note: POSIX `O_APPEND` only guarantees atomic `write(2)` calls up to
/// `PIPE_BUF` bytes (≥ 512 on Linux, typically 4 096).  Events larger than
/// this limit would not be atomic at the OS level.  The `Mutex` here ensures
/// in-process serialization; if multiple independent processes write to the
/// same file, OS-level atomicity is not guaranteed for large events.
/// The file is never truncated or rotated by this implementation.
pub struct JsonlFileLogger {
    file: std::sync::Mutex<std::fs::File>,
    path: String,
}

impl JsonlFileLogger {
    /// Open (or create) a JSONL audit log at `path`.
    ///
    /// The file is opened in append mode; existing content is never overwritten.
    pub fn open(path: &str) -> std::io::Result<Self> {
        use std::fs::OpenOptions;
        let file = OpenOptions::new().append(true).create(true).open(path)?;
        Ok(Self {
            file: std::sync::Mutex::new(file),
            path: path.to_string(),
        })
    }

    /// Return the path this logger was opened with.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl AuditLogger for JsonlFileLogger {
    fn log(&self, event: AuditEvent) {
        use std::io::Write as _;
        // Best-effort: silently ignore lock poisoning and I/O failures.
        // Operators should monitor the file descriptor via OS-level alerting.
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{}", event.to_json());
        }
    }
}

/// Configuration for the audit log backend.
///
/// Used in both `stoa-transit` and `stoa-reader` config files under
/// the `[audit]` section.
#[derive(Debug, serde::Deserialize, Default, Clone)]
pub struct AuditConfig {
    /// Audit log backend.  Defaults to `sqlite`.
    #[serde(default)]
    pub backend: AuditBackend,
    /// Path for the JSONL file backend.  Required when `backend = "file"`.
    pub path: Option<String>,
}

/// Selects the audit log implementation used at startup.
#[derive(Debug, serde::Deserialize, Default, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditBackend {
    /// Write audit events to the core SQLite database (default).
    #[default]
    Sqlite,
    /// Write audit events as newline-delimited JSON to a file.
    File,
}

/// Construct the audit logger backend specified by `config`.
///
/// - `backend = "sqlite"` (default) — starts a background task that batches
///   events into the `audit_log` table of `pool`.
/// - `backend = "file"` — opens (or creates) a JSONL file at `config.path`.
///   `config.path` must be set when this backend is selected.
///
/// Returns `Err` only when `backend = "file"` and `path` is absent or the
/// file cannot be opened.
pub fn build_audit_logger(
    config: &AuditConfig,
    pool: &AnyPool,
) -> Result<std::sync::Arc<dyn AuditLogger>, String> {
    match config.backend {
        AuditBackend::Sqlite => {
            let handle = start_audit_logger(pool.clone(), AUDIT_BATCH_SIZE, AUDIT_FLUSH_INTERVAL);
            Ok(std::sync::Arc::new(handle) as std::sync::Arc<dyn AuditLogger>)
        }
        AuditBackend::File => {
            let path = config.path.as_deref().ok_or_else(|| {
                "audit.path is required when audit.backend = \"file\"".to_string()
            })?;
            let logger = JsonlFileLogger::open(path)
                .map_err(|e| format!("cannot open audit log file '{}': {e}", path))?;
            Ok(std::sync::Arc::new(logger) as std::sync::Arc<dyn AuditLogger>)
        }
    }
}

/// Start the background audit logger task.
///
/// The task accumulates events until either `batch_size` events are buffered
/// or `flush_interval` elapses, then writes them all in a single SQLite transaction.
///
/// Returns a handle. Dropping the handle causes the background task to flush
/// remaining events and exit; call `handle.shutdown().await` to wait for
/// completion.
pub fn start_audit_logger(
    pool: AnyPool,
    batch_size: usize,
    flush_interval: std::time::Duration,
) -> AuditLoggerHandle {
    let (tx, rx) = tokio::sync::mpsc::channel::<(i64, AuditEvent)>(AUDIT_CHANNEL_CAPACITY);
    let join = tokio::spawn(audit_logger_task(pool, rx, batch_size, flush_interval));
    AuditLoggerHandle { tx, join }
}

async fn audit_logger_task(
    pool: AnyPool,
    mut rx: tokio::sync::mpsc::Receiver<(i64, AuditEvent)>,
    batch_size: usize,
    flush_interval: std::time::Duration,
) {
    let mut buffer: Vec<(i64, AuditEvent)> = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(flush_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        buffer.push(e);
                        if buffer.len() >= batch_size {
                            flush_buffer(&pool, &mut buffer).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            flush_buffer(&pool, &mut buffer).await;
                        }
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(&pool, &mut buffer).await;
                }
            }
        }
    }
}

async fn flush_buffer(pool: &AnyPool, buffer: &mut Vec<(i64, AuditEvent)>) {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            let count = buffer.len() as u64;
            let total = AUDIT_EVENTS_DROPPED.fetch_add(count, Ordering::Relaxed) + count;
            tracing::error!(
                audit_events_dropped_total = total,
                dropped_this_flush = count,
                "audit logger: failed to begin transaction, dropping buffered events: {e}"
            );
            buffer.clear();
            return;
        }
    };

    // Bulk INSERT all buffered events.  Each row needs 3 bind parameters
    // (timestamp_ms, event_type, event_json); SQLite's default
    // SQLITE_MAX_VARIABLE_NUMBER is 999 on old versions, so chunk at 333 rows
    // (333 × 3 = 999) to stay within the limit on any SQLite build.
    const CHUNK_SIZE: usize = 333;
    for chunk in buffer.chunks(CHUNK_SIZE) {
        let placeholders = chunk
            .iter()
            .map(|_| "(?, ?, ?)")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO audit_log (timestamp_ms, event_type, event_json) VALUES {}",
            placeholders
        );
        let mut q = sqlx::query(&sql);
        for (occurred_at_ms, event) in chunk {
            q = q
                .bind(occurred_at_ms)
                .bind(event.event_type())
                .bind(event.to_json());
        }
        if let Err(e) = q.execute(&mut *tx).await {
            let count = buffer.len() as u64;
            let total = AUDIT_EVENTS_DROPPED.fetch_add(count, Ordering::Relaxed) + count;
            tracing::error!(
                audit_events_dropped_total = total,
                dropped_this_flush = count,
                "audit logger: bulk insert failed, dropping buffered events: {e}"
            );
            buffer.clear();
            return;
        }
    }

    if let Err(e) = tx.commit().await {
        // Count all buffered events as dropped exactly once here.
        // Per-INSERT failures within the transaction are not counted separately
        // because the entire transaction is rolled back on commit failure,
        // so all events in the buffer are lost regardless of individual INSERT outcomes.
        let count = buffer.len() as u64;
        let total = AUDIT_EVENTS_DROPPED.fetch_add(count, Ordering::Relaxed) + count;
        tracing::error!(
            audit_events_dropped_total = total,
            dropped_this_flush = count,
            "audit logger: commit failed, dropping buffered events: {e}"
        );
        buffer.clear();
        return;
    }

    buffer.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_pool::try_open_any_pool;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = try_open_any_pool(&url, 1).await.unwrap();
        (pool, tmp)
    }

    #[test]
    fn article_signed_roundtrip() {
        let event = AuditEvent::ArticleSigned {
            message_id: "<test@example.com>".to_string(),
            cid: "bafy123".to_string(),
            key_fingerprint: "ab:cd:ef".to_string(),
        };
        let json = event.to_json();
        let parsed = AuditEvent::from_json(&json).unwrap();
        assert_eq!(event, parsed);
        assert!(
            json.contains("article_signed"),
            "event_type in JSON: {json}"
        );
    }

    #[test]
    fn all_event_types_serialize() {
        let events = vec![
            AuditEvent::ArticleSigned {
                message_id: "m".into(),
                cid: "c".into(),
                key_fingerprint: "k".into(),
            },
            AuditEvent::AuthAttempt {
                peer_addr: "127.0.0.1:9000".into(),
                user: "u".into(),
                success: true,
                service: "nntp".into(),
                auth_method: "password".into(),
            },
            AuditEvent::PeerBlacklisted {
                peer_id: "p".into(),
                reason: "spam".into(),
                duration_secs: 3600,
            },
            AuditEvent::GcRun {
                articles_unpinned: 5,
                group_name: "comp.test".into(),
            },
            AuditEvent::AdminAccess {
                peer_addr: "127.0.0.1".into(),
                path: "/status".into(),
                method: "GET".into(),
                status_code: 200,
            },
        ];
        for event in &events {
            let json = event.to_json();
            let parsed = AuditEvent::from_json(&json).unwrap();
            assert_eq!(event, &parsed, "roundtrip failed for {json}");
        }
    }

    #[tokio::test]
    async fn append_and_read_events() {
        let (pool, _tmp) = make_pool().await;
        let event = AuditEvent::GcRun {
            articles_unpinned: 3,
            group_name: "alt.test".into(),
        };
        append_audit_event(&pool, 1_700_000_000_000, &event)
            .await
            .unwrap();

        let events = recent_audit_events(&pool, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, 1_700_000_000_000);
        assert_eq!(events[0].1, event);
    }

    #[tokio::test]
    async fn multiple_events_ordered_desc() {
        let (pool, _tmp) = make_pool().await;
        for i in 0..5u64 {
            let e = AuditEvent::GcRun {
                articles_unpinned: i,
                group_name: "alt.test".into(),
            };
            append_audit_event(&pool, i as i64 * 1000, &e)
                .await
                .unwrap();
        }
        let events = recent_audit_events(&pool, 3).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].1,
            AuditEvent::GcRun {
                articles_unpinned: 4,
                group_name: "alt.test".into()
            }
        );
    }

    #[tokio::test]
    async fn audit_logger_sends_1000_events() {
        let (pool, _tmp) = make_pool().await;

        let handle = start_audit_logger(pool.clone(), 100, std::time::Duration::from_millis(50));

        for i in 0u64..1000 {
            handle.log(AuditEvent::GcRun {
                articles_unpinned: i,
                group_name: "comp.test".to_string(),
            });
        }

        handle.shutdown().await;

        let events = recent_audit_events(&pool, 1100).await.unwrap();
        assert_eq!(
            events.len(),
            1000,
            "all 1000 events should be written, got {}",
            events.len()
        );
    }

    #[tokio::test]
    async fn audit_logger_non_blocking() {
        let (pool, _tmp) = make_pool().await;
        let handle = start_audit_logger(pool.clone(), 100, std::time::Duration::from_millis(100));

        let start = std::time::Instant::now();
        for i in 0u64..200 {
            handle.log(AuditEvent::AdminAccess {
                peer_addr: "127.0.0.1".to_string(),
                path: format!("/path/{i}"),
                method: "GET".to_string(),
                status_code: 200,
            });
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "non-blocking sends took too long: {elapsed:?}"
        );

        // Shutdown waits for the logger to flush all remaining events.
        handle.shutdown().await;
        let events = recent_audit_events(&pool, 300).await.unwrap();
        assert_eq!(events.len(), 200);
    }

    /// Channel overflow (1001 events into a 1000-slot channel, no awaits between sends)
    /// must increment the dropped counter by exactly 1.
    ///
    /// This works because `#[tokio::test]` uses a single-threaded scheduler by default:
    /// the background logger task cannot run while we hold the CPU in the send loop,
    /// so the channel stays full until we yield.
    #[tokio::test]
    async fn channel_overflow_increments_dropped_counter() {
        let (pool, _tmp) = make_pool().await;
        // Use a very long flush interval so the logger task never drains the channel
        // during our send loop.
        let handle = start_audit_logger(pool.clone(), 2000, std::time::Duration::from_secs(3600));

        let before = dropped_event_count();

        // Fill the 1000-slot channel plus one extra that must be dropped.
        for i in 0u64..1001 {
            handle.log(AuditEvent::GcRun {
                articles_unpinned: i,
                group_name: "comp.test".to_string(),
            });
        }

        let after = dropped_event_count();
        // At least one event must have been dropped; the counter must have increased.
        assert!(
            after > before,
            "expected dropped_event_count to increase; before={before} after={after}"
        );
        drop(handle);
    }

    /// When `flush_buffer` is called with a closed pool, `pool.begin()` fails.
    /// The buffer must be cleared and the dropped counter must increase by the
    /// number of events in the buffer.
    ///
    /// This test calls `flush_buffer` directly to avoid timing dependencies with
    /// the background task's internal loop.
    #[tokio::test]
    async fn db_failure_increments_dropped_counter() {
        let (pool, _tmp) = make_pool().await;

        // Close the pool so that pool.begin() will fail.
        pool.close().await;
        assert!(
            pool.begin().await.is_err(),
            "pool.begin() must fail after pool.close() — if this assertion fails, \
             the test strategy needs to be updated"
        );

        let before = dropped_event_count();

        // Build a buffer of 3 events and call flush_buffer directly.
        // Use fixed timestamps (1/2/3 ms) — the exact values don't matter for
        // this test; we're only verifying that the dropped counter increments.
        let mut buffer = vec![
            (
                1i64,
                AuditEvent::GcRun {
                    articles_unpinned: 1,
                    group_name: "comp.test".to_string(),
                },
            ),
            (
                2i64,
                AuditEvent::GcRun {
                    articles_unpinned: 2,
                    group_name: "comp.test".to_string(),
                },
            ),
            (
                3i64,
                AuditEvent::GcRun {
                    articles_unpinned: 3,
                    group_name: "comp.test".to_string(),
                },
            ),
        ];

        flush_buffer(&pool, &mut buffer).await;

        let after = dropped_event_count();
        assert!(
            after >= before + 3,
            "dropped counter must increase by at least 3 (one per buffered event); \
             before={before} after={after}"
        );
        assert!(
            buffer.is_empty(),
            "buffer must be cleared even on DB failure"
        );
    }
}
