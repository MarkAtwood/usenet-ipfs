//! Pull-style import: fetch new articles from a remote NNTP server via NEWNEWS.

use sqlx::AnyPool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use stoa_core::{error::StorageError, msgid_map::MsgIdMap};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Maximum article body size accepted from a remote peer.
///
/// Matches the ingestion pipeline limit so articles are never fetched
/// only to be rejected at ingestion due to exceeding the size cap.
use crate::peering::ingestion::MAX_ARTICLE_BYTES;

/// Configuration for the suck pull import.
#[derive(Debug, Clone)]
pub struct SuckPullConfig {
    /// Remote NNTP server address (e.g., "news.example.com:119").
    pub remote_addr: String,
    /// Groups to pull (glob patterns accepted by the remote NEWNEWS command).
    pub groups: Vec<String>,
    /// Override starting timestamp (Unix seconds). If None, uses the cursor.
    pub since_override: Option<u64>,
    /// Max retry attempts per article on network error.
    pub max_retries: usize,
}

/// Summary of a completed suck pull run.
#[derive(Debug, Default)]
pub struct SuckPullSummary {
    pub new_articles: usize,
    pub fetched: usize,
    pub skipped_duplicate: usize,
    pub failed: usize,
    pub elapsed_ms: u64,
}

impl std::fmt::Display for SuckPullSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "new: {}, fetched: {}, skipped: {}, failed: {}, elapsed: {}ms",
            self.new_articles, self.fetched, self.skipped_duplicate, self.failed, self.elapsed_ms
        )
    }
}

/// Run the suck pull import for all configured groups.
///
/// Fetched articles are validated (format, size, duplicate check) via
/// [`check_ingest`] and then enqueued into `ingestion_sender` for processing
/// by the shared pipeline drain task.  Duplicate articles increment
/// `skipped_duplicate`; articles that fail validation or queue insertion
/// increment `failed`.
///
/// [`check_ingest`]: crate::peering::ingestion::check_ingest
pub async fn run_suck_pull(
    pool: &AnyPool,
    config: &SuckPullConfig,
    ingestion_sender: &crate::peering::ingestion_queue::IngestionSender,
    msgid_map: &MsgIdMap,
) -> Result<SuckPullSummary, StorageError> {
    let start = Instant::now();

    ensure_cursor_table(pool).await?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let default_since = now_unix.saturating_sub(86400);

    let stream = match TcpStream::connect(&config.remote_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "suck_pull: TCP connect to {} failed: {e}",
                config.remote_addr
            );
            return Ok(SuckPullSummary {
                failed: config.groups.len(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                ..Default::default()
            });
        }
    };

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read server greeting.
    line.clear();
    if let Err(e) = reader.read_line(&mut line).await {
        tracing::warn!("suck_pull: failed to read greeting: {e}");
        return Ok(SuckPullSummary {
            failed: config.groups.len(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        });
    }
    let code = crate::import::parse_nntp_response_code(&line);
    if code != 200 && code != 201 {
        tracing::warn!(
            "suck_pull: unexpected greeting from {}: {}",
            config.remote_addr,
            line.trim()
        );
        return Ok(SuckPullSummary {
            failed: config.groups.len(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        });
    }

    let mut summary = SuckPullSummary::default();

    for group in &config.groups {
        let mut attempted_this_group: usize = 0;
        let since = match config.since_override {
            Some(ts) => ts,
            None => read_cursor(pool, group).await?.unwrap_or(default_since),
        };

        let date_str = format_nntp_date(since);
        let newnews_cmd = format!("NEWNEWS {} {} GMT\r\n", group, date_str);

        if let Err(e) = writer.write_all(newnews_cmd.as_bytes()).await {
            tracing::warn!("suck_pull: write NEWNEWS for {group} failed: {e}");
            summary.failed += 1;
            continue;
        }

        line.clear();
        if let Err(e) = reader.read_line(&mut line).await {
            tracing::warn!("suck_pull: read NEWNEWS response for {group} failed: {e}");
            summary.failed += 1;
            continue;
        }
        let code = crate::import::parse_nntp_response_code(&line);
        if code != 230 {
            tracing::info!(
                "suck_pull: NEWNEWS {group} returned code {code}: {}",
                line.trim()
            );
            summary.failed += 1;
            continue;
        }

        // Collect dot-terminated list of Message-IDs.
        let mut msgids: Vec<String> = Vec::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("suck_pull: read msgid list for {group} failed: {e}");
                    break;
                }
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed == "." {
                break;
            }
            msgids.push(trimmed.to_string());
        }

        summary.new_articles += msgids.len();

        for msgid in &msgids {
            match fetch_article_with_retry(&mut writer, &mut reader, msgid, config.max_retries)
                .await
            {
                FetchResult::Fetched(bytes) => {
                    use crate::peering::ingestion::{check_ingest, IngestResult};
                    use crate::peering::ingestion_queue::QueuedArticle;

                    match check_ingest(msgid, &bytes, msgid_map).await {
                        IngestResult::Accepted => {
                            match ingestion_sender
                                .try_enqueue(QueuedArticle {
                                    bytes,
                                    message_id: msgid.to_string(),
                                })
                                .await
                            {
                                Ok(()) => {
                                    tracing::debug!("suck_pull: enqueued {msgid}");
                                    summary.fetched += 1;
                                    attempted_this_group += 1;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "suck_pull: ingestion queue rejected {msgid}: {e}"
                                    );
                                    summary.failed += 1;
                                    attempted_this_group += 1;
                                }
                            }
                        }
                        IngestResult::Duplicate => {
                            tracing::debug!("suck_pull: duplicate {msgid}");
                            summary.skipped_duplicate += 1;
                            attempted_this_group += 1;
                        }
                        IngestResult::Rejected(reason) => {
                            tracing::warn!("suck_pull: rejected {msgid}: {reason}");
                            summary.failed += 1;
                            attempted_this_group += 1;
                        }
                        IngestResult::TransientError(reason) => {
                            tracing::warn!("suck_pull: transient error checking {msgid}: {reason}");
                            summary.failed += 1;
                            // Transient: do not count toward attempted_this_group
                            // so the cursor is not advanced past this article.
                        }
                    }
                }
                FetchResult::NotFound => {
                    tracing::debug!("suck_pull: not found (430) {msgid}");
                    summary.skipped_duplicate += 1;
                    attempted_this_group += 1;
                }
                FetchResult::Failed => {
                    tracing::warn!("suck_pull: failed to fetch {msgid}");
                    summary.failed += 1;
                    // Network failure: do not count toward attempted_this_group
                    // so the cursor is not advanced past an article we couldn't
                    // even retrieve.
                }
            }
        }

        // Advance the cursor whenever we made a definitive attempt on at least
        // one article (accepted, rejected, duplicate, or 430-not-found).
        // Transient failures (network errors, TransientError from check_ingest)
        // do not count so we retry those articles on the next run.
        // This prevents an infinite loop when a permanently-invalid article
        // sits at the current cursor position: previously the cursor only
        // advanced on successful fetches, so all-rejected batches would be
        // retried indefinitely.
        if attempted_this_group > 0 {
            update_cursor(pool, group, now_unix).await?;
        }
    }

    // Send QUIT.
    let _ = writer.write_all(b"QUIT\r\n").await;

    summary.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(summary)
}

// ── Cursor helpers ─────────────────────────────────────────────────────────────

async fn ensure_cursor_table(pool: &AnyPool) -> Result<(), StorageError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS suck_pull_cursor (\
            group_name TEXT PRIMARY KEY NOT NULL,\
            last_fetched_unix INTEGER NOT NULL\
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

async fn read_cursor(pool: &AnyPool, group: &str) -> Result<Option<u64>, StorageError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT last_fetched_unix FROM suck_pull_cursor WHERE group_name = ?")
            .bind(group)
            .fetch_optional(pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(row.map(|(ts,)| ts as u64))
}

async fn update_cursor(pool: &AnyPool, group: &str, unix_secs: u64) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO suck_pull_cursor (group_name, last_fetched_unix) VALUES (?, ?) \
         ON CONFLICT (group_name) DO UPDATE SET last_fetched_unix = EXCLUDED.last_fetched_unix",
    )
    .bind(group)
    .bind(unix_secs as i64)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

// ── Article fetch ──────────────────────────────────────────────────────────────

#[derive(Debug)]
enum FetchResult {
    /// Article bytes were successfully received from the wire.
    ///
    /// The accumulated bytes are returned so the caller can feed them into the
    /// ingestion pipeline.  Full pipeline wiring (run_pipeline / AppState) is
    /// not yet plumbed through the suck_pull import path — see follow-up work
    /// tracked in the usenet-ipfs-a4b6 epic.
    Fetched(Vec<u8>),
    NotFound,
    Failed,
}

async fn fetch_article_with_retry(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    msgid: &str,
    max_retries: usize,
) -> FetchResult {
    let mut attempts = 0usize;
    loop {
        match fetch_article(writer, reader, msgid).await {
            FetchResult::Fetched(bytes) => return FetchResult::Fetched(bytes),
            FetchResult::NotFound => return FetchResult::NotFound,
            FetchResult::Failed => {
                attempts += 1;
                if attempts > max_retries {
                    return FetchResult::Failed;
                }
                tracing::debug!("suck_pull: retry {attempts}/{max_retries} for {msgid}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn fetch_article(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    msgid: &str,
) -> FetchResult {
    let cmd = format!("ARTICLE {msgid}\r\n");
    if let Err(e) = writer.write_all(cmd.as_bytes()).await {
        tracing::warn!("suck_pull: write ARTICLE {msgid} failed: {e}");
        return FetchResult::Failed;
    }

    let mut line = String::new();
    line.clear();
    match reader.read_line(&mut line).await {
        Ok(0) => return FetchResult::Failed,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("suck_pull: read ARTICLE response for {msgid} failed: {e}");
            return FetchResult::Failed;
        }
    }

    let code = crate::import::parse_nntp_response_code(&line);
    match code {
        430 => return FetchResult::NotFound,
        220 => {}
        _ => {
            tracing::info!(
                "suck_pull: ARTICLE {msgid} unexpected code {code}: {}",
                line.trim()
            );
            return FetchResult::Failed;
        }
    }

    // Read dot-terminated article body and accumulate bytes.
    // RFC 3977 §3.1.1: a lone "." terminates the block; ".." on the wire
    // represents a single "." in the article (dot-stuffing).
    let mut body: Vec<u8> = Vec::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => return FetchResult::Failed,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("suck_pull: read article body for {msgid} failed: {e}");
                return FetchResult::Failed;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            break;
        }
        // Undo dot-stuffing: a line beginning with ".." on the wire is a
        // single "." in the article.
        let out_line = if trimmed.starts_with("..") {
            &trimmed[1..]
        } else {
            trimmed
        };
        body.extend_from_slice(out_line.as_bytes());
        body.extend_from_slice(b"\r\n");
        if body.len() > MAX_ARTICLE_BYTES {
            tracing::warn!(
                "suck_pull: article {msgid} exceeded {} bytes; dropping",
                MAX_ARTICLE_BYTES
            );
            return FetchResult::Failed;
        }
    }

    FetchResult::Fetched(body)
}

// ── Date formatting ────────────────────────────────────────────────────────────

/// Format a Unix timestamp as NNTP NEWNEWS date/time string.
///
/// Returns `"YYYYMMDD HHMMSS"` (caller appends `" GMT"` in the NEWNEWS command).
pub(crate) fn format_nntp_date(unix_secs: u64) -> String {
    use chrono::DateTime;
    let dt = DateTime::from_timestamp(unix_secs as i64, 0).unwrap_or(DateTime::UNIX_EPOCH);
    dt.format("%Y%m%d %H%M%S").to_string()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_nntp_date_epoch() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(format_nntp_date(0), "19700101 000000");
    }

    #[test]
    fn format_nntp_date_known_date() {
        // 2024-01-15 12:30:45 UTC
        // 2024-01-15: days from epoch = 19737
        // 19737 * 86400 = 1705276800, + 12*3600 + 30*60 + 45 = 45045
        // = 1705276800 + 45045 = 1705321845
        // Cross-checked: python3 -c "import datetime; print(int(datetime.datetime(2024,1,15,12,30,45,tzinfo=datetime.timezone.utc).timestamp()))"
        assert_eq!(format_nntp_date(1705321845), "20240115 123045");
    }

    #[tokio::test]
    async fn run_suck_pull_connection_refused_fails_gracefully() {
        use stoa_core::msgid_map::MsgIdMap;

        // Use a port that nothing is listening on
        let tmp_transit = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let transit_url = format!("sqlite://{}", tmp_transit.to_str().unwrap());
        let pool = stoa_core::db_pool::try_open_any_pool(&transit_url, 1)
            .await
            .unwrap();

        // Build a MsgIdMap backed by a temp file pool.
        let tmp_core = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let core_url = format!("sqlite://{}", tmp_core.to_str().unwrap());
        stoa_core::migrations::run_migrations(&core_url)
            .await
            .unwrap();
        let core_pool = stoa_core::db_pool::try_open_any_pool(&core_url, 1)
            .await
            .unwrap();
        let msgid_map = MsgIdMap::new(core_pool);

        // Minimal ingestion queue; the receiver is dropped immediately since
        // no articles will be enqueued in this test (TCP connect fails).
        let (ingestion_sender, _rx) =
            crate::peering::ingestion_queue::ingestion_queue(16, u64::MAX);

        let config = SuckPullConfig {
            remote_addr: "127.0.0.1:19998".to_string(),
            groups: vec!["comp.lang.rust".to_string()],
            since_override: Some(0),
            max_retries: 1,
        };
        // Should not panic; connection failure is handled gracefully
        let result = run_suck_pull(&pool, &config, &ingestion_sender, &msgid_map).await;
        // Either Ok with 0 fetched or Err — either is acceptable, no panic
        match result {
            Ok(s) => assert_eq!(s.fetched, 0),
            Err(_) => {} // Also acceptable
        }
    }

    #[test]
    fn summary_display_is_readable() {
        let s = SuckPullSummary {
            new_articles: 10,
            fetched: 8,
            skipped_duplicate: 2,
            failed: 0,
            elapsed_ms: 1234,
        };
        let text = s.to_string();
        assert!(text.contains("10") || text.contains("fetched"));
    }
}
