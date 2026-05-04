//! Message-ID to CID reindex tool.
//!
//! Rebuilds the msgid_map SQLite table from raw article content.
//! Used for disaster recovery when SQLite state is lost but article
//! content is still available (e.g., from IPFS block store walk).

use cid::Cid;
use sqlx::AnyPool;
use stoa_core::error::StorageError;
use stoa_core::validation::validate_message_id;

/// Result of a reindex run.
#[derive(Debug, Default)]
pub struct ReindexSummary {
    pub total_scanned: usize,
    pub indexed: usize,
    pub skipped_not_article: usize,
    pub skipped_duplicate: usize,
    pub dry_run: bool,
}

impl std::fmt::Display for ReindexSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = if self.dry_run { "DRY RUN " } else { "" };
        write!(
            f,
            "{mode}scanned: {}, indexed: {}, skipped(not_article): {}, skipped(duplicate): {}",
            self.total_scanned, self.indexed, self.skipped_not_article, self.skipped_duplicate
        )
    }
}

/// Reindex configuration.
#[derive(Debug, Clone)]
pub struct ReindexConfig {
    /// If true, report what would be indexed but don't write to SQLite.
    pub dry_run: bool,
    /// Log progress every N blocks.
    pub progress_interval: usize,
}

impl Default for ReindexConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            progress_interval: 1000,
        }
    }
}

/// Run a reindex pass over the provided articles.
///
/// For each `(cid, raw_bytes)` pair:
/// - Attempt to extract the Message-ID header from `raw_bytes`
/// - If found and not already in msgid_map: insert `(message_id, cid_str)` into msgid_map
/// - If not found: count as skipped_not_article
/// - If already present: count as skipped_duplicate
///
/// Logs progress every `config.progress_interval` items.
pub async fn run_reindex<I>(
    articles: I,
    pool: &AnyPool,
    config: &ReindexConfig,
) -> Result<ReindexSummary, StorageError>
where
    I: IntoIterator<Item = (Cid, Vec<u8>)>,
{
    let mut summary = ReindexSummary {
        dry_run: config.dry_run,
        ..Default::default()
    };

    for (cid, raw) in articles {
        summary.total_scanned += 1;
        if summary.total_scanned % config.progress_interval == 0 {
            tracing::info!(count = summary.total_scanned, "reindex progress");
        }

        let msg_id = match extract_message_id_bytes(&raw) {
            Some(id) => id,
            None => {
                summary.skipped_not_article += 1;
                continue;
            }
        };

        // Reject malformed Message-IDs to avoid inserting invalid keys into
        // the msgid_map.  Articles stored via the normal ingestion path are
        // already validated, but corrupted blocks or manual imports may not be.
        if validate_message_id(&msg_id).is_err() {
            tracing::warn!(msg_id, cid = %cid, "reindex: skipping article with invalid Message-ID");
            summary.skipped_not_article += 1;
            continue;
        }

        if config.dry_run {
            tracing::debug!(msg_id, cid = %cid, "dry-run: would index");
            summary.indexed += 1;
            continue;
        }

        // Insert, skipping if already present
        let cid_str = cid.to_string();
        let result = sqlx::query(
            "INSERT INTO msgid_map (message_id, cid) VALUES (?, ?) \
             ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(&msg_id)
        .bind(&cid_str)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            summary.skipped_duplicate += 1;
        } else {
            summary.indexed += 1;
        }
    }

    tracing::info!(
        total = summary.total_scanned,
        indexed = summary.indexed,
        "reindex complete"
    );
    Ok(summary)
}

/// Extract Message-ID from raw article bytes.
///
/// Delegates to [`crate::peering::ingestion::extract_body_msgid`], which
/// handles RFC 5322 §2.2.3 header folding (continuation lines beginning with
/// SP or HTAB).  The previous implementation used `String::from_utf8_lossy` +
/// `.lines()` and missed folded headers, causing folded-Message-ID articles to
/// be counted as `skipped_not_article` during disaster-recovery reindex.
pub fn extract_message_id_bytes(raw: &[u8]) -> Option<String> {
    crate::peering::ingestion::extract_body_msgid(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    fn make_article(n: u8, msgid: &str) -> (Cid, Vec<u8>) {
        let raw = format!(
            "From: test@example.com\r\nMessage-ID: {msgid}\r\nNewsgroups: comp.test\r\n\r\nBody {n}\r\n"
        );
        (make_cid(&[n]), raw.into_bytes())
    }

    #[tokio::test]
    async fn reindex_20_articles_all_indexed() {
        let (pool, _tmp) = make_pool().await;
        let articles: Vec<(Cid, Vec<u8>)> = (0u8..20)
            .map(|i| make_article(i, &format!("<msg{i}@test.com>")))
            .collect();
        let config = ReindexConfig::default();
        let summary = run_reindex(articles, &pool, &config).await.unwrap();
        assert_eq!(summary.total_scanned, 20);
        assert_eq!(summary.indexed, 20);
        assert_eq!(summary.skipped_not_article, 0);
        assert_eq!(summary.skipped_duplicate, 0);
    }

    #[tokio::test]
    async fn reindex_skips_non_articles() {
        let (pool, _tmp) = make_pool().await;
        let raw = b"Content-Type: application/octet-stream\r\n\r\nBinary data".to_vec();
        let articles = vec![(make_cid(b"binary"), raw)];
        let config = ReindexConfig::default();
        let summary = run_reindex(articles, &pool, &config).await.unwrap();
        assert_eq!(summary.skipped_not_article, 1);
        assert_eq!(summary.indexed, 0);
    }

    #[tokio::test]
    async fn reindex_skips_duplicates() {
        let (pool, _tmp) = make_pool().await;
        let article = make_article(0, "<dup@test.com>");
        let config = ReindexConfig::default();
        run_reindex(vec![article.clone()], &pool, &config)
            .await
            .unwrap();
        let summary = run_reindex(vec![article], &pool, &config).await.unwrap();
        assert_eq!(summary.skipped_duplicate, 1);
        assert_eq!(summary.indexed, 0);
    }

    #[tokio::test]
    async fn reindex_dry_run_does_not_write() {
        let (pool, _tmp) = make_pool().await;
        let articles: Vec<(Cid, Vec<u8>)> = (0u8..5)
            .map(|i| make_article(i, &format!("<dry{i}@test.com>")))
            .collect();
        let config = ReindexConfig {
            dry_run: true,
            progress_interval: 1000,
        };
        let summary = run_reindex(articles, &pool, &config).await.unwrap();
        assert!(summary.dry_run);
        assert_eq!(summary.indexed, 5, "dry_run counts as 'would index'");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "dry_run should not write to DB");
    }

    #[test]
    fn extract_message_id_bytes_finds_header() {
        let raw = b"From: a@b.com\r\nMessage-ID: <abc@test.com>\r\n\r\nBody\r\n";
        assert_eq!(
            extract_message_id_bytes(raw).as_deref(),
            Some("<abc@test.com>")
        );
    }

    #[test]
    fn extract_message_id_bytes_returns_none_when_missing() {
        let raw = b"From: a@b.com\r\nSubject: No ID\r\n\r\nBody\r\n";
        assert_eq!(extract_message_id_bytes(raw), None);
    }

    #[test]
    fn extract_message_id_bytes_handles_folded_header() {
        // RFC 5322 §2.2.3: value entirely on a continuation line (SP-prefixed).
        // The old .lines() implementation returned None for this input.
        let raw = b"From: a@b.com\r\nMessage-ID:\r\n <folded@test.com>\r\n\r\nBody\r\n";
        assert_eq!(
            extract_message_id_bytes(raw).as_deref(),
            Some("<folded@test.com>"),
            "folded Message-ID must be extracted by reindex path"
        );
    }
}
