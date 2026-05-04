use cid::Cid;
use multihash_codetable::Multihash;
use stoa_core::article::GroupName;
use stoa_core::group_log::append::append as crdt_append;
use stoa_core::group_log::types::{LogEntry, LogEntryId};
use stoa_core::group_log::verify::verify_signature;
use stoa_core::group_log::LogStorage;
use stoa_core::hlc::HlcTimestamp;
use stoa_core::signing::SigningKey;
use stoa_core::InjectionSource;

use crate::session::response::Response;
use crate::store::article_numbers::ArticleNumberStore;

/// Result of appending an article to the group logs.
pub struct AppendResult {
    /// `(group_name, article_number)` for each group the article was appended to.
    pub assignments: Vec<(String, u64)>,
}

/// Convert a `LogEntryId` to a `Cid` suitable for use as a `parent_cid` in a
/// subsequent log entry.
///
/// The CID uses DAG-CBOR codec (0x71) and wraps the 32-byte entry ID as a
/// SHA2-256 multihash, matching the convention in `append::compute_entry_id`.
fn entry_id_to_cid(id: &LogEntryId) -> Cid {
    let mh =
        Multihash::wrap(0x12, id.as_bytes()).expect("32-byte SHA2-256 multihash is always valid");
    Cid::new_v1(0x71, mh)
}

/// Append `article_cid` to the log for each group in `newsgroups`, assigning
/// a local article number in each group.
///
/// `hlc_timestamps` must have one pre-computed HLC wall_ms value per entry in
/// `newsgroups`.  The caller is responsible for generating these under the HLC
/// clock mutex (and releasing the mutex before calling this function) so that
/// the mutex is not held across async I/O operations.
///
/// Each log entry is signed over its canonical bytes
/// (`hlc_timestamp BE-8 || article_cid || sorted parent_cids`) so that entries
/// are independently verifiable from the log alone without fetching the article.
///
/// Steps for each group:
/// 1. Get current tips from storage → parent CIDs.
/// 2. Compute canonical bytes and sign to produce `operator_signature`.
/// 3. Build a `LogEntry` with the HLC timestamp, article CID, signature, and
///    parent CIDs.
/// 4. Call `crdt_append` to persist the entry.
/// 5. Call `article_numbers.assign_number` to get the local article number.
/// 6. Collect `(group_name, article_number)` pairs.
///
/// If any step fails for any group, returns `Err(441 Posting failed)`.
pub async fn append_to_groups<S: LogStorage>(
    log_storage: &S,
    article_numbers: &ArticleNumberStore,
    hlc_timestamps: &[u64],
    article_cid: &Cid,
    signing_key: &SigningKey,
    newsgroups: &[GroupName],
    injection_source: InjectionSource,
) -> Result<AppendResult, Response> {
    if hlc_timestamps.len() != newsgroups.len() {
        return Err(Response::new(
            500,
            format!(
                "Internal error: hlc_timestamps length {} != newsgroups length {}",
                hlc_timestamps.len(),
                newsgroups.len()
            ),
        ));
    }

    let mut assignments = Vec::with_capacity(newsgroups.len());

    for (group, &hlc_ts) in newsgroups.iter().zip(hlc_timestamps.iter()) {
        // Only write the group log entry (which replicates to peers) when the
        // injection source is peerable.  SmtpListId articles are local-only.
        if injection_source.is_peerable() {
            let current_tips = log_storage
                .list_tips(group)
                .await
                .map_err(|e| Response::new(441, format!("storage error listing tips: {e}")))?;

            let parent_cids: Vec<Cid> = current_tips.iter().map(entry_id_to_cid).collect();

            // Sign the log entry canonical bytes so the entry is independently
            // verifiable without fetching the article from IPFS.
            // canonical = hlc_timestamp (8 BE bytes) || article_cid || sorted parent_cids
            let operator_signature = {
                let mut canonical = Vec::new();
                canonical.extend_from_slice(&hlc_ts.to_be_bytes());
                canonical.extend_from_slice(&article_cid.to_bytes());
                let mut parent_bytes: Vec<Vec<u8>> =
                    parent_cids.iter().map(|c| c.to_bytes()).collect();
                parent_bytes.sort();
                for pb in &parent_bytes {
                    canonical.extend_from_slice(pb);
                }
                let sig = stoa_core::signing::sign(signing_key, &canonical);
                sig.to_bytes().to_vec()
            };

            let entry = LogEntry {
                hlc_timestamp: HlcTimestamp {
                    wall_ms: hlc_ts,
                    logical: 0,
                    node_id: [0u8; 8],
                },
                article_cid: *article_cid,
                operator_signature,
                parent_cids,
            };

            let verified = verify_signature(entry, &signing_key.verifying_key())
                .map_err(|e| Response::new(441, format!("log entry self-check failed: {e}")))?;

            crdt_append(log_storage, group, verified)
                .await
                .map_err(|e| Response::new(441, format!("log append failed for {group}: {e}")))?;
        }

        // Article numbers and overview are always assigned regardless of source
        // so that local readers can access all articles.
        let article_number = article_numbers
            .assign_number(group.as_str(), article_cid)
            .await
            .map_err(|e| Response::new(441, format!("article number assignment failed: {e}")))?;

        assignments.push((group.as_str().to_owned(), article_number));
    }

    Ok(AppendResult { assignments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};
    use stoa_core::group_log::MemLogStorage;
    use stoa_core::hlc::HlcClock;
    use stoa_core::signing::SigningKey;
    use stoa_core::InjectionSource;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    /// Generate `n` HLC timestamps using a fixed test clock.
    fn test_timestamps(n: usize) -> Vec<u64> {
        let mut clock = HlcClock::new([0x01; 8], 1_000_000);
        (0..n).map(|_| clock.send(1_000_000).wall_ms).collect()
    }

    async fn make_article_numbers() -> (ArticleNumberStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (ArticleNumberStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn append_to_single_group() {
        let log_storage = MemLogStorage::new();
        let (article_numbers, _tmp) = make_article_numbers().await;
        let cid = test_cid(b"article-single");
        let groups = vec![GroupName::new("comp.lang.rust").unwrap()];
        let timestamps = test_timestamps(groups.len());

        let result = append_to_groups(
            &log_storage,
            &article_numbers,
            &timestamps,
            &cid,
            &test_signing_key(),
            &groups,
            InjectionSource::NntpPost,
        )
        .await
        .unwrap();

        assert_eq!(result.assignments.len(), 1);
        assert_eq!(result.assignments[0].0, "comp.lang.rust");
        assert_eq!(result.assignments[0].1, 1);
    }

    #[tokio::test]
    async fn append_to_three_groups() {
        let log_storage = MemLogStorage::new();
        let (article_numbers, _tmp) = make_article_numbers().await;
        let cid = test_cid(b"article-three-groups");
        let groups = vec![
            GroupName::new("comp.lang.rust").unwrap(),
            GroupName::new("comp.lang.python").unwrap(),
            GroupName::new("alt.test").unwrap(),
        ];
        let timestamps = test_timestamps(groups.len());

        let result = append_to_groups(
            &log_storage,
            &article_numbers,
            &timestamps,
            &cid,
            &test_signing_key(),
            &groups,
            InjectionSource::NntpPost,
        )
        .await
        .unwrap();

        assert_eq!(result.assignments.len(), 3);

        let group_names: Vec<&str> = result.assignments.iter().map(|(g, _)| g.as_str()).collect();
        assert!(group_names.contains(&"comp.lang.rust"));
        assert!(group_names.contains(&"comp.lang.python"));
        assert!(group_names.contains(&"alt.test"));

        for (_, num) in &result.assignments {
            assert_eq!(*num, 1, "each group should start at article number 1");
        }
    }

    #[tokio::test]
    async fn sequential_appends_increment_numbers() {
        let log_storage = MemLogStorage::new();
        let (article_numbers, _tmp) = make_article_numbers().await;
        let group = vec![GroupName::new("comp.lang.rust").unwrap()];

        let key = test_signing_key();
        let cid1 = test_cid(b"article-seq-1");
        let r1 = append_to_groups(
            &log_storage,
            &article_numbers,
            &test_timestamps(group.len()),
            &cid1,
            &key,
            &group,
            InjectionSource::NntpPost,
        )
        .await
        .unwrap();

        let cid2 = test_cid(b"article-seq-2");
        let r2 = append_to_groups(
            &log_storage,
            &article_numbers,
            &test_timestamps(group.len()),
            &cid2,
            &key,
            &group,
            InjectionSource::NntpPost,
        )
        .await
        .unwrap();

        assert_eq!(r1.assignments[0].1, 1);
        assert_eq!(r2.assignments[0].1, 2);
    }

    #[tokio::test]
    async fn log_entry_in_storage() {
        let log_storage = MemLogStorage::new();
        let (article_numbers, _tmp) = make_article_numbers().await;
        let cid = test_cid(b"article-log-check");
        let group_name = GroupName::new("comp.lang.rust").unwrap();
        let groups = vec![group_name.clone()];
        let timestamps = test_timestamps(groups.len());

        append_to_groups(
            &log_storage,
            &article_numbers,
            &timestamps,
            &cid,
            &test_signing_key(),
            &groups,
            InjectionSource::NntpPost,
        )
        .await
        .unwrap();

        let tips = log_storage.list_tips(&group_name).await.unwrap();
        assert!(
            !tips.is_empty(),
            "log_storage must have at least one tip after append"
        );
    }

    /// SmtpListId articles must get an article number (so local readers can
    /// see them) but must NOT produce a group log entry (local-only, not
    /// replicated to peers).
    #[tokio::test]
    async fn smtp_list_id_skips_log_but_assigns_number() {
        let log_storage = MemLogStorage::new();
        let (article_numbers, _tmp) = make_article_numbers().await;
        let cid = test_cid(b"article-list-id");
        let group_name = GroupName::new("comp.lang.rust").unwrap();
        let groups = vec![group_name.clone()];
        let timestamps = test_timestamps(groups.len());

        let result = append_to_groups(
            &log_storage,
            &article_numbers,
            &timestamps,
            &cid,
            &test_signing_key(),
            &groups,
            InjectionSource::SmtpListId,
        )
        .await
        .unwrap();

        assert_eq!(result.assignments.len(), 1, "must still get an assignment");
        assert_eq!(result.assignments[0].0, "comp.lang.rust");
        assert_eq!(
            result.assignments[0].1, 1,
            "article number must be assigned"
        );

        let tips = log_storage.list_tips(&group_name).await.unwrap();
        assert!(
            tips.is_empty(),
            "SmtpListId must not produce a group log entry; got {tips:?}"
        );
    }
}
