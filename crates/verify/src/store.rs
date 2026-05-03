//! SQLite-backed store for article verification results and seen signing keys.

use cid::Cid;

use crate::types::{ArticleVerification, SigType, VerifResult};

/// Stores and retrieves verification results from a database (SQLite or PostgreSQL).
pub struct VerificationStore {
    pool: sqlx::AnyPool,
}

impl VerificationStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Persist a list of verification results for an article CID.
    ///
    /// Existing rows for the same `(cid, sig_type, identity)` are replaced.
    pub async fn record_verifications(
        &self,
        cid: &Cid,
        verifications: &[ArticleVerification],
        verified_at_ms: i64,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        for v in verifications {
            let sig_type = v.sig_type.as_str();
            let result_str = v.result.as_str();
            // For DnsError, encode both domain and err separated by NUL so
            // the domain survives the round-trip.  Domain names never contain
            // NUL, so this is unambiguous.  Other variants use reason() as-is.
            let dns_reason_buf: String;
            let reason: Option<&str> = match &v.result {
                crate::types::VerifResult::DnsError { domain, err } => {
                    // Strip any NUL bytes from domain before encoding.  RFC 1035
                    // domain labels cannot contain NUL, so a NUL in `domain`
                    // indicates a malformed DKIM-Signature header; removing it
                    // prevents the NUL-split in parse_result from misparsing the
                    // stored value.
                    let safe_domain = domain.replace('\x00', "");
                    dns_reason_buf = format!("{safe_domain}\x00{err}");
                    Some(&dns_reason_buf)
                }
                r => r.reason(),
            };
            // The schema defines identity as NOT NULL DEFAULT ''. Map None
            // (Fail/NoKey/ParseError with no known key) to empty string so
            // the INSERT does not violate the NOT NULL constraint.  An empty
            // string identity is the schema-documented sentinel for "unknown".
            let identity: &str = v.identity.as_deref().unwrap_or("");
            sqlx::query(
                "INSERT INTO article_verifications \
                 (cid, sig_type, result, identity, reason, verified_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (cid, sig_type, identity) DO UPDATE SET \
                 result = EXCLUDED.result, \
                 reason = EXCLUDED.reason, \
                 verified_at = EXCLUDED.verified_at",
            )
            .bind(&cid_bytes)
            .bind(sig_type)
            .bind(result_str)
            .bind(identity)
            .bind(reason)
            .bind(verified_at_ms)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Retrieve all verification results for an article CID.
    ///
    /// Returns an empty vec when no results have been recorded yet.
    pub async fn get_verifications(
        &self,
        cid: &Cid,
    ) -> Result<Vec<ArticleVerification>, sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT sig_type, result, identity, reason \
             FROM article_verifications \
             WHERE cid = ?",
        )
        .bind(&cid_bytes)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(sig_type_str, result_str, identity, reason)| {
                let sig_type = parse_sig_type(&sig_type_str)?;
                let result = parse_result(&result_str, reason.as_deref(), &sig_type);
                // Empty string is the sentinel for "unknown" identity; convert
                // back to None to match the in-memory representation.
                let identity = identity.filter(|s| !s.is_empty());
                Some(ArticleVerification {
                    sig_type,
                    result,
                    identity,
                })
            })
            .collect())
    }

    /// Record a seen Ed25519 public key.
    ///
    /// `key_data` is the 32 raw bytes of the verifying key.
    /// `key_id` is the lowercase hex SHA-256 of `key_data`.
    /// Only inserts the first time; ignores duplicate key_ids.
    pub async fn upsert_seen_ed25519_key(
        &self,
        key_id: &str,
        key_data: &[u8; 32],
        first_seen_cid: &Cid,
        first_seen_at_ms: i64,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = first_seen_cid.to_bytes();
        sqlx::query(
            "INSERT INTO seen_keys \
             (key_type, key_id, key_data, first_seen_cid, first_seen_at) \
             VALUES ('ed25519', ?, ?, ?, ?) \
             ON CONFLICT (key_type, key_id) DO NOTHING",
        )
        .bind(key_id)
        .bind(key_data.as_slice())
        .bind(&cid_bytes)
        .bind(first_seen_at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn parse_sig_type(s: &str) -> Option<SigType> {
    match s {
        "dkim" => Some(SigType::Dkim),
        "x-stoa-sig" => Some(SigType::XUsenetIpfsSig),
        other => {
            tracing::warn!(
                sig_type = other,
                "unrecognised sig_type in article_verifications; skipping row"
            );
            None
        }
    }
}

fn parse_result(result: &str, reason: Option<&str>, _sig_type: &SigType) -> VerifResult {
    match result {
        "pass" => VerifResult::Pass,
        "fail" => VerifResult::Fail {
            reason: reason.unwrap_or("unknown").to_owned(),
        },
        "dns-error" => {
            // reason was stored as "domain\x00err" (NUL-separated).
            // Older rows may lack NUL; treat the whole string as err in that case.
            let raw = reason.unwrap_or("");
            let (domain, err) = match raw.split_once('\x00') {
                Some((d, e)) => (d.to_owned(), e.to_owned()),
                None => (String::new(), raw.to_owned()),
            };
            VerifResult::DnsError { domain, err }
        }
        "no-key" => VerifResult::NoKey,
        "neutral" => VerifResult::Neutral {
            reason: reason.unwrap_or("unknown").to_owned(),
        },
        _ => VerifResult::ParseError {
            reason: format!("unknown result type '{}': {}", result, reason.unwrap_or("")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (VerificationStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::run_migrations(&url).await.expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (VerificationStore::new(pool), tmp)
    }

    fn dummy_cid() -> Cid {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(b"test article");
        // Build a raw multihash: 0x12 = sha2-256, 0x20 = 32 bytes
        let mut mh_bytes = vec![0x12u8, 0x20];
        mh_bytes.extend_from_slice(&hash);
        let mh = cid::multihash::Multihash::<64>::from_bytes(&mh_bytes)
            .expect("valid sha2-256 multihash");
        Cid::new_v1(0x55, mh)
    }

    /// Fail result (identity=None) must be stored and retrieved without error.
    /// Previously this silently dropped the row because None bound as SQL NULL
    /// violates the NOT NULL constraint on the identity column.
    #[tokio::test]
    async fn fail_result_with_no_identity_round_trips() {
        let (store, _tmp) = make_store().await;
        let cid = dummy_cid();
        let verifications = vec![ArticleVerification {
            sig_type: SigType::XUsenetIpfsSig,
            result: VerifResult::Fail {
                reason: "no key matched".to_owned(),
            },
            identity: None,
        }];
        store
            .record_verifications(&cid, &verifications, 0)
            .await
            .expect("record must succeed for Fail with no identity");

        let retrieved = store.get_verifications(&cid).await.expect("get");
        assert_eq!(retrieved.len(), 1, "Fail row must be retrievable");
        assert!(
            matches!(retrieved[0].result, VerifResult::Fail { .. }),
            "result must be Fail"
        );
        assert_eq!(
            retrieved[0].identity, None,
            "identity must round-trip as None"
        );
    }

    /// NoKey result (identity=None) must also persist correctly.
    #[tokio::test]
    async fn no_key_result_round_trips() {
        let (store, _tmp) = make_store().await;
        let cid = dummy_cid();
        let verifications = vec![ArticleVerification {
            sig_type: SigType::XUsenetIpfsSig,
            result: VerifResult::NoKey,
            identity: None,
        }];
        store
            .record_verifications(&cid, &verifications, 0)
            .await
            .expect("record must succeed for NoKey");

        let retrieved = store.get_verifications(&cid).await.expect("get");
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].result, VerifResult::NoKey);
        assert_eq!(retrieved[0].identity, None);
    }

    /// Pass result with a known identity round-trips correctly.
    #[tokio::test]
    async fn pass_result_with_identity_round_trips() {
        let (store, _tmp) = make_store().await;
        let cid = dummy_cid();
        let key_id = "abcdef1234567890".to_owned();
        let verifications = vec![ArticleVerification {
            sig_type: SigType::XUsenetIpfsSig,
            result: VerifResult::Pass,
            identity: Some(key_id.clone()),
        }];
        store
            .record_verifications(&cid, &verifications, 0)
            .await
            .expect("record");

        let retrieved = store.get_verifications(&cid).await.expect("get");
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].result, VerifResult::Pass);
        assert_eq!(retrieved[0].identity, Some(key_id));
    }
}
