use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::canonical::log_entry_canonical_bytes;
use crate::error::{SigningError, StorageError};
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::hlc::HlcTimestamp;
use crate::signing::{verify, VerifyingKey};

use ed25519_dalek::Signature;

/// A [`LogEntry`] that has passed Ed25519 signature verification.
///
/// This type can only be constructed via [`verify_signature`] or (in tests)
/// via [`VerifiedEntry::new_for_test`], ensuring that any `VerifiedEntry`
/// in hand carries a valid operator signature.
pub struct VerifiedEntry(LogEntry);

impl VerifiedEntry {
    /// Extract the inner [`LogEntry`].
    pub fn into_inner(self) -> LogEntry {
        self.0
    }

    /// Read-only reference to the inner entry.
    pub fn as_entry(&self) -> &LogEntry {
        &self.0
    }

    /// Construct a `VerifiedEntry` without signature verification.
    ///
    /// Use only in tests that exercise backfill mechanics and are not testing
    /// signature correctness.  Production paths must go through
    /// [`verify_signature`].
    ///
    /// Only available when the `test-helpers` feature is enabled or in `#[cfg(test)]`
    /// contexts.  Never use this in production code.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new_for_test(entry: LogEntry) -> Self {
        Self(entry)
    }
}

/// Compute a deterministic hash of a tip set.
///
/// Tip CIDs are sorted lexicographically by their raw byte representation,
/// concatenated, then SHA2-256 hashed. An empty tip set produces the
/// SHA2-256 of an empty byte string.
pub fn tip_hash(tips: &[Cid]) -> [u8; 32] {
    let mut tip_bytes: Vec<Vec<u8>> = tips.iter().map(|c| c.to_bytes()).collect();
    tip_bytes.sort();
    let mut combined = Vec::new();
    for tb in &tip_bytes {
        combined.extend_from_slice(tb);
    }
    let digest = Code::Sha2_256.digest(&combined);
    digest
        .digest()
        .try_into()
        .expect("SHA2-256 is always 32 bytes")
}

/// Maximum number of parent CIDs allowed per log entry.
///
/// In normal CRDT operation entries have 1–2 parents (one after convergence,
/// two at a merge point).  Capping at 100 prevents an adversarial peer from
/// crafting entries that trigger O(n) DB lookups, SQL inserts, and BFS
/// enqueue per entry.
pub const MAX_PARENT_CIDS: usize = 100;

/// Errors returned by [`verify_entry`].
#[non_exhaustive]
#[derive(Debug)]
pub enum VerifyError {
    Storage(StorageError),
    InvalidSignature(SigningError),
    MissingParent(String),
    HlcNotMonotonic {
        entry: HlcTimestamp,
        parent: HlcTimestamp,
    },
    /// The provided `entry_id` does not match the SHA2-256 of the entry's
    /// canonical bytes.  Indicates the entry was tampered with or the wrong
    /// ID was supplied.
    EntryIdMismatch,
    /// `entry.parent_cids` exceeds [`MAX_PARENT_CIDS`].
    TooManyParents {
        count: usize,
    },
    /// `entry.article_cid` uses a codec other than DAG-CBOR (0x71).
    InvalidArticleCidCodec {
        codec: u64,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::MissingParent(cid) => write!(f, "parent entry not found: {cid}"),
            Self::HlcNotMonotonic { entry, parent } => write!(
                f,
                "HLC not monotonic: entry timestamp {entry:?} <= parent timestamp {parent:?}"
            ),
            Self::EntryIdMismatch => {
                write!(f, "entry ID does not match entry content hash")
            }
            Self::TooManyParents { count } => {
                write!(
                    f,
                    "entry has {count} parent CIDs; maximum is {MAX_PARENT_CIDS}"
                )
            }
            Self::InvalidArticleCidCodec { codec } => {
                write!(f, "article_cid codec 0x{codec:x} is not DAG-CBOR (0x71)")
            }
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::InvalidSignature(e) => Some(e),
            Self::MissingParent(_)
            | Self::HlcNotMonotonic { .. }
            | Self::EntryIdMismatch
            | Self::TooManyParents { .. }
            | Self::InvalidArticleCidCodec { .. } => None,
        }
    }
}

impl From<StorageError> for VerifyError {
    fn from(e: StorageError) -> Self {
        VerifyError::Storage(e)
    }
}

/// Verify only the Ed25519 signature in `entry.operator_signature`.
///
/// The signature must be valid over the canonical bytes:
/// `hlc_timestamp (8 BE bytes) || article_cid bytes || sorted parent_cid bytes`.
/// Parent existence and HLC monotonicity are NOT checked here; use
/// [`verify_entry`] for the full check.
///
/// On success, returns a [`VerifiedEntry`] that proves the entry carries a
/// valid operator signature.  This is the only stable way to produce a
/// `VerifiedEntry` in production code.
pub fn verify_signature(
    entry: LogEntry,
    pubkey: &VerifyingKey,
) -> Result<VerifiedEntry, VerifyError> {
    check_signature(&entry, pubkey)?;
    Ok(VerifiedEntry(entry))
}

/// Shared signature check over canonical log entry bytes.
fn check_signature(entry: &LogEntry, pubkey: &VerifyingKey) -> Result<(), VerifyError> {
    let canonical = log_entry_canonical_bytes(
        entry.hlc_timestamp.wall_ms,
        &entry.article_cid,
        &entry.parent_cids,
    );

    let sig_bytes: [u8; 64] = entry
        .operator_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            VerifyError::InvalidSignature(SigningError::SignatureLengthInvalid {
                got: entry.operator_signature.len(),
                expected: 64,
            })
        })?;
    let sig = Signature::from_bytes(&sig_bytes);
    verify(pubkey, &canonical, &sig).map_err(VerifyError::InvalidSignature)
}

/// Verify a log entry's consistency:
///
/// 1. The Ed25519 signature in `entry.operator_signature` is valid over the
///    canonical bytes: `hlc_timestamp (8 BE bytes) || article_cid bytes ||
///    sorted parent_cid bytes`.  The signature field itself is excluded from
///    the signed content.
/// 2. All parent CIDs listed in `entry.parent_cids` exist in `storage`.
/// 3. `entry.hlc_timestamp` is strictly greater than every parent's
///    `hlc_timestamp`.
/// 4. The provided `entry_id` matches `LogEntryId::from_entry(entry)`.
///
/// Genesis entries (no parents) pass checks 2 and 3 vacuously.
pub async fn verify_entry<S: LogStorage>(
    entry: &LogEntry,
    entry_id: &LogEntryId,
    storage: &S,
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    // ── 0. Structural bounds ──────────────────────────────────────────────────
    // Reject entries with an excessively large parent set before doing any
    // storage lookups.  This prevents amplification: one entry → O(n) DB reads
    // + O(n) inserts + O(n) BFS enqueue.
    if entry.parent_cids.len() > MAX_PARENT_CIDS {
        return Err(VerifyError::TooManyParents {
            count: entry.parent_cids.len(),
        });
    }

    // Reject entries whose article_cid uses any codec other than DAG-CBOR
    // (0x71).  An adversarial peer could supply a different codec that passes
    // signature verification but fails downstream IPFS fetch or IPLD decode.
    if entry.article_cid.codec() != 0x71 {
        return Err(VerifyError::InvalidArticleCidCodec {
            codec: entry.article_cid.codec(),
        });
    }

    // ── 1. Signature verification ─────────────────────────────────────────────
    check_signature(entry, pubkey)?;

    // ── 2 & 3. Parent existence and HLC monotonicity ──────────────────────────
    for parent_cid in &entry.parent_cids {
        let digest_bytes = parent_cid.hash().digest();
        let raw: [u8; 32] = digest_bytes.try_into().map_err(|_| {
            VerifyError::MissingParent(format!(
                "parent CID {} has a non-32-byte digest (length {})",
                parent_cid,
                parent_cid.hash().digest().len()
            ))
        })?;
        let parent_id = LogEntryId::from_bytes(raw);

        let parent_entry = match storage.get_entry(&parent_id).await? {
            Some(e) => e,
            None => return Err(VerifyError::MissingParent(parent_cid.to_string())),
        };

        if entry.hlc_timestamp <= parent_entry.hlc_timestamp {
            return Err(VerifyError::HlcNotMonotonic {
                entry: entry.hlc_timestamp,
                parent: parent_entry.hlc_timestamp,
            });
        }
    }

    // ── 4. Entry ID integrity ─────────────────────────────────────────────────
    if LogEntryId::from_entry(entry) != *entry_id {
        return Err(VerifyError::EntryIdMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::entry_id_bytes;
    use crate::group_log::mem_storage::MemLogStorage;
    use crate::signing::SigningKey;
    use multihash_codetable::Multihash;

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn sign_entry(entry: &mut LogEntry, key: &SigningKey) {
        let canonical = log_entry_canonical_bytes(
            entry.hlc_timestamp.wall_ms,
            &entry.article_cid,
            &entry.parent_cids,
        );
        let sig = crate::signing::sign(key, &canonical);
        entry.operator_signature = sig.to_bytes().to_vec();
    }

    /// Helper: store an entry in MemLogStorage and return its id CID.
    async fn store_entry(storage: &MemLogStorage, id: LogEntryId, entry: LogEntry) -> Cid {
        storage
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert");
        entry_id_to_cid(&id)
    }

    // ── tip_hash_deterministic ────────────────────────────────────────────────

    #[test]
    fn tip_hash_deterministic() {
        let cid_a = test_cid(b"aaa");
        let cid_b = test_cid(b"bbb");
        assert_eq!(
            tip_hash(&[cid_b.clone(), cid_a.clone()]),
            tip_hash(&[cid_a, cid_b]),
            "tip_hash must be order-independent"
        );
    }

    // ── tip_hash_empty ────────────────────────────────────────────────────────

    #[test]
    fn tip_hash_empty() {
        // SHA2-256 of the empty byte string, from an independent reference:
        // $ echo -n "" | sha256sum
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855",
        )
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");
        assert_eq!(tip_hash(&[]), expected);
    }

    // ── verify_entry_valid ────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_valid() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-valid"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        // Compute entry id the same way append.rs does (includes sig bytes).
        let entry_id = {
            let input = entry_id_bytes(
                entry.hlc_timestamp.wall_ms,
                &entry.article_cid,
                &entry.operator_signature,
                &entry.parent_cids,
            );
            let digest = Code::Sha2_256.digest(&input);
            LogEntryId::from_bytes(digest.digest().try_into().expect("32 bytes"))
        };

        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            result.is_ok(),
            "valid entry must pass verification: {result:?}"
        );
    }

    // ── verify_entry_bad_signature ────────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_bad_signature() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-tampered"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        // Flip the first byte of the signature to invalidate it.
        entry.operator_signature[0] ^= 0xff;

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::InvalidSignature(_))),
            "tampered signature must yield InvalidSignature, got {result:?}"
        );
    }

    // ── verify_entry_missing_parent ───────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_missing_parent() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Invent a parent CID whose digest is not in storage.
        let phantom_id = LogEntryId::from_bytes([0xde; 32]);
        let phantom_cid = entry_id_to_cid(&phantom_id);

        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 3_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-orphan"),
            operator_signature: vec![],
            parent_cids: vec![phantom_cid],
        };
        sign_entry(&mut entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::MissingParent(_))),
            "missing parent must yield MissingParent, got {result:?}"
        );
    }

    // ── verify_entry_hlc_not_monotonic ────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_hlc_not_monotonic() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Store a parent entry with hlc_timestamp = 5_000.
        let mut parent_entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 5_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"parent-article"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut parent_entry, &key);
        let parent_id = {
            let input = entry_id_bytes(
                parent_entry.hlc_timestamp.wall_ms,
                &parent_entry.article_cid,
                &parent_entry.operator_signature,
                &parent_entry.parent_cids,
            );
            let digest = Code::Sha2_256.digest(&input);
            LogEntryId::from_bytes(digest.digest().try_into().expect("32 bytes"))
        };
        let parent_cid = store_entry(&storage, parent_id, parent_entry).await;

        // Child entry with hlc_timestamp <= parent's (equal — not strictly greater).
        let mut child_entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 4_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"child-article"),
            operator_signature: vec![],
            parent_cids: vec![parent_cid],
        };
        sign_entry(&mut child_entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&child_entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::HlcNotMonotonic { .. })),
            "non-monotonic HLC must yield HlcNotMonotonic, got {result:?}"
        );
    }

    // ── verify_entry_wrong_entry_id ───────────────────────────────────────────

    /// A valid entry whose provided entry_id does not match the computed hash
    /// must be rejected with EntryIdMismatch.
    #[tokio::test]
    async fn verify_entry_wrong_entry_id() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 9_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-id-mismatch"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        // All-zeros is not the correct entry ID.
        let wrong_entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &wrong_entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::EntryIdMismatch)),
            "wrong entry_id must yield EntryIdMismatch, got {result:?}"
        );
    }

    // ── verify_entry_too_many_parents ─────────────────────────────────────────

    /// An entry with more than MAX_PARENT_CIDS parents must be rejected before
    /// any storage lookups are performed.
    #[tokio::test]
    async fn verify_entry_too_many_parents() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Build an entry with MAX_PARENT_CIDS + 1 parents.
        // The parent CIDs themselves don't exist in storage — the check must
        // fire before any DB lookup.
        let oversized_parents: Vec<Cid> = (0..=(MAX_PARENT_CIDS))
            .map(|i| test_cid(format!("phantom-parent-{i}").as_bytes()))
            .collect();
        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 10_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: test_cid(b"article-too-many-parents"),
            operator_signature: vec![],
            parent_cids: oversized_parents,
        };
        sign_entry(&mut entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::TooManyParents { count }) if count == MAX_PARENT_CIDS + 1),
            "oversized parent list must yield TooManyParents, got {result:?}"
        );
    }

    // ── verify_entry_wrong_codec ──────────────────────────────────────────────

    /// An entry whose article_cid uses a codec other than DAG-CBOR (0x71)
    /// must be rejected with InvalidArticleCidCodec before signature checks.
    #[tokio::test]
    async fn verify_entry_wrong_codec() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Use raw codec (0x55) instead of DAG-CBOR (0x71).
        let digest = Code::Sha2_256.digest(b"article-raw-codec");
        let wrong_codec_cid = Cid::new_v1(0x55, digest);

        let mut entry = LogEntry {
            hlc_timestamp: HlcTimestamp {
                wall_ms: 11_000,
                logical: 0,
                node_id: [0; 8],
            },
            article_cid: wrong_codec_cid,
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::InvalidArticleCidCodec { codec }) if codec == 0x55),
            "wrong codec must yield InvalidArticleCidCodec, got {result:?}"
        );
    }
}
