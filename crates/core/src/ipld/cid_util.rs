//! CID utilities and the dual-CID model for stoa articles.
//!
//! # DECISION (rbe3.20): dual-CID model separates dedup identity from IPFS address
//!
//! A single CID cannot serve both roles.  The root CID (DAG-CBOR) is not
//! stable across ingests because it encodes HLC timestamp and operator
//! signature, both of which differ per ingest.  The canonical CID (raw
//! wire bytes) is stable but not an IPFS address — requesting it from IPFS
//! would not return the article root node.  Conflating the two would break
//! either dedup (using root CID) or IPFS addressability (using canonical CID).
//! Do NOT use a single CID for both purposes.
//!
//! # The Dual-CID Model
//!
//! Every article in stoa has **two distinct CIDs**, and they must never
//! be confused with each other.
//!
//! ## Canonical CID (codec 0x55, raw)
//!
//! The *canonical CID* is a CIDv1 SHA-256 of the **deterministic canonical
//! bytes** of an article — specifically `SHA-256(len(header_bytes) as u32
//! big-endian ++ header_bytes ++ body_bytes)`.  The 4-byte length prefix
//! disambiguates the header/body split, preventing split-ambiguity collisions.
//! Because these bytes are fixed for a given article, the canonical CID is
//! stable across ingest paths and independent of any IPLD encoding.
//!
//! **Uses:**
//! - Key in the `message_id → CID` deduplication map (`msgid_map`).
//! - Detecting duplicate articles arriving from multiple peers.
//!
//! **Do not** use the canonical CID as an IPFS address.  Requesting it from
//! IPFS will not return the article root node; it references raw bytes that
//! are stored separately as the header and body sub-blocks.
//!
//! ## Root CID (codec 0x71, DAG-CBOR)
//!
//! The *root CID* is the CIDv1 SHA-256 of the DAG-CBOR encoding of the
//! [`ArticleRootNode`](crate::ipld::root_node::ArticleRootNode) block.  It is
//! the IPFS content address that actually locates the article in the block
//! store.
//!
//! **Uses:**
//! - Addressing the article in IPFS (`ipfs block get <root-cid>`).
//! - NNTP `X-Stoa-CID` article header.
//! - JMAP `x-stoa-cid` custom Email property.
//! - Group log entries.
//! - JMAP email `id` and `blobId` fields.
//!
//! **Do not** use the root CID as a map key for deduplication.  Two ingests
//! of the same article may produce different root CIDs if metadata fields
//! (e.g. `hlc_timestamp`) differ; use the canonical CID for identity checks.
//!
//! ## Summary
//!
//! | Property | Canonical CID | Root CID |
//! |---|---|---|
//! | Codec | 0x55 (raw) | 0x71 (DAG-CBOR) |
//! | Content hashed | len(header) ++ header ++ body bytes | DAG-CBOR ArticleRootNode |
//! | IPFS address? | No | Yes |
//! | Map key / dedup? | Yes | No |
//! | Stable across ingests? | Yes | No (HLC differs) |

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::ipld::codec::CODEC_RAW;

/// Compute the canonical CID (CIDv1 SHA-256, codec 0x55 raw) for an article.
///
/// The canonical CID is derived from the raw wire bytes of the article using
/// a length-prefixed encoding that unambiguously identifies the header/body
/// split.  The bytes hashed are:
///
/// ```text
/// SHA-256(len(header_bytes) as u32 big-endian ++ header_bytes ++ body_bytes)
/// ```
///
/// Prepending the 4-byte header length prevents split-ambiguity collisions:
/// two articles whose `header_bytes ++ body_bytes` concatenations are
/// identical but whose header/body splits differ will hash to different
/// values and therefore receive different canonical CIDs.
///
/// The CID is stable across ingest paths and is the correct key to use in the
/// `message_id → CID` deduplication map.
///
/// See the [module-level documentation](self) for the distinction between the
/// canonical CID and the root CID.
///
/// # Arguments
/// - `header_bytes`: verbatim RFC 5536 wire header bytes
/// - `body_bytes`: dot-unstuffed NNTP body bytes
///
/// # Panics
///
/// Panics if `header_bytes.len()` exceeds [`u32::MAX`] (≈4 GiB).  This cannot
/// happen in practice: [`validate_article_ingress`](crate::validation::validate_article_ingress)
/// limits every header field to 998 bytes, making the maximum realistic header
/// length far below this bound.  Callers that bypass validation (e.g. test
/// helpers constructing artificial articles) must ensure the header slice
/// fits in a `u32`.
pub fn cid_for_article(header_bytes: &[u8], body_bytes: &[u8]) -> Cid {
    let header_len = u32::try_from(header_bytes.len())
        .expect("header_bytes length exceeds u32::MAX — caller must enforce size limits via validate_article_ingress");
    let mut combined = Vec::with_capacity(4 + header_bytes.len() + body_bytes.len());
    combined.extend_from_slice(&header_len.to_be_bytes());
    combined.extend_from_slice(header_bytes);
    combined.extend_from_slice(body_bytes);
    let digest = Code::Sha2_256.digest(&combined);
    Cid::new_v1(CODEC_RAW, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipld::codec::{CODEC_DAG_CBOR, CODEC_RAW};

    #[test]
    fn canonical_cid_uses_raw_codec() {
        let cid = cid_for_article(b"From: a@b.com\r\n", b"body\r\n");
        assert_eq!(
            cid.codec(),
            CODEC_RAW,
            "canonical CID must use raw codec (0x55)"
        );
    }

    #[test]
    fn canonical_cid_is_not_dag_cbor() {
        let cid = cid_for_article(b"From: a@b.com\r\n", b"body\r\n");
        assert_ne!(
            cid.codec(),
            CODEC_DAG_CBOR,
            "canonical CID must not use DAG-CBOR codec"
        );
    }

    #[test]
    fn canonical_cid_is_deterministic() {
        let headers = b"From: user@example.com\r\nMessage-ID: <x@y.com>\r\n";
        let body = b"Hello.\r\n";
        let cid1 = cid_for_article(headers, body);
        let cid2 = cid_for_article(headers, body);
        assert_eq!(cid1, cid2, "same bytes must produce same canonical CID");
    }

    #[test]
    fn different_bodies_produce_different_canonical_cids() {
        let headers = b"From: user@example.com\r\n";
        let cid1 = cid_for_article(headers, b"body one\r\n");
        let cid2 = cid_for_article(headers, b"body two\r\n");
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn canonical_cid_uses_sha256() {
        let cid = cid_for_article(b"Subject: Test\r\n", b"text\r\n");
        // SHA-256 multihash code is 0x12.
        assert_eq!(cid.hash().code(), 0x12u64);
    }

    #[test]
    fn no_length_extension_collision() {
        // header1="AB", body1="C" vs header2="A", body2="BC" — same concat, different split.
        let cid1 = cid_for_article(b"AB", b"C");
        let cid2 = cid_for_article(b"A", b"BC");
        assert_ne!(
            cid1, cid2,
            "different header/body splits must produce different CIDs"
        );
    }
}
