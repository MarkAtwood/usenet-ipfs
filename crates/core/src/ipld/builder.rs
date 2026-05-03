//! Article IPLD block set builder.
//!
//! This module produces the *root CID* (DAG-CBOR, codec 0x71) and all
//! associated blocks for an article.  For the *canonical CID* (raw, codec
//! 0x55) used for deduplication and `msgid_map` keying, see
//! [`crate::ipld::cid_util`].

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::ipld::{
    blocks::{body_block, header_block},
    header_map::build_header_map,
    metadata::compute_metadata,
    mime_parser::parse_mime,
    root_node::{ArticleRootNode, SCHEMA_VERSION},
};

use crate::ipld::codec::CODEC_DAG_CBOR;

/// Result of building a complete article IPLD block set.
#[derive(Debug)]
pub struct BuiltArticle {
    /// The canonical article CID (CIDv1 SHA-256 DAG-CBOR).
    /// This is the stable identifier used in the group log and Message-ID→CID map.
    pub root_cid: Cid,
    /// All IPLD blocks that must be written to IPFS storage, keyed by CID.
    /// Includes: root block, header block, body block, MIME block (if any),
    /// and all decoded content blocks from MIME parsing.
    pub blocks: Vec<(Cid, Vec<u8>)>,
    /// The root node (for inspection/debugging; also present in blocks).
    pub root_node: ArticleRootNode,
}

/// Error returned by [`build_article`].
#[non_exhaustive]
#[derive(Debug)]
pub enum BuildError {
    CborEncode(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::CborEncode(msg) => write!(f, "CBOR encoding error: {msg}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Build a complete IPLD article block set from wire bytes.
///
/// # Arguments
/// - `header_bytes`: verbatim RFC 5536 wire header bytes
/// - `body_bytes`: verbatim NNTP body bytes (after dot-unstuffing)
/// - `message_id`: Message-ID header value (including angle brackets)
/// - `newsgroups`: destination groups (sorted lexicographically)
/// - `hlc_timestamp`: HLC timestamp for this log entry
/// - `operator_signature`: raw 64-byte Ed25519 signature over the pre-sign
///   article bytes (from `sign_article`), or `vec![]` for unsigned articles.
///
/// # Returns
/// `BuiltArticle` containing the root CID and all blocks to store.
pub fn build_article(
    header_bytes: &[u8],
    body_bytes: &[u8],
    message_id: String,
    newsgroups: Vec<String>,
    hlc_timestamp: u64,
    operator_signature: Vec<u8>,
) -> Result<BuiltArticle, BuildError> {
    let (header_cid, header_block_bytes) = header_block(header_bytes);
    let (body_cid, body_block_bytes) = body_block(body_bytes);

    let header_map = build_header_map(header_bytes);
    let header_map_bytes = serde_ipld_dagcbor::to_vec(&header_map)
        .map_err(|e| BuildError::CborEncode(e.to_string()))?;
    let header_map_cid = dag_cbor_cid(&header_map_bytes);

    let parsed = parse_mime(header_bytes, body_bytes);

    let (mime_cid, mime_blocks) = match parsed {
        None => (None, Vec::new()),
        Some(p) => {
            let mime_bytes = serde_ipld_dagcbor::to_vec(&p.node)
                .map_err(|e| BuildError::CborEncode(e.to_string()))?;
            let cid = dag_cbor_cid(&mime_bytes);
            let mut blocks = vec![(cid, mime_bytes)];
            blocks.extend(p.blocks);
            (Some(cid), blocks)
        }
    };

    let metadata = compute_metadata(
        header_bytes,
        body_bytes,
        message_id,
        newsgroups,
        hlc_timestamp,
        operator_signature,
    );

    let root_node = ArticleRootNode {
        schema_version: SCHEMA_VERSION,
        header_cid,
        header_map_cid: Some(header_map_cid),
        body_cid,
        mime_cid,
        metadata,
    };

    let root_bytes = serde_ipld_dagcbor::to_vec(&root_node)
        .map_err(|e| BuildError::CborEncode(e.to_string()))?;
    let root_cid = dag_cbor_cid(&root_bytes);

    let mut blocks = vec![
        (root_cid, root_bytes),
        (header_cid, header_block_bytes),
        (header_map_cid, header_map_bytes),
        (body_cid, body_block_bytes),
    ];
    blocks.extend(mime_blocks);

    Ok(BuiltArticle {
        root_cid,
        blocks,
        root_node,
    })
}

fn dag_cbor_cid(bytes: &[u8]) -> Cid {
    let digest = Code::Sha2_256.digest(bytes);
    Cid::new_v1(CODEC_DAG_CBOR, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipld::root_node::ArticleRootNode;

    fn make_article_bytes() -> (Vec<u8>, Vec<u8>) {
        let headers = b"From: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nNewsgroups: comp.lang.rust\r\nSubject: Test article\r\nPath: news.example.com!user\r\n";
        let body = b"This is the article body.\r\n";
        (headers.to_vec(), body.to_vec())
    }

    fn build_test_article() -> BuiltArticle {
        let (headers, body) = make_article_bytes();
        build_article(
            &headers,
            &body,
            "<test@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("build_article must succeed for well-formed input")
    }

    #[test]
    fn test_root_cid_uses_dag_cbor_codec() {
        let built = build_test_article();
        assert_eq!(
            built.root_cid.codec(),
            CODEC_DAG_CBOR,
            "root CID must use DAG-CBOR codec (0x71)"
        );
    }

    #[test]
    fn test_determinism() {
        let (headers, body) = make_article_bytes();
        let built1 = build_article(
            &headers,
            &body,
            "<test@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("first build must succeed");
        let built2 = build_article(
            &headers,
            &body,
            "<test@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("second build must succeed");

        assert_eq!(
            built1.root_cid, built2.root_cid,
            "root CIDs must be identical"
        );

        let root_bytes1 = built1
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built1.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in first build");
        let root_bytes2 = built2
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built2.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in second build");
        assert_eq!(
            root_bytes1, root_bytes2,
            "root block bytes must be identical"
        );
    }

    #[test]
    fn test_blocks_contain_root_header_body() {
        let (headers, body) = make_article_bytes();
        let built = build_article(
            &headers,
            &body,
            "<test@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("build must succeed");

        let root_block = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .expect("blocks must contain root block");
        assert!(!root_block.1.is_empty(), "root block must not be empty");

        let header_cid = built.root_node.header_cid;
        let header_block_entry = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == header_cid)
            .expect("blocks must contain header block");
        assert_eq!(
            header_block_entry.1, headers,
            "header block bytes must equal original header bytes"
        );

        let body_cid = built.root_node.body_cid;
        let body_block_entry = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == body_cid)
            .expect("blocks must contain body block");
        assert_eq!(
            body_block_entry.1, body,
            "body block bytes must equal original body bytes"
        );
    }

    /// Verifies that the root block bytes produced by `build_article` can be
    /// decoded back to an `ArticleRootNode` without loss.
    ///
    /// Limitation: this is a roundtrip-only test — encode and decode both use
    /// `serde_ipld_dagcbor`, so a symmetric codec bug would pass undetected.
    /// The oracle-anchored equivalent is `tv1_root_block_decodes_correctly` in
    /// `test_vectors.rs`, which decodes bytes whose CID has been independently
    /// verified against Python `dag_cbor` 0.3.3.  This test is retained because
    /// it exercises a different article payload (different header fields and body
    /// content) and provides an additional sanity check for the full pipeline.
    #[test]
    fn test_root_block_round_trips() {
        let built = build_test_article();

        let root_block_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in blocks");

        let decoded: ArticleRootNode = serde_ipld_dagcbor::from_slice(root_block_bytes)
            .expect("root block must deserialize to ArticleRootNode");
        assert_eq!(
            decoded, built.root_node,
            "deserialized root node must equal original"
        );
    }

    #[test]
    fn test_no_content_type_produces_none_mime_cid() {
        let (headers, body) = make_article_bytes();
        let built = build_article(
            &headers,
            &body,
            "<test@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("build must succeed");

        assert!(
            built.root_node.mime_cid.is_none(),
            "article without Content-Type must produce None mime_cid"
        );
    }

    #[test]
    fn test_with_content_type_produces_some_mime_cid() {
        let headers = b"From: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <test2@example.com>\r\nNewsgroups: comp.lang.rust\r\nSubject: MIME article\r\nContent-Type: text/plain\r\nPath: news.example.com!user\r\n";
        let body = b"This is a MIME article body.\r\n";

        let built = build_article(
            headers,
            body,
            "<test2@example.com>".to_string(),
            vec!["comp.lang.rust".to_string()],
            1_700_000_000_000,
            vec![],
        )
        .expect("build must succeed");

        assert!(
            built.root_node.mime_cid.is_some(),
            "article with Content-Type must produce Some mime_cid"
        );
    }
}
