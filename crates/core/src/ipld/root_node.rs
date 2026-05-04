use cid::Cid;
use serde::{Deserialize, Serialize};

/// Deserialize a list of newsgroup name strings, rejecting any that fail
/// RFC 3977 group name validation.  Keeps the field type as `Vec<String>`
/// for CBOR schema stability (changing to `Vec<GroupName>` would alter the
/// on-wire encoding); validation is enforced at deserialization time instead.
// Serde calls this via `#[serde(deserialize_with = "...")]` generated code;
// the dead_code lint cannot see that reference.
#[allow(dead_code)]
fn deserialize_newsgroups<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings = Vec::<String>::deserialize(de)?;
    for s in &strings {
        crate::article::GroupName::new(s.clone())
            .map_err(|e| serde::de::Error::custom(format!("invalid newsgroup name {s:?}: {e}")))?;
    }
    Ok(strings)
}

/// Current schema version. Increment on breaking changes.
/// Consumers must reject root nodes with schema_version > their maximum known.
pub const SCHEMA_VERSION: u32 = 1;

/// The article root node stored as a DAG-CBOR block in IPFS.
///
/// Links to raw blocks for verbatim wire bytes and to IPLD sub-nodes for
/// parsed MIME content and derived metadata. All CIDs are CIDv1 SHA-256.
///
/// # Schema versioning
///
/// `schema_version` increments on breaking changes (removed fields, changed
/// semantics). Additive changes (new optional fields) do NOT increment the
/// version; consumers must ignore unknown fields during deserialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArticleRootNode {
    /// Schema version; currently 1.
    pub schema_version: u32,
    /// CID of the raw block containing verbatim RFC 5536 wire headers.
    pub header_cid: Cid,
    /// CID of the DAG-CBOR block containing the structured header map
    /// (`HeaderMapNode`). Enables `ipfs dag get <root>/header_map_cid/<name>`
    /// for per-header IPLD traversal. `None` only for legacy articles that
    /// predate this field.
    pub header_map_cid: Option<Cid>,
    /// CID of the raw block containing verbatim NNTP body bytes.
    pub body_cid: Cid,
    /// CID of the MIME parsed node, or None if MIME parsing was skipped.
    pub mime_cid: Option<Cid>,
    /// Derived metadata for preview and routing without fetching sub-blocks.
    pub metadata: ArticleMetadata,
}

/// Derived metadata embedded in the article root node.
///
/// Contains enough information for Corundum (and other consumers) to render
/// a preview and route the article without fetching sub-blocks. Fields must
/// be computable deterministically from the article wire bytes.
///
/// # Extensibility
///
/// New optional fields may be added without incrementing `schema_version`.
/// Consumers using standard serde deserialization will silently ignore unknown
/// fields: DAG-CBOR map keys not present in this struct are dropped on
/// deserialization. This is the correct default behaviour for forward
/// compatibility.
///
/// If unknown-field preservation is required in the future (e.g. for a
/// schema-migration tool that must not lose data), add:
/// ```ignore
/// #[serde(flatten)]
/// extra: std::collections::HashMap<String, ciborium::Value>,
/// ```
/// Do not add that field now — it changes the serialized shape and must be a
/// deliberate, versioned decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArticleMetadata {
    /// RFC 5536 Message-ID header value, including angle brackets.
    pub message_id: String,
    /// Destination newsgroups, in lexicographic order.
    /// Validated at deserialization: each entry must pass RFC 3977 group name
    /// rules (`[a-zA-Z][a-zA-Z0-9\-+_]*` components separated by dots).
    #[serde(deserialize_with = "deserialize_newsgroups")]
    pub newsgroups: Vec<String>,
    /// Hybrid Logical Clock timestamp (milliseconds since Unix epoch).
    pub hlc_timestamp: u64,
    /// Ed25519 signature by the operator key over the raw article bytes
    /// **before** the `X-Stoa-Sig` header is inserted (i.e. the same bytes
    /// that `sign_article` signs).  This is intentionally NOT a signature
    /// over the root CID — signing the CID would create a circular dependency
    /// because the CID is derived from content that includes this field.
    ///
    /// Set by the POST pipeline after calling `sign_article`.  Empty for
    /// transit-ingested articles (which are signed by their originating peer
    /// via `X-Stoa-Sig`, not re-signed by the local operator).
    /// Callers must not interpret an empty slice as a valid signature — treat
    /// empty as unsigned/unverified.
    pub operator_signature: Vec<u8>,
    /// Total byte count of the article (header + body wire bytes).
    pub byte_count: u64,
    /// Line count of the article body.
    pub line_count: u64,
    /// Summary of the MIME content type (e.g. "text/plain", "multipart/mixed").
    /// "text/plain" for non-MIME articles.
    pub content_type_summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    fn make_root_node() -> ArticleRootNode {
        ArticleRootNode {
            schema_version: SCHEMA_VERSION,
            header_cid: test_cid(b"header bytes"),
            header_map_cid: Some(test_cid(b"header map")),
            body_cid: test_cid(b"body bytes"),
            mime_cid: Some(test_cid(b"mime node")),
            metadata: ArticleMetadata {
                message_id: "<test-123@example.com>".into(),
                newsgroups: vec!["comp.lang.rust".into(), "comp.lang.c".into()],
                hlc_timestamp: 1_700_000_000_000,
                operator_signature: vec![0xde, 0xad, 0xbe, 0xef],
                byte_count: 512,
                line_count: 10,
                content_type_summary: "text/plain".into(),
            },
        }
    }

    #[test]
    fn root_node_dagcbor_serialization_is_deterministic() {
        let node = make_root_node();
        let bytes1 = serde_ipld_dagcbor::to_vec(&node).expect("first serialize");
        let bytes2 = serde_ipld_dagcbor::to_vec(&node).expect("second serialize");
        assert_eq!(bytes1, bytes2, "same value must produce identical bytes");
    }

    #[test]
    fn schema_version_constant_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    /// Round-trip a root node: serialize → deserialize with valid group names.
    /// The deserialization validator must accept RFC 3977-conforming names.
    #[test]
    fn newsgroups_valid_names_roundtrip() {
        let node = make_root_node(); // newsgroups: ["comp.lang.rust", "comp.lang.c"]
        let bytes = serde_ipld_dagcbor::to_vec(&node).expect("serialize");
        let decoded: ArticleRootNode = serde_ipld_dagcbor::from_slice(&bytes)
            .expect("valid newsgroup names must deserialize without error");
        assert_eq!(decoded.metadata.newsgroups, node.metadata.newsgroups);
    }

    /// Deserializing an `ArticleMetadata` that contains an invalid newsgroup
    /// name (one that would bypass `GroupName::new`) must fail with a serde
    /// error.  This verifies that the `deserialize_newsgroups` guard fires.
    #[test]
    fn newsgroups_invalid_name_rejected_at_deserialization() {
        // Build a node with an obviously invalid group name by constructing
        // the raw CBOR manually via serde_json (JSON → CBOR conversion is
        // not available, so we serialize a valid node and then patch the
        // bytes using serde_json → DAG-CBOR of a crafted struct).
        // Simpler: serialize a node using serde with the invalid name injected
        // via a helper that bypasses GroupName validation.
        use serde::Serialize;

        // Inline struct that mirrors ArticleMetadata but without the
        // `deserialize_with` guard, so we can serialize invalid names.
        #[derive(Serialize)]
        struct RawMetadata<'a> {
            message_id: &'a str,
            newsgroups: Vec<&'a str>,
            hlc_timestamp: u64,
            operator_signature: Vec<u8>,
            byte_count: u64,
            line_count: u64,
            content_type_summary: &'a str,
        }
        #[derive(Serialize)]
        struct RawRootNode<'a> {
            schema_version: u32,
            header_cid: Cid,
            header_map_cid: Option<Cid>,
            body_cid: Cid,
            mime_cid: Option<Cid>,
            metadata: RawMetadata<'a>,
        }

        let raw = RawRootNode {
            schema_version: 1,
            header_cid: test_cid(b"h"),
            header_map_cid: None,
            body_cid: test_cid(b"b"),
            mime_cid: None,
            metadata: RawMetadata {
                message_id: "<x@y.com>",
                newsgroups: vec!["not a valid group name!!"],
                hlc_timestamp: 0,
                operator_signature: vec![],
                byte_count: 0,
                line_count: 0,
                content_type_summary: "text/plain",
            },
        };
        let bytes = serde_ipld_dagcbor::to_vec(&raw).expect("raw serialize");
        let result: Result<ArticleRootNode, _> = serde_ipld_dagcbor::from_slice(&bytes);
        assert!(
            result.is_err(),
            "invalid newsgroup name must cause deserialization error"
        );
    }
}
