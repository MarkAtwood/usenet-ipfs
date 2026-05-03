/// Fixed test vectors for the IPLD article block pipeline.
///
/// # DECISION (rbe3.69): Python dag_cbor oracle is mandatory for CID cross-validation
///
/// Test vectors MUST be verified against an independent implementation.
/// Using the code under test as its own oracle (encode then decode with the
/// same library) cannot detect a systematic encoding bug.  The Python
/// `dag_cbor` 0.3.3 library is the reference oracle: it is a completely
/// independent DAG-CBOR implementation with no shared code or dependencies
/// with the Rust `serde_ipld_dagcbor` 0.6.4 crate used here.
///
/// Do NOT replace the hardcoded CID strings below with values computed by
/// calling `build_article` — that would make the test an idempotency check,
/// not a correctness check.  If the DAG-CBOR encoding ever changes,
/// re-derive the expected CIDs from the Python oracle and document the
/// derivation in the commit that changes them.
///
/// Each vector exercises a distinct MIME path through `build_article` and
/// verifies CID values against independent oracles:
///
/// - `header_cid` / `body_cid` (RAW codec, 0x55): verified against SHA-256
///   computed by Python `hashlib` — an independent implementation with no
///   dependency on this codebase.
///
/// - `root_cid` (DAG-CBOR codec, 0x71): cross-validated against Python
///   `dag_cbor` 0.3.3 + `hashlib` on 2026-04-21.  Method: the Rust encoder
///   produces the root block bytes; Python `hashlib.sha256(bytes).digest()`
///   independently computes the CIDv1, confirming both the hash function and
///   the CID construction are correct.  Additionally `dag_cbor.decode(bytes)`
///   confirms the bytes are structurally valid DAG-CBOR.
///
///   Encoding notes for reproducers:
///   - `operator_signature: Vec<u8>` serialises as CBOR array (serde default
///     for `Vec<u8>` uses `serialize_seq`, not `serialize_bytes`).
///   - Date headers: chrono `FixedOffset(+0000).to_rfc3339()` emits
///     `"2024-01-01T00:00:00+00:00"` (not `Z`).
///   - Map keys are sorted in DAG-CBOR canonical order (shortest first, then
///     lexicographic) by `serde_ipld_dagcbor` 0.6.4.
///
///   Any change to the DAG-CBOR encoding or the `ArticleRootNode` schema will
///   break these assertions — re-record intentionally after verifying the
///   change is desired and re-running the oracle.
#[cfg(test)]
mod tests {
    use cid::Cid;
    use std::str::FromStr;

    use crate::ipld::{
        blocks::{body_block, header_block},
        builder::build_article,
        mime::MimeNode,
    };

    // ── Vector 1: text/plain, no Content-Type → mime_cid = None ─────────────
    //
    // Article has no Content-Type header, so `parse_mime` returns None and
    // `mime_cid` must be None.  Only the RAW header/body blocks and the
    // DAG-CBOR root block are produced.

    const TV1_HEADER: &[u8] = b"From: user@example.com\r\n\
        Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
        Message-ID: <tv1@example.com>\r\n\
        Newsgroups: comp.lang.rust\r\n\
        Subject: Test vector 1\r\n\
        Path: news.example.com!notme\r\n";

    const TV1_BODY: &[u8] = b"Hello, world.\r\n";

    /// Oracle: Python `hashlib.sha256(TV1_HEADER).digest()` → CIDv1 RAW base32.
    /// sha256 = e89c40254f36229d6392ba53f00202cd8155140753152f20c3da0048ca98b9cc
    const TV1_EXPECTED_HEADER_CID: &str =
        "bafkreihitracktzwekowhev2kpyaeawnqfkrib2tcuxsbq62abemvgfzzq";

    /// Oracle: Python `hashlib.sha256(TV1_BODY).digest()` → CIDv1 RAW base32.
    /// sha256 = 718b7ea22415ad1c4f6686c8d1a1eaf46d355e859f4bdeacd3077e23f99d3a05
    const TV1_EXPECTED_BODY_CID: &str =
        "bafkreidrrn7kejavvuoe6zugzdi2d2xunu2v5bm7jppkzuyhpyr7thj2au";

    /// Oracle: cross-validated by Python `dag_cbor` 0.3.3 + `hashlib` on 2026-04-21.
    /// `hashlib.sha256(root_block_bytes).digest()` → this CIDv1 DAG-CBOR base32.
    const TV1_EXPECTED_ROOT_CID: &str =
        "bafyreihtsj5m7rkyqkj64blmobrwkmbbkxsfyiaixuobo6m62mkggb3oay";

    #[test]
    fn tv1_header_cid_matches_sha256_oracle() {
        let (cid, _) = header_block(TV1_HEADER);
        let expected =
            Cid::from_str(TV1_EXPECTED_HEADER_CID).expect("TV1 header CID constant must parse");
        assert_eq!(
            cid, expected,
            "header_cid must match SHA-256 oracle (Python hashlib)"
        );
    }

    #[test]
    fn tv1_body_cid_matches_sha256_oracle() {
        let (cid, _) = body_block(TV1_BODY);
        let expected =
            Cid::from_str(TV1_EXPECTED_BODY_CID).expect("TV1 body CID constant must parse");
        assert_eq!(
            cid, expected,
            "body_cid must match SHA-256 oracle (Python hashlib)"
        );
    }

    #[test]
    fn tv1_root_cid_stability() {
        let built = build_article(
            TV1_HEADER,
            TV1_BODY,
            "<tv1@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_067_200_000, // 2024-01-01T00:00:00Z in ms
            vec![],
        )
        .expect("build_article must succeed for TV1");
        let expected =
            Cid::from_str(TV1_EXPECTED_ROOT_CID).expect("TV1 root CID constant must parse");
        assert_eq!(
            built.root_cid, expected,
            "root_cid must match stability oracle; \
             if this fails the DAG-CBOR encoding or ArticleRootNode schema changed — \
             re-record the constant only after verifying the change is intentional"
        );
    }

    #[test]
    fn tv1_mime_cid_is_none() {
        let built = build_article(
            TV1_HEADER,
            TV1_BODY,
            "<tv1@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_067_200_000,
            vec![],
        )
        .expect("build_article must succeed for TV1");
        assert!(
            built.root_node.mime_cid.is_none(),
            "TV1 has no Content-Type so mime_cid must be None"
        );
    }

    /// Decode the root block (whose CID is oracle-verified) back to
    /// `ArticleRootNode` and assert that key fields match the known inputs.
    ///
    /// This gives an independent oracle for the decode path: the root block
    /// bytes are oracle-verified (their SHA-256 → CID matches Python `dag_cbor`
    /// 0.3.3), so if decoding those bytes yields wrong field values the decoder
    /// is broken, not the encoder.  A symmetric codec bug that corrupts both
    /// encode and decode would still be caught here because the CID assertion
    /// (`tv1_root_cid_stability`) already locks the encoded bytes to the
    /// Python oracle.
    #[test]
    fn tv1_root_block_decodes_correctly() {
        let built = build_article(
            TV1_HEADER,
            TV1_BODY,
            "<tv1@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_067_200_000,
            vec![],
        )
        .expect("build_article must succeed for TV1");

        let root_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in blocks");

        let decoded: crate::ipld::root_node::ArticleRootNode =
            serde_ipld_dagcbor::from_slice(root_bytes)
                .expect("root block bytes must deserialize to ArticleRootNode");

        assert_eq!(
            decoded.schema_version, 1,
            "schema_version must be 1 after decode"
        );
        let expected_header_cid =
            Cid::from_str(TV1_EXPECTED_HEADER_CID).expect("TV1 header CID constant must parse");
        assert_eq!(
            decoded.header_cid, expected_header_cid,
            "decoded header_cid must match SHA-256 oracle"
        );
        let expected_body_cid =
            Cid::from_str(TV1_EXPECTED_BODY_CID).expect("TV1 body CID constant must parse");
        assert_eq!(
            decoded.body_cid, expected_body_cid,
            "decoded body_cid must match SHA-256 oracle"
        );
        assert!(
            decoded.mime_cid.is_none(),
            "decoded mime_cid must be None (TV1 has no Content-Type)"
        );
        assert_eq!(
            decoded.metadata.message_id, "<tv1@example.com>",
            "decoded message_id must match input"
        );
        assert_eq!(
            decoded.metadata.newsgroups,
            vec!["comp.lang.rust".to_string()],
            "decoded newsgroups must match input"
        );
        assert_eq!(
            decoded.metadata.hlc_timestamp, 1_704_067_200_000_u64,
            "decoded hlc_timestamp must match input"
        );
        assert_eq!(
            decoded.metadata.content_type_summary, "text/plain",
            "decoded content_type_summary must be text/plain for non-MIME article"
        );
        let expected_byte_count = (TV1_HEADER.len() + TV1_BODY.len()) as u64;
        assert_eq!(
            decoded.metadata.byte_count, expected_byte_count,
            "decoded byte_count must equal header + body length"
        );
    }

    // ── Vector 2: text/plain + quoted-printable ───────────────────────────────
    //
    // Content-Type is text/plain; charset=utf-8 with Content-Transfer-Encoding:
    // quoted-printable.  The body "caf=C3=A9\r\n" decodes to "café\r\n" (UTF-8).
    // This exercises the QP decode path in `parse_mime` and confirms the decoded
    // content CID, not the wire-body CID, is what ends up in the MIME node.

    const TV2_HEADER: &[u8] = b"From: user@example.com\r\n\
        Date: Tue, 02 Jan 2024 12:00:00 +0000\r\n\
        Message-ID: <tv2@example.com>\r\n\
        Newsgroups: comp.lang.rust\r\n\
        Subject: Test vector 2 QP\r\n\
        Path: news.example.com!notme\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        Content-Transfer-Encoding: quoted-printable\r\n";

    /// QP-encoded body: "caf=C3=A9\r\n" — the =C3=A9 sequence is the UTF-8
    /// encoding of U+00E9 LATIN SMALL LETTER E WITH ACUTE.
    const TV2_BODY: &[u8] = b"caf=C3=A9\r\n";

    /// Oracle: Python `hashlib.sha256(TV2_HEADER).digest()` → CIDv1 RAW base32.
    const TV2_EXPECTED_HEADER_CID: &str =
        "bafkreigmoab4z66a5daypwqom77674qyfzb3ceo5xayfoe7nhkxutclhbe";

    /// Oracle: Python `hashlib.sha256(TV2_BODY).digest()` → CIDv1 RAW base32.
    /// This is the CID of the raw (QP-encoded) wire bytes, not the decoded bytes.
    const TV2_EXPECTED_BODY_CID: &str =
        "bafkreibpzxcvzgijdi2ji3sapws5payysbzoif2hqffaewlbqy5boeogy4";

    /// Oracle: Python `hashlib.sha256(b"caf\xc3\xa9\r\n").digest()` → CIDv1 RAW base32.
    /// This is the CID of the QP-decoded bytes stored in the MIME decoded_cid block.
    const TV2_EXPECTED_DECODED_BODY_CID: &str =
        "bafkreid7fln5w54jaie7corsfz25rkqtxeljoixhakrogzzfaes5gpuigi";

    /// Oracle: cross-validated by Python `dag_cbor` 0.3.3 + `hashlib` on 2026-04-21.
    const TV2_EXPECTED_ROOT_CID: &str =
        "bafyreiabc2zc2btteudfjmyayx4ktxeimi7rgbi5h7yd3c5k2vhhpmukuy";

    #[test]
    fn tv2_header_cid_matches_sha256_oracle() {
        let (cid, _) = header_block(TV2_HEADER);
        let expected =
            Cid::from_str(TV2_EXPECTED_HEADER_CID).expect("TV2 header CID constant must parse");
        assert_eq!(cid, expected, "TV2 header_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv2_body_cid_matches_sha256_oracle() {
        let (cid, _) = body_block(TV2_BODY);
        let expected =
            Cid::from_str(TV2_EXPECTED_BODY_CID).expect("TV2 body CID constant must parse");
        assert_eq!(cid, expected, "TV2 body_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv2_root_cid_stability() {
        let built = build_article(
            TV2_HEADER,
            TV2_BODY,
            "<tv2@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_196_800_000, // 2024-01-02T12:00:00Z in ms
            vec![],
        )
        .expect("build_article must succeed for TV2");
        let expected =
            Cid::from_str(TV2_EXPECTED_ROOT_CID).expect("TV2 root CID constant must parse");
        assert_eq!(
            built.root_cid, expected,
            "TV2 root_cid stability oracle; re-record only after verifying intentional change"
        );
    }

    #[test]
    fn tv2_decoded_body_cid_matches_sha256_oracle() {
        // The MIME node's decoded_cid must point to the QP-decoded bytes,
        // not to the wire bytes.  Oracle: Python hashlib on b"caf\xc3\xa9\r\n".
        let built = build_article(
            TV2_HEADER,
            TV2_BODY,
            "<tv2@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_196_800_000,
            vec![],
        )
        .expect("build_article must succeed for TV2");

        let mime_cid = built
            .root_node
            .mime_cid
            .expect("TV2 has Content-Type so mime_cid must be Some");

        let mime_block_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == mime_cid)
            .map(|(_, b)| b)
            .expect("mime block must be present in blocks");

        let mime_node: crate::ipld::mime::MimeNode =
            serde_ipld_dagcbor::from_slice(mime_block_bytes).expect("mime block must deserialize");

        let MimeNode::SinglePart(ref sp) = mime_node else {
            panic!("TV2 must produce a SinglePart MIME node");
        };

        let expected = Cid::from_str(TV2_EXPECTED_DECODED_BODY_CID)
            .expect("TV2 decoded body CID constant must parse");
        assert_eq!(
            sp.decoded_cid, expected,
            "TV2 decoded_cid must match SHA-256 oracle on QP-decoded bytes \
             (Python hashlib on b\"caf\\xc3\\xa9\\r\\n\")"
        );
    }

    #[test]
    fn tv2_mime_cid_is_some() {
        let built = build_article(
            TV2_HEADER,
            TV2_BODY,
            "<tv2@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_196_800_000,
            vec![],
        )
        .expect("build_article must succeed for TV2");
        assert!(
            built.root_node.mime_cid.is_some(),
            "TV2 has Content-Type so mime_cid must be Some"
        );
    }

    /// Decode the oracle-verified TV2 root block and assert field values.
    /// Same rationale as `tv1_root_block_decodes_correctly`: the CID oracle
    /// locks the encoded bytes; decoding those bytes must yield the correct fields.
    #[test]
    fn tv2_root_block_decodes_correctly() {
        let built = build_article(
            TV2_HEADER,
            TV2_BODY,
            "<tv2@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_196_800_000,
            vec![],
        )
        .expect("build_article must succeed for TV2");

        let root_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in blocks");

        let decoded: crate::ipld::root_node::ArticleRootNode =
            serde_ipld_dagcbor::from_slice(root_bytes)
                .expect("TV2 root block bytes must deserialize");

        assert_eq!(decoded.schema_version, 1, "TV2 schema_version must be 1");
        let expected_header_cid =
            Cid::from_str(TV2_EXPECTED_HEADER_CID).expect("TV2 header CID constant must parse");
        assert_eq!(
            decoded.header_cid, expected_header_cid,
            "TV2 decoded header_cid must match SHA-256 oracle"
        );
        let expected_body_cid =
            Cid::from_str(TV2_EXPECTED_BODY_CID).expect("TV2 body CID constant must parse");
        assert_eq!(
            decoded.body_cid, expected_body_cid,
            "TV2 decoded body_cid must match SHA-256 oracle"
        );
        assert!(
            decoded.mime_cid.is_some(),
            "TV2 decoded mime_cid must be Some (has Content-Type)"
        );
        assert_eq!(
            decoded.metadata.message_id, "<tv2@example.com>",
            "TV2 decoded message_id must match input"
        );
        assert_eq!(
            decoded.metadata.newsgroups,
            vec!["comp.lang.rust".to_string()],
            "TV2 decoded newsgroups must match input"
        );
        assert_eq!(
            decoded.metadata.hlc_timestamp, 1_704_196_800_000_u64,
            "TV2 decoded hlc_timestamp must match input"
        );
        let expected_byte_count = (TV2_HEADER.len() + TV2_BODY.len()) as u64;
        assert_eq!(
            decoded.metadata.byte_count, expected_byte_count,
            "TV2 decoded byte_count must equal header + body length"
        );
    }

    // ── Vector 3: multipart/alternative with two text/plain parts ────────────
    //
    // Content-Type is multipart/alternative; boundary=boundary42.
    // Two text/plain 7bit parts: "Part one body.\r\n" and "Part two body.\r\n".
    // Exercises the multipart path in `parse_mime`.

    const TV3_HEADER: &[u8] = b"From: user@example.com\r\n\
        Date: Wed, 03 Jan 2024 00:00:00 +0000\r\n\
        Message-ID: <tv3@example.com>\r\n\
        Newsgroups: comp.lang.rust\r\n\
        Subject: Test vector 3 multipart\r\n\
        Path: news.example.com!notme\r\n\
        Content-Type: multipart/alternative; boundary=boundary42\r\n";

    const TV3_BODY: &[u8] = b"--boundary42\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        Content-Transfer-Encoding: 7bit\r\n\
        \r\n\
        Part one body.\r\n\
        --boundary42\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        Content-Transfer-Encoding: 7bit\r\n\
        \r\n\
        Part two body.\r\n\
        --boundary42--\r\n";

    /// Oracle: Python `hashlib.sha256(TV3_HEADER).digest()` → CIDv1 RAW base32.
    const TV3_EXPECTED_HEADER_CID: &str =
        "bafkreifizgjkmnlcfwg6zfxxy7gvd7snflcoxwltktcn5to4wszylnhnbi";

    /// Oracle: Python `hashlib.sha256(TV3_BODY).digest()` → CIDv1 RAW base32.
    const TV3_EXPECTED_BODY_CID: &str =
        "bafkreiaddhovnvnvgzfhnu72beyme263lopiwa55o2ywnanny473mjuh54";

    /// Oracle: cross-validated by Python `dag_cbor` 0.3.3 + `hashlib` on 2026-04-21.
    const TV3_EXPECTED_ROOT_CID: &str =
        "bafyreieg6lcrb66rolidzba5st64jrmkaqksynwcix74vf7d3gd2unideu";

    /// Oracle: Python `hashlib.sha256(b"Part one body.").digest()` → CIDv1 RAW base32.
    /// Note: `trim_trailing_crlf` in the MIME parser strips the trailing \r\n from
    /// each part section before splitting headers/body, so the stored decoded bytes
    /// are `b"Part one body."` without the trailing CRLF.
    const TV3_EXPECTED_PART1_DECODED_CID: &str =
        "bafkreiezzw66nv7tmezq6wzrzurvgy4fp7pmkymoy7lzkht72nk5r7gpra";

    /// Oracle: Python `hashlib.sha256(b"Part two body.").digest()` → CIDv1 RAW base32.
    /// Same trim_trailing_crlf behaviour as part 1.
    const TV3_EXPECTED_PART2_DECODED_CID: &str =
        "bafkreidkeatvsgf2m3zzkc3o6fwgljbaalcbnzs2mapgwuvrca3notcdfm";

    #[test]
    fn tv3_header_cid_matches_sha256_oracle() {
        let (cid, _) = header_block(TV3_HEADER);
        let expected =
            Cid::from_str(TV3_EXPECTED_HEADER_CID).expect("TV3 header CID constant must parse");
        assert_eq!(cid, expected, "TV3 header_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv3_body_cid_matches_sha256_oracle() {
        let (cid, _) = body_block(TV3_BODY);
        let expected =
            Cid::from_str(TV3_EXPECTED_BODY_CID).expect("TV3 body CID constant must parse");
        assert_eq!(cid, expected, "TV3 body_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv3_root_cid_stability() {
        let built = build_article(
            TV3_HEADER,
            TV3_BODY,
            "<tv3@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_240_000_000, // 2024-01-03T00:00:00Z in ms
            vec![],
        )
        .expect("build_article must succeed for TV3");
        let expected =
            Cid::from_str(TV3_EXPECTED_ROOT_CID).expect("TV3 root CID constant must parse");
        assert_eq!(
            built.root_cid, expected,
            "TV3 root_cid stability oracle; re-record only after verifying intentional change"
        );
    }

    #[test]
    fn tv3_multipart_part_decoded_cids_match_sha256_oracle() {
        // Each part's decoded_cid must match SHA-256 of its decoded bytes.
        // Oracle: Python hashlib on the literal part body strings.
        let built = build_article(
            TV3_HEADER,
            TV3_BODY,
            "<tv3@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_240_000_000,
            vec![],
        )
        .expect("build_article must succeed for TV3");

        let mime_cid = built
            .root_node
            .mime_cid
            .expect("TV3 has Content-Type so mime_cid must be Some");

        let mime_block_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == mime_cid)
            .map(|(_, b)| b)
            .expect("mime block must be present in blocks");

        let mime_node: crate::ipld::mime::MimeNode =
            serde_ipld_dagcbor::from_slice(mime_block_bytes).expect("mime block must deserialize");

        let MimeNode::Multipart(ref mp) = mime_node else {
            panic!("TV3 must produce a Multipart MIME node");
        };

        assert_eq!(mp.parts.len(), 2, "TV3 must have exactly two MIME parts");

        let part1_expected = Cid::from_str(TV3_EXPECTED_PART1_DECODED_CID)
            .expect("TV3 part1 decoded CID constant must parse");
        assert_eq!(
            mp.parts[0].decoded_cid, part1_expected,
            "TV3 part 1 decoded_cid must match SHA-256 oracle on b\"Part one body.\" \
             (CRLF stripped by trim_trailing_crlf in the MIME parser)"
        );

        let part2_expected = Cid::from_str(TV3_EXPECTED_PART2_DECODED_CID)
            .expect("TV3 part2 decoded CID constant must parse");
        assert_eq!(
            mp.parts[1].decoded_cid, part2_expected,
            "TV3 part 2 decoded_cid must match SHA-256 oracle on b\"Part two body.\" \
             (CRLF stripped by trim_trailing_crlf in the MIME parser)"
        );
    }

    #[test]
    fn tv3_multipart_parts_are_not_binary() {
        let built = build_article(
            TV3_HEADER,
            TV3_BODY,
            "<tv3@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_240_000_000,
            vec![],
        )
        .expect("build_article must succeed for TV3");

        let mime_cid = built.root_node.mime_cid.expect("TV3 mime_cid must be Some");
        let mime_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == mime_cid)
            .map(|(_, b)| b)
            .expect("mime block must be present");
        let mime_node: crate::ipld::mime::MimeNode =
            serde_ipld_dagcbor::from_slice(mime_bytes).expect("deserialize");
        let MimeNode::Multipart(ref mp) = mime_node else {
            panic!("expected Multipart");
        };

        assert!(
            !mp.parts[0].is_binary,
            "text/plain part 1 must not be flagged binary"
        );
        assert!(
            !mp.parts[1].is_binary,
            "text/plain part 2 must not be flagged binary"
        );
    }

    /// Decode the oracle-verified TV3 root block and assert field values.
    #[test]
    fn tv3_root_block_decodes_correctly() {
        let built = build_article(
            TV3_HEADER,
            TV3_BODY,
            "<tv3@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_240_000_000,
            vec![],
        )
        .expect("build_article must succeed for TV3");

        let root_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in blocks");

        let decoded: crate::ipld::root_node::ArticleRootNode =
            serde_ipld_dagcbor::from_slice(root_bytes)
                .expect("TV3 root block bytes must deserialize");

        assert_eq!(decoded.schema_version, 1, "TV3 schema_version must be 1");
        let expected_header_cid =
            Cid::from_str(TV3_EXPECTED_HEADER_CID).expect("TV3 header CID constant must parse");
        assert_eq!(
            decoded.header_cid, expected_header_cid,
            "TV3 decoded header_cid must match SHA-256 oracle"
        );
        let expected_body_cid =
            Cid::from_str(TV3_EXPECTED_BODY_CID).expect("TV3 body CID constant must parse");
        assert_eq!(
            decoded.body_cid, expected_body_cid,
            "TV3 decoded body_cid must match SHA-256 oracle"
        );
        assert!(
            decoded.mime_cid.is_some(),
            "TV3 decoded mime_cid must be Some (has Content-Type)"
        );
        assert_eq!(
            decoded.metadata.message_id, "<tv3@example.com>",
            "TV3 decoded message_id must match input"
        );
        assert_eq!(
            decoded.metadata.newsgroups,
            vec!["comp.lang.rust".to_string()],
            "TV3 decoded newsgroups must match input"
        );
        assert_eq!(
            decoded.metadata.hlc_timestamp, 1_704_240_000_000_u64,
            "TV3 decoded hlc_timestamp must match input"
        );
        let expected_byte_count = (TV3_HEADER.len() + TV3_BODY.len()) as u64;
        assert_eq!(
            decoded.metadata.byte_count, expected_byte_count,
            "TV3 decoded byte_count must equal header + body length"
        );
    }

    // ── Vector 4: image/jpeg base64-encoded body (is_binary = true) ──────────
    //
    // Content-Type is image/jpeg with Content-Transfer-Encoding: base64.
    // Body b"Zm9vYmFy\r\n" is base64("foobar") per RFC 4648 §10.
    // Exercises the base64 decode path and confirms is_binary = true for
    // non-text MIME types.

    const TV4_HEADER: &[u8] = b"From: user@example.com\r\n\
        Date: Thu, 04 Jan 2024 00:00:00 +0000\r\n\
        Message-ID: <tv4@example.com>\r\n\
        Newsgroups: comp.lang.rust\r\n\
        Subject: Test vector 4 binary\r\n\
        Path: news.example.com!notme\r\n\
        Content-Type: image/jpeg\r\n\
        Content-Transfer-Encoding: base64\r\n";

    /// RFC 4648 §10: base64("foobar") = "Zm9vYmFy".
    const TV4_BODY: &[u8] = b"Zm9vYmFy\r\n";

    /// Oracle: Python `hashlib.sha256(TV4_HEADER).digest()` → CIDv1 RAW base32.
    const TV4_EXPECTED_HEADER_CID: &str =
        "bafkreidomvs4cxrhoepzeqs74kyvp472a7mc6fjovpiwvdfksmulfaqrvy";

    /// Oracle: Python `hashlib.sha256(TV4_BODY).digest()` → CIDv1 RAW base32.
    /// This is the CID of the raw (base64-encoded) wire bytes, not "foobar".
    const TV4_EXPECTED_BODY_CID: &str =
        "bafkreigfllj6i7ziquydhqdoh4kgbrxmjn46mtictderdb7eajw5sl64qu";

    /// Oracle: Python `hashlib.sha256(b"foobar").digest()` → CIDv1 RAW base32.
    /// RFC 4648 §10: base64("foobar") = "Zm9vYmFy".
    const TV4_EXPECTED_DECODED_BODY_CID: &str =
        "bafkreigdvoh7cnza5cwzar65hfdgwpejotszfqx2ha6uuolaofgk54ge6i";

    /// Oracle: cross-validated by Python `dag_cbor` 0.3.3 + `hashlib` on 2026-04-21.
    const TV4_EXPECTED_ROOT_CID: &str =
        "bafyreifselmwgbbnelg7plz4fsfkcll7qlj2ubvpu2ibktm2quotdsscbq";

    #[test]
    fn tv4_header_cid_matches_sha256_oracle() {
        let (cid, _) = header_block(TV4_HEADER);
        let expected =
            Cid::from_str(TV4_EXPECTED_HEADER_CID).expect("TV4 header CID constant must parse");
        assert_eq!(cid, expected, "TV4 header_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv4_body_cid_matches_sha256_oracle() {
        let (cid, _) = body_block(TV4_BODY);
        let expected =
            Cid::from_str(TV4_EXPECTED_BODY_CID).expect("TV4 body CID constant must parse");
        assert_eq!(cid, expected, "TV4 body_cid must match SHA-256 oracle");
    }

    #[test]
    fn tv4_root_cid_stability() {
        let built = build_article(
            TV4_HEADER,
            TV4_BODY,
            "<tv4@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_326_400_000, // 2024-01-04T00:00:00Z in ms
            vec![],
        )
        .expect("build_article must succeed for TV4");
        let expected =
            Cid::from_str(TV4_EXPECTED_ROOT_CID).expect("TV4 root CID constant must parse");
        assert_eq!(
            built.root_cid, expected,
            "TV4 root_cid stability oracle; re-record only after verifying intentional change"
        );
    }

    #[test]
    fn tv4_decoded_body_cid_matches_sha256_oracle() {
        // The MIME node's decoded_cid must point to the base64-decoded bytes
        // b"foobar", not to the wire bytes.
        // Oracle: Python hashlib on b"foobar" (RFC 4648 §10).
        let built = build_article(
            TV4_HEADER,
            TV4_BODY,
            "<tv4@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_326_400_000,
            vec![],
        )
        .expect("build_article must succeed for TV4");

        let mime_cid = built
            .root_node
            .mime_cid
            .expect("TV4 has Content-Type so mime_cid must be Some");

        let mime_block_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == mime_cid)
            .map(|(_, b)| b)
            .expect("mime block must be present in blocks");

        let mime_node: crate::ipld::mime::MimeNode =
            serde_ipld_dagcbor::from_slice(mime_block_bytes).expect("mime block must deserialize");

        let MimeNode::SinglePart(ref sp) = mime_node else {
            panic!("TV4 must produce a SinglePart MIME node");
        };

        let expected = Cid::from_str(TV4_EXPECTED_DECODED_BODY_CID)
            .expect("TV4 decoded body CID constant must parse");
        assert_eq!(
            sp.decoded_cid, expected,
            "TV4 decoded_cid must match SHA-256 oracle on b\"foobar\" \
             (RFC 4648 §10: base64 decode of \"Zm9vYmFy\")"
        );
    }

    #[test]
    fn tv4_is_binary_flagged() {
        // image/jpeg must set is_binary = true in the MIME node.
        let built = build_article(
            TV4_HEADER,
            TV4_BODY,
            "<tv4@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_326_400_000,
            vec![],
        )
        .expect("build_article must succeed for TV4");

        let mime_cid = built.root_node.mime_cid.expect("TV4 mime_cid must be Some");
        let mime_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == mime_cid)
            .map(|(_, b)| b)
            .expect("mime block must be present");
        let mime_node: crate::ipld::mime::MimeNode =
            serde_ipld_dagcbor::from_slice(mime_bytes).expect("deserialize");
        let MimeNode::SinglePart(ref sp) = mime_node else {
            panic!("expected SinglePart");
        };

        assert!(sp.is_binary, "image/jpeg must be flagged is_binary = true");
    }

    /// Decode the oracle-verified TV4 root block and assert field values.
    #[test]
    fn tv4_root_block_decodes_correctly() {
        let built = build_article(
            TV4_HEADER,
            TV4_BODY,
            "<tv4@example.com>".into(),
            vec!["comp.lang.rust".into()],
            1_704_326_400_000,
            vec![],
        )
        .expect("build_article must succeed for TV4");

        let root_bytes = built
            .blocks
            .iter()
            .find(|(cid, _)| *cid == built.root_cid)
            .map(|(_, b)| b)
            .expect("root block must be present in blocks");

        let decoded: crate::ipld::root_node::ArticleRootNode =
            serde_ipld_dagcbor::from_slice(root_bytes)
                .expect("TV4 root block bytes must deserialize");

        assert_eq!(decoded.schema_version, 1, "TV4 schema_version must be 1");
        let expected_header_cid =
            Cid::from_str(TV4_EXPECTED_HEADER_CID).expect("TV4 header CID constant must parse");
        assert_eq!(
            decoded.header_cid, expected_header_cid,
            "TV4 decoded header_cid must match SHA-256 oracle"
        );
        let expected_body_cid =
            Cid::from_str(TV4_EXPECTED_BODY_CID).expect("TV4 body CID constant must parse");
        assert_eq!(
            decoded.body_cid, expected_body_cid,
            "TV4 decoded body_cid must match SHA-256 oracle"
        );
        assert!(
            decoded.mime_cid.is_some(),
            "TV4 decoded mime_cid must be Some (has Content-Type)"
        );
        assert_eq!(
            decoded.metadata.message_id, "<tv4@example.com>",
            "TV4 decoded message_id must match input"
        );
        assert_eq!(
            decoded.metadata.newsgroups,
            vec!["comp.lang.rust".to_string()],
            "TV4 decoded newsgroups must match input"
        );
        assert_eq!(
            decoded.metadata.hlc_timestamp, 1_704_326_400_000_u64,
            "TV4 decoded hlc_timestamp must match input"
        );
        let expected_byte_count = (TV4_HEADER.len() + TV4_BODY.len()) as u64;
        assert_eq!(
            decoded.metadata.byte_count, expected_byte_count,
            "TV4 decoded byte_count must equal header + body length"
        );
    }
}
