use crate::peering::mode_stream::PeeringMode;
use stoa_core::msgid_map::MsgIdMap;
use stoa_core::validation::validate_message_id;

/// Maximum article size for v1 text-only mode: 1 MiB.
pub const MAX_ARTICLE_BYTES: usize = 1_048_576;

/// Result of attempting to ingest an article.
#[derive(Debug, PartialEq)]
pub enum IngestResult {
    /// Article accepted and stored: respond 235 (IHAVE) or 239 (TAKETHIS).
    Accepted,
    /// Already known by Message-ID: respond 435 (IHAVE) or 438 (TAKETHIS).
    Duplicate,
    /// Article rejected (malformed/invalid): respond 437 (IHAVE) or 439 (TAKETHIS).
    Rejected(String),
    /// Transient failure: respond 436 (IHAVE) or 431 (TAKETHIS).
    TransientError(String),
}

/// Validate and process an incoming article from a peer.
///
/// Checks (in order):
/// 1. Message-ID format valid (angle brackets, single `@`, non-empty parts)
/// 2. Article size ≤ [`MAX_ARTICLE_BYTES`]  — cheap array-len check before any I/O
/// 3. Duplicate check via `msgid_map` — keyed on the body's `Message-ID` header,
///    NOT on the IHAVE/TAKETHIS envelope msgid.  A peer that sends
///    `IHAVE <envelope@example>` with `Message-ID: <body@example>` in the body
///    would bypass dedup if we keyed on the envelope.
/// 4. Mandatory headers present (`From`, `Date`, `Message-ID`, `Newsgroups`, `Subject`)
///
/// The `envelope_msgid` parameter is validated for format (step 1) so that
/// obviously malformed commands are rejected early, but the deduplication key
/// (step 3) always comes from the body.
///
/// Returns [`IngestResult`] without storing anything — the caller is
/// responsible for actually writing to IPFS and the group log.
pub async fn check_ingest(
    envelope_msgid: &str,
    article_bytes: &[u8],
    msgid_map: &MsgIdMap,
) -> IngestResult {
    // 1. Envelope Message-ID format — validate before reading the body so that
    // malformed commands are rejected early (before the duplicate DB round-trip).
    if let Err(e) = validate_message_id(envelope_msgid) {
        crate::metrics::ARTICLES_REJECTED_TOTAL
            .with_label_values(&["malformed"])
            .inc();
        return IngestResult::Rejected(format!("invalid envelope Message-ID format: {e}"));
    }

    // 2. Size limit — O(1) check before the DB round-trip below.
    // A peer sending oversized articles should be rejected immediately without
    // paying the cost of a duplicate lookup.
    if article_bytes.len() > MAX_ARTICLE_BYTES {
        crate::metrics::ARTICLES_REJECTED_TOTAL
            .with_label_values(&["size_exceeded"])
            .inc();
        return IngestResult::Rejected(format!(
            "article too large: {} bytes (limit {})",
            article_bytes.len(),
            MAX_ARTICLE_BYTES
        ));
    }

    // 3. Duplicate check keyed on the body's Message-ID header.
    //
    // Using the envelope msgid for dedup would allow a peer to bypass it:
    //   IHAVE <known-dup@example>  → rejected (435)
    //   IHAVE <fresh-envelope@example> (same body with Message-ID: <known-dup@example>)
    //   → envelope is unknown, so dedup passes; body msgid is stored as a new entry.
    //
    // By extracting the body msgid here we close that gap: the duplicate check
    // and the pipeline storage key are always the same value.
    // If the body has no Message-ID header the string is empty; step 4 below
    // will produce the Rejected response via has_header("Message-ID").
    let body_msgid = extract_body_msgid(article_bytes).unwrap_or_default();

    if !body_msgid.is_empty() {
        match msgid_map.lookup_by_msgid(&body_msgid).await {
            Err(e) => {
                return IngestResult::TransientError(format!(
                    "storage error during duplicate check: {e}"
                ));
            }
            Ok(Some(_)) => {
                crate::metrics::ARTICLES_REJECTED_TOTAL
                    .with_label_values(&["duplicate"])
                    .inc();
                return IngestResult::Duplicate;
            }
            Ok(None) => {}
        }
    }

    // 4. Mandatory headers.
    const MANDATORY: &[&str] = &["From", "Date", "Message-ID", "Newsgroups", "Subject"];
    for name in MANDATORY {
        if !has_header(article_bytes, name) {
            crate::metrics::ARTICLES_REJECTED_TOTAL
                .with_label_values(&["malformed"])
                .inc();
            return IngestResult::Rejected(format!("missing mandatory header: {name}"));
        }
    }

    IngestResult::Accepted
}

/// Extract the `Message-ID:` header value from raw article bytes.
///
/// Scans only the header section (before the first blank line).  Handles
/// RFC 5322 §2.2.3 header folding: if the field value starts on the next
/// line (or continues on subsequent lines that begin with SP or HTAB), those
/// continuation lines are concatenated into the returned string.
///
/// Non-UTF-8 header lines other than the target field are skipped (not an
/// error); non-UTF-8 on the `Message-ID` line itself returns `None`.
pub fn extract_body_msgid(article_bytes: &[u8]) -> Option<String> {
    let mut lines = article_bytes.split(|&b| b == b'\n');
    while let Some(line) = lines.next() {
        let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
        if trimmed.is_empty() {
            // Blank line: end of headers.
            break;
        }
        // Skip RFC 5322 continuation lines belonging to a preceding non-target header.
        if trimmed.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            continue;
        }
        let Ok(s) = std::str::from_utf8(trimmed) else {
            // Skip non-UTF-8 header lines; don't abort the scan.
            continue;
        };
        let prefix = "message-id:";
        if s.len() < prefix.len() || !s[..prefix.len()].eq_ignore_ascii_case(prefix) {
            continue;
        }
        // Collect the field value, including any folded continuation lines.
        let mut value = s[prefix.len()..].trim_ascii_start().to_owned();
        for cont in &mut lines {
            let ct = cont.strip_suffix(b"\r").unwrap_or(cont);
            if ct.is_empty() {
                break;
            }
            if ct.first().is_some_and(|&b| b == b' ' || b == b'\t') {
                // Non-UTF-8 continuation of the Message-ID field → malformed; bail out.
                let cs = std::str::from_utf8(ct).ok()?;
                value.push_str(cs.trim_ascii());
            } else {
                break;
            }
        }
        return Some(value.trim_ascii().to_owned());
    }
    None
}

/// Format the NNTP response line for an IHAVE result.
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 235  |
/// | Duplicate       | 435  |
/// | Rejected        | 437  |
/// | TransientError  | 436  |
pub fn ihave_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "235 Article transferred OK\r\n",
        IngestResult::Duplicate => "435 Duplicate\r\n",
        IngestResult::Rejected(_) => "437 Article rejected\r\n",
        IngestResult::TransientError(_) => "436 Transfer failed, try again later\r\n",
    }
}

/// Format the NNTP response line for a TAKETHIS result.
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 239  |
/// | Duplicate       | 438  |
/// | Rejected        | 439  |
/// | TransientError  | 431  |
pub fn takethis_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "239 Article transferred OK\r\n",
        IngestResult::Duplicate => "438 Already have it\r\n",
        IngestResult::Rejected(_) => "439 Article not wanted\r\n",
        IngestResult::TransientError(_) => "431 Try sending it again later\r\n",
    }
}

/// Format the NNTP response line for a CHECK result (RFC 4644).
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 238  |
/// | Duplicate       | 438  |
/// | Rejected        | 438  |
/// | TransientError  | 431  |
pub fn check_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "238 Send it\r\n",
        IngestResult::Duplicate => "438 Already have it\r\n",
        IngestResult::Rejected(_) => "438 Article not wanted\r\n",
        IngestResult::TransientError(_) => "431 Try sending it again later\r\n",
    }
}

/// Guard for the CHECK command: CHECK is only valid in streaming mode.
///
/// Returns `None` if `mode` is [`PeeringMode::Streaming`] (CHECK allowed),
/// or `Some(response)` with a 401 error line if the mode is
/// [`PeeringMode::Ihave`] (CHECK not permitted).
pub fn check_mode_guard(mode: PeeringMode) -> Option<&'static str> {
    match mode {
        PeeringMode::Streaming => None,
        PeeringMode::Ihave => Some("401 This command is only allowed in streaming mode\r\n"),
    }
}

/// Guard for the TAKETHIS command: TAKETHIS is only valid after MODE STREAM.
///
/// RFC 4644 §2.5: the server MUST NOT accept TAKETHIS unless MODE STREAM was
/// successfully negotiated.  Returns `None` if `mode` is
/// [`PeeringMode::Streaming`] (TAKETHIS allowed), or `Some(response)` with a
/// 500 error line if the mode is [`PeeringMode::Ihave`] (TAKETHIS not
/// permitted — 500 because the command is not available in this mode, not
/// merely disallowed by policy).
pub fn takethis_mode_guard(mode: PeeringMode) -> Option<&'static str> {
    match mode {
        PeeringMode::Streaming => None,
        PeeringMode::Ihave => Some("500 Command not available in current mode\r\n"),
    }
}

// ── Path: header mutation ─────────────────────────────────────────────────────

/// Prepend `<hostname>!` to the `Path:` header, creating the header if absent.
///
/// Son-of-RFC-1036 §3.3: every transit hop MUST prepend its FQDN to the
/// `Path:` header before storing or forwarding an article.
///
/// * If `Path:` is present: the new value is `<hostname>!<old-value>`.
/// * If `Path:` is absent: `Path: <hostname>\r\n` is inserted just before
///   the blank line that separates headers from body.
pub fn prepend_path_header(article_bytes: Vec<u8>, hostname: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(article_bytes.len() + hostname.len() + 10);
    let mut path_found = false;
    let mut in_body = false;

    // Use peekable iterator to avoid the Vec<&[u8]> heap allocation from
    // split().collect().  The trailing empty slice produced when the article
    // ends with '\n' is skipped by checking peek() before acting on an empty
    // slice at the end of the stream.
    let mut iter = article_bytes.split(|&b| b == b'\n').peekable();
    while let Some(line) = iter.next() {
        // Skip the trailing empty element that split() produces when the
        // article bytes end with '\n' — this is not a genuine blank line.
        if line.is_empty() && iter.peek().is_none() {
            break;
        }
        if in_body {
            out.extend_from_slice(line);
            out.push(b'\n');
            continue;
        }

        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };

        if trimmed.is_empty() {
            if !path_found {
                let new_path = format!("Path: {hostname}\r\n");
                out.extend_from_slice(new_path.as_bytes());
            }
            in_body = true;
            out.extend_from_slice(b"\r\n");
            continue;
        }

        if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case(b"path:") {
            let old_val = String::from_utf8_lossy(&trimmed["path:".len()..]);
            let old_val = old_val.trim();
            let new_line = format!("Path: {hostname}!{old_val}\r\n");
            out.extend_from_slice(new_line.as_bytes());
            path_found = true;
        } else {
            out.extend_from_slice(trimmed);
            out.extend_from_slice(b"\r\n");
        }
    }

    out
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` if the raw article bytes contain a header named `name`.
///
/// Scans the header section (up to the first blank line) for a line that
/// starts with `name:` (case-insensitive ASCII comparison).
fn has_header(article_bytes: &[u8], name: &str) -> bool {
    let name_bytes = name.as_bytes();

    for line in article_bytes.split(|&b| b == b'\n') {
        // Stop at the blank line separating headers from body.
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }
        if trimmed.len() > name_bytes.len()
            && trimmed[..name_bytes.len()].eq_ignore_ascii_case(name_bytes)
            && trimmed[name_bytes.len()] == b':'
        {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
        // Use a unique temp file per test to avoid shared-memory migration races.
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (MsgIdMap::new(pool), tmp)
    }

    fn valid_article(msgid: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Test\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn valid_article_accepted() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<valid@example.com>";
        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert_eq!(result, IngestResult::Accepted);
    }

    #[tokio::test]
    async fn duplicate_msgid_rejected() {
        use cid::Cid;
        use multihash_codetable::{Code, MultihashDigest};

        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<dup@example.com>";

        // Pre-insert a CID for this Message-ID to simulate a known article.
        let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"some-article"));
        map.insert(msgid, &cid).await.unwrap();

        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert_eq!(result, IngestResult::Duplicate);
    }

    #[tokio::test]
    async fn oversized_article_rejected() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<big@example.com>";
        let big: Vec<u8> = vec![b'x'; MAX_ARTICLE_BYTES + 1];
        let result = check_ingest(msgid, &big, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(_)),
            "expected Rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_msgid_format() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "no-angle-brackets@example.com";
        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(_)),
            "expected Rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn missing_from_header() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<nofrom@example.com>";
        let bytes = format!(
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Test\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes();
        let result = check_ingest(msgid, &bytes, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(ref msg) if msg.contains("From")),
            "expected Rejected with 'From', got {result:?}"
        );
    }

    #[test]
    fn ihave_response_codes() {
        assert!(ihave_response(&IngestResult::Accepted).starts_with("235"));
        assert!(ihave_response(&IngestResult::Duplicate).starts_with("435"));
        assert!(ihave_response(&IngestResult::Rejected("x".into())).starts_with("437"));
        assert!(ihave_response(&IngestResult::TransientError("x".into())).starts_with("436"));
    }

    #[test]
    fn takethis_response_codes() {
        assert!(takethis_response(&IngestResult::Accepted).starts_with("239"));
        assert!(takethis_response(&IngestResult::Duplicate).starts_with("438"));
        assert!(takethis_response(&IngestResult::Rejected("x".into())).starts_with("439"));
        assert!(takethis_response(&IngestResult::TransientError("x".into())).starts_with("431"));
    }

    #[test]
    fn check_response_codes() {
        assert!(check_response(&IngestResult::Accepted).starts_with("238"));
        assert!(check_response(&IngestResult::Duplicate).starts_with("438"));
        assert!(check_response(&IngestResult::Rejected("x".into())).starts_with("438"));
        assert!(check_response(&IngestResult::TransientError("x".into())).starts_with("431"));
    }

    #[test]
    fn check_mode_guard_streaming_allows() {
        assert!(check_mode_guard(PeeringMode::Streaming).is_none());
    }

    #[test]
    fn check_mode_guard_ihave_blocks() {
        let resp = check_mode_guard(PeeringMode::Ihave).expect("should return Some");
        assert!(resp.starts_with("401"));
    }

    #[test]
    fn takethis_mode_guard_streaming_allows() {
        assert!(takethis_mode_guard(PeeringMode::Streaming).is_none());
    }

    #[test]
    fn takethis_mode_guard_ihave_blocks_with_500() {
        let resp = takethis_mode_guard(PeeringMode::Ihave).expect("should return Some");
        assert!(
            resp.starts_with("500"),
            "RFC 4644 §2.5: TAKETHIS in IHAVE mode must return 500, got: {resp:?}"
        );
    }

    // ── prepend_path_header tests ─────────────────────────────────────────────

    #[test]
    fn path_header_existing_gets_prepended() {
        let article =
            b"From: sender@example.com\r\nPath: peer.example.com\r\nMessage-ID: <x@y>\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname!peer.example.com\r\n"),
            "Path: must be prepended: {text:?}"
        );
        assert!(
            !text.contains("Path: peer.example.com\r\n"),
            "old standalone Path: must not remain: {text:?}"
        );
    }

    #[test]
    fn path_header_absent_gets_inserted() {
        let article = b"From: sender@example.com\r\nMessage-ID: <x@y>\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname\r\n"),
            "Path: must be inserted: {text:?}"
        );
    }

    #[test]
    fn path_header_body_preserved() {
        let article =
            b"From: sender@example.com\r\nPath: peer.example.com\r\n\r\nHello, world!\r\nSecond line.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.ends_with("Hello, world!\r\nSecond line.\r\n"),
            "body must be unchanged: {text:?}"
        );
    }

    #[test]
    fn path_header_multi_hop_chain() {
        let article =
            b"From: sender@example.com\r\nPath: hop2.example.com!hop1.example.com\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname!hop2.example.com!hop1.example.com\r\n"),
            "multi-hop chain must be built correctly: {text:?}"
        );
    }

    #[test]
    fn path_header_blank_body_lines_preserved_lf_only() {
        // LF-only article (non-CRLF): blank lines within the body must not be dropped.
        let article = b"From: sender@example.com\nMessage-ID: <x@y>\n\nPara one.\n\nPara two.\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Para one.\nPara two.") || text.contains("Para one.\n\nPara two."),
            "blank line between paragraphs must be preserved: {text:?}"
        );
        // Specifically: the blank line separating the two paragraphs must be present.
        assert!(
            text.contains("Para one.\n\n"),
            "blank line after Para one must be preserved: {text:?}"
        );
    }

    /// Regression test for rbe3.33: duplicate check must use the body's
    /// Message-ID, not the envelope msgid.
    ///
    /// Before the fix, `check_ingest` keyed on `envelope_msgid`, so a peer could
    /// bypass dedup by presenting a fresh envelope msgid while reusing a known
    /// body Message-ID.
    #[tokio::test]
    async fn dedup_keyed_on_body_msgid_not_envelope() {
        use cid::Cid;
        use multihash_codetable::{Code, MultihashDigest};

        let (map, _tmp) = make_msgid_map().await;
        let body_msgid = "<body-dup@example.com>";

        // Pre-insert a CID for the body msgid to simulate a known article.
        let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"some-article"));
        map.insert(body_msgid, &cid).await.unwrap();

        // Article body contains the known Message-ID, but the envelope presents
        // a fresh (unknown) msgid — the attack vector for bypass.
        let fresh_envelope = "<fresh-envelope@example.com>";
        let bytes = valid_article(body_msgid); // body has Message-ID: <body-dup@example.com>

        // With the fix: dedup is keyed on the body msgid → must be Duplicate.
        let result = check_ingest(fresh_envelope, &bytes, &map).await;
        assert_eq!(
            result,
            IngestResult::Duplicate,
            "must deduplicate on body Message-ID, not on envelope: got {result:?}"
        );
    }

    #[test]
    fn path_header_blank_body_lines_preserved_crlf() {
        // CRLF article: blank lines within the body must not be dropped.
        let article =
            b"From: sender@example.com\r\nMessage-ID: <x@y>\r\n\r\nPara one.\r\n\r\nPara two.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Para one.\r\n\r\nPara two."),
            "blank line between paragraphs must be preserved in CRLF article: {text:?}"
        );
    }

    // ── extract_body_msgid folding tests ──────────────────────────────────────

    #[test]
    fn extract_body_msgid_handles_folded_value_on_continuation() {
        // RFC 5322 §2.2.3: field value entirely on a continuation line.
        // Note: the continuation line must begin with SP or HTAB — not stripped
        // by backslash-continuation so we use concat! to preserve the leading space.
        let article = concat!(
            "From: sender@example.com\r\n",
            "Message-ID:\r\n",
            " <folded@example.com>\r\n",
            "Subject: Test\r\n",
            "\r\n",
            "Body.\r\n"
        )
        .as_bytes();
        assert_eq!(
            extract_body_msgid(article),
            Some("<folded@example.com>".to_owned()),
            "folded Message-ID value must be extracted correctly"
        );
    }

    #[test]
    fn extract_body_msgid_skips_non_utf8_header_before_msgid() {
        // A non-UTF-8 header line before Message-ID must be skipped, not abort.
        let article: &[u8] =
            b"From: \xff\xfe sender\r\nMessage-ID: <ok@example.com>\r\n\r\nBody.\r\n";
        assert_eq!(
            extract_body_msgid(article),
            Some("<ok@example.com>".to_owned()),
            "non-UTF-8 header before Message-ID must not abort extraction"
        );
    }

    #[test]
    fn extract_body_msgid_returns_none_for_non_utf8_continuation() {
        // A non-UTF-8 byte sequence on a continuation line of the Message-ID
        // field is unrecoverable — the partial value cannot be trusted, so the
        // function must return None.
        let article: &[u8] = b"Message-ID:\r\n \xff\xfe<broken@example.com>\r\n\r\nBody.\r\n";
        assert_eq!(
            extract_body_msgid(article),
            None,
            "non-UTF-8 Message-ID continuation must return None"
        );
    }

    /// Regression test: a folded Message-ID header must be correctly deduped.
    ///
    /// Before the fix, `extract_body_msgid` returned `Some("")` for a folded
    /// `Message-ID:` (value on the next line), causing `body_msgid.is_empty()`
    /// to skip the duplicate check — a storage-amplification vector for
    /// authenticated peers.
    #[tokio::test]
    async fn folded_msgid_is_deduped_correctly() {
        use cid::Cid;
        use multihash_codetable::{Code, MultihashDigest};

        let (map, _tmp) = make_msgid_map().await;
        let body_msgid = "<folded-dup@example.com>";

        // Pre-insert a CID for this Message-ID.
        let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"folded-article"));
        map.insert(body_msgid, &cid).await.unwrap();

        // Article with the same Message-ID folded onto a continuation line.
        // Use String::from to preserve the leading space on the continuation.
        let bytes = {
            let mut s = String::new();
            s.push_str("From: sender@example.com\r\n");
            s.push_str("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n");
            s.push_str("Message-ID:\r\n");
            s.push(' ');
            s.push_str(body_msgid);
            s.push_str("\r\n");
            s.push_str("Newsgroups: alt.test\r\n");
            s.push_str("Subject: Test\r\n");
            s.push_str("\r\n");
            s.push_str("Body.\r\n");
            s.into_bytes()
        };

        let result = check_ingest(body_msgid, &bytes, &map).await;
        assert_eq!(
            result,
            IngestResult::Duplicate,
            "folded Message-ID must be deduped: got {result:?}"
        );
    }
}
