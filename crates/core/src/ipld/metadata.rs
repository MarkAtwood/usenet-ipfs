/// Return the number of bytes in `body_bytes`.
///
/// Used by [`compute_metadata`] to build the `:bytes` field in OVER/XOVER
/// output.  Per RFC 3977 §8.5.2, `:bytes` counts the total article size
/// (header + body); `compute_metadata` adds the header byte count separately
/// before storing the result.
pub fn compute_byte_count(body_bytes: &[u8]) -> u64 {
    u64::try_from(body_bytes.len()).expect("usize fits in u64 on all supported platforms")
}

/// Compute line_count for OVER/XOVER output from verbatim body bytes.
///
/// Per RFC 3977 §8.5.2, the `:lines` field counts the number of lines
/// in the article body. A line ends with \n (LF). Matches what NNTP
/// servers report in OVER/XOVER output.
pub fn compute_line_count(body_bytes: &[u8]) -> u64 {
    u64::try_from(body_bytes.iter().filter(|&&b| b == b'\n').count())
        .expect("usize fits in u64 on all supported platforms")
}

/// Extract content_type_summary from raw article header bytes.
///
/// Returns the type/subtype portion of the Content-Type header value
/// without parameters (e.g. "text/plain" from "text/plain; charset=utf-8").
/// Returns "text/plain" if no Content-Type header is present (RFC 2045
/// §5.2: default content type is text/plain; charset=us-ascii).
///
/// Uses `mailparse` for header unfolding and RFC 2047 decoding, the same
/// library used throughout the IPLD stack, to avoid a divergent bug surface.
pub fn extract_content_type_summary(header_bytes: &[u8]) -> String {
    let (headers, _) = match mailparse::parse_headers(header_bytes) {
        Ok(r) => r,
        Err(_) => return "text/plain".to_string(),
    };
    for header in &headers {
        if header.get_key().eq_ignore_ascii_case("content-type") {
            let ct = mailparse::parse_content_type(&header.get_value());
            return ct.mimetype;
        }
    }
    "text/plain".to_string()
}

/// Compute the fields of ArticleMetadata that are derived from article bytes.
///
/// The caller must provide:
/// - `header_bytes`: verbatim RFC 5536 wire headers
/// - `body_bytes`: verbatim NNTP body bytes (after dot-unstuffing)
/// - `message_id`: the Message-ID header value (already parsed)
/// - `newsgroups`: the Newsgroups list (already parsed, sorted)
/// - `hlc_timestamp`: the HLC timestamp for this entry (caller-provided)
/// - `operator_signature`: raw 64-byte Ed25519 signature over the pre-sign
///   article bytes (from `sign_article`), or an empty `Vec` for unsigned articles.
pub fn compute_metadata(
    header_bytes: &[u8],
    body_bytes: &[u8],
    message_id: String,
    newsgroups: Vec<String>,
    hlc_timestamp: u64,
    operator_signature: Vec<u8>,
) -> crate::ipld::root_node::ArticleMetadata {
    crate::ipld::root_node::ArticleMetadata {
        message_id,
        newsgroups,
        hlc_timestamp,
        operator_signature,
        byte_count: u64::try_from(header_bytes.len())
            .expect("usize fits in u64 on all supported platforms")
            + compute_byte_count(body_bytes),
        line_count: compute_line_count(body_bytes),
        content_type_summary: extract_content_type_summary(header_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_count_empty_body() {
        assert_eq!(compute_byte_count(b""), 0);
    }

    #[test]
    fn byte_count_known_bytes() {
        assert_eq!(compute_byte_count(b"Hello\r\n"), 7);
    }

    #[test]
    fn line_count_empty_body() {
        assert_eq!(compute_line_count(b""), 0);
    }

    #[test]
    fn line_count_single_line() {
        assert_eq!(compute_line_count(b"Hello\r\n"), 1);
    }

    #[test]
    fn line_count_multi_line() {
        assert_eq!(compute_line_count(b"line1\r\nline2\r\nline3\r\n"), 3);
    }

    #[test]
    fn line_count_no_trailing_newline() {
        assert_eq!(compute_line_count(b"noeol"), 0);
    }

    #[test]
    fn content_type_plain_text() {
        let headers = b"From: user@example.com\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_with_params() {
        let headers = b"From: user@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_multipart() {
        let headers =
            b"From: user@example.com\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "multipart/mixed");
    }

    #[test]
    fn content_type_missing_returns_default() {
        let headers = b"From: user@example.com\r\nSubject: no content-type here\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_case_insensitive() {
        let headers = b"From: user@example.com\r\ncontent-type: TEXT/HTML\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/html");
    }

    #[test]
    fn compute_metadata_fields() {
        // header_bytes is 47 bytes, body_bytes is 21 bytes → byte_count = 68
        // body has 3 LF characters → line_count = 3
        // Content-Type header is "text/plain; charset=utf-8" → summary "text/plain"
        let header_bytes = b"Content-Type: text/plain; charset=utf-8\r\n\r\n";
        let body_bytes = b"line1\r\nline2\r\nline3\r\n";

        assert_eq!(header_bytes.len(), 43);
        assert_eq!(body_bytes.len(), 21);

        let metadata = compute_metadata(
            header_bytes,
            body_bytes,
            "<test-001@example.com>".to_string(),
            vec!["comp.lang.rust".to_string(), "comp.test".to_string()],
            1_700_000_000_000,
            vec![],
        );

        assert_eq!(metadata.byte_count, 64); // 43 + 21
        assert_eq!(metadata.line_count, 3);
        assert_eq!(metadata.content_type_summary, "text/plain");
        assert_eq!(metadata.message_id, "<test-001@example.com>");
        assert_eq!(
            metadata.newsgroups,
            vec!["comp.lang.rust".to_string(), "comp.test".to_string()]
        );
        assert_eq!(metadata.hlc_timestamp, 1_700_000_000_000);
        assert!(metadata.operator_signature.is_empty());
    }
}
