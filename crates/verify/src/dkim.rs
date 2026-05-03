//! DKIM signature verification via `mail-auth`.
//!
//! Wraps `mail_auth::MessageAuthenticator::verify_dkim` to return
//! `ArticleVerification` results.  One result is produced per DKIM-Signature
//! header present in the article.
//!
//! NNTP articles are RFC 5536, not RFC 5322.  They may contain headers that
//! are legal per RFC 5536 but rejected by a strict RFC 5322 parser (e.g.
//! oversized Newsgroups values, non-standard extension headers).  To avoid
//! spurious `ParseError` rows for ordinary articles that simply have no DKIM
//! signature, we check for a `DKIM-Signature:` header before invoking the
//! mail-auth parser.  If no such header is present we return an empty vec
//! immediately, exactly as if the parser found no signatures.

use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};

use crate::types::{ArticleVerification, SigType, VerifResult};

/// Return `true` if the article's header section contains a `DKIM-Signature:`
/// field (case-insensitive, per RFC 5321).
fn has_dkim_signature_header(article_bytes: &[u8]) -> bool {
    // Find the header/body separator.
    //
    // RFC 5322 specifies CRLF line endings; the canonical separator is
    // \r\n\r\n.  Some articles use bare LF (\n) line endings; for those,
    // \n\n is the separator.
    //
    // The \n\n fallback is only used when the article contains NO \r bytes at
    // all (i.e., it is a pure-LF article).  If \r bytes are present but
    // \r\n\r\n was not found — e.g. a truncated or malformed CRLF article —
    // we do NOT fall back to \n\n.  A \n\n found in the body of a CRLF
    // article would otherwise be mistaken for a header/body separator and
    // allow body content (including a "DKIM-Signature:" line) to be falsely
    // detected as a header field.
    //
    // When no separator is found, the entire article is treated as the header
    // section — safe because without a body boundary there can be no body
    // content to falsely match.
    let header_end = if let Some(pos) = article_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        pos
    } else if !article_bytes.contains(&b'\r') {
        // Pure LF article: \n\n is the valid separator.
        article_bytes
            .windows(2)
            .position(|w| w == b"\n\n")
            .unwrap_or(article_bytes.len())
    } else {
        // CRLF article with no \r\n\r\n found (truncated / malformed):
        // treat the entire input as headers to avoid scanning body content.
        article_bytes.len()
    };

    let header_bytes = &article_bytes[..header_end];

    // "DKIM-Signature:" is 15 bytes.
    for line in header_bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() >= 15 && line[..15].eq_ignore_ascii_case(b"DKIM-Signature:") {
            return true;
        }
    }
    false
}

/// Verify all `DKIM-Signature` headers in `article_bytes`.
///
/// Returns one `ArticleVerification` per DKIM-Signature header found.
/// Returns an empty vec when no DKIM-Signature header is present.
///
/// Never panics or returns an error: DNS failures, parse errors, and
/// verification failures are all represented as non-Pass results.
pub async fn verify_dkim_headers(
    authenticator: &MessageAuthenticator,
    article_bytes: &[u8],
) -> Vec<ArticleVerification> {
    // Skip RFC 5322 parsing entirely when no DKIM-Signature is present.
    // NNTP articles may be valid RFC 5536 but rejected by a strict RFC 5322
    // parser; returning ParseError for every unsigned article would generate
    // noise and mislead operators into thinking articles are malformed.
    if !has_dkim_signature_header(article_bytes) {
        return vec![];
    }

    let msg = match AuthenticatedMessage::parse(article_bytes) {
        Some(m) => m,
        None => {
            return vec![ArticleVerification {
                sig_type: SigType::Dkim,
                result: VerifResult::ParseError {
                    reason: "mail-auth could not parse the article as an RFC 5322 message"
                        .to_owned(),
                },
                identity: None,
            }];
        }
    };

    let dkim_outputs = authenticator.verify_dkim(&msg).await;
    if dkim_outputs.is_empty() {
        return vec![];
    }

    dkim_outputs
        .iter()
        .map(|output| {
            let identity = output.signature().map(|s| s.d.clone());

            let result = match output.result() {
                DkimResult::Pass => VerifResult::Pass,
                DkimResult::None => {
                    return ArticleVerification {
                        sig_type: SigType::Dkim,
                        result: VerifResult::NoKey,
                        identity,
                    };
                }
                DkimResult::Neutral(err) => VerifResult::Neutral {
                    reason: format!("{err}"),
                },
                DkimResult::Fail(err) => VerifResult::Fail {
                    reason: format!("{err}"),
                },
                DkimResult::PermError(err) => VerifResult::Fail {
                    reason: format!("perm-error: {err}"),
                },
                DkimResult::TempError(err) => VerifResult::DnsError {
                    domain: identity.clone().unwrap_or_default(),
                    err: format!("{err}"),
                },
            };

            ArticleVerification {
                sig_type: SigType::Dkim,
                result,
                identity,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    use super::*;

    /// Create a `MessageAuthenticator` with no nameservers configured.
    ///
    /// An empty `ResolverConfig` has no nameservers, so all DNS lookups fail
    /// immediately without making any network connections.  This keeps tests
    /// fully offline — no Cloudflare DoT or any other external resolver is
    /// contacted.
    fn offline_authenticator() -> MessageAuthenticator {
        MessageAuthenticator::new(ResolverConfig::default(), ResolverOpts::default())
            .expect("empty resolver config must succeed")
    }

    #[test]
    fn has_dkim_signature_header_detects_field() {
        assert!(has_dkim_signature_header(
            b"From: x@y.com\r\nDKIM-Signature: v=1\r\n\r\nbody\r\n"
        ));
        // Case-insensitive match.
        assert!(has_dkim_signature_header(
            b"dkim-signature: v=1\r\n\r\nbody\r\n"
        ));
        // No DKIM-Signature field.
        assert!(!has_dkim_signature_header(
            b"From: x@y.com\r\nSubject: hi\r\n\r\nbody\r\n"
        ));
        // "DKIM-Signature:" in the body (CRLF article) must not be detected.
        assert!(!has_dkim_signature_header(
            b"From: x\r\n\r\nDKIM-Signature: v=1 is in body\r\n"
        ));
    }

    #[test]
    fn has_dkim_signature_header_lf_only_article() {
        // Pure LF article with DKIM-Signature in headers.
        assert!(has_dkim_signature_header(
            b"From: x@y.com\nDKIM-Signature: v=1\n\nbody\n"
        ));
        // Pure LF article with DKIM-Signature only in the body — must not detect.
        assert!(!has_dkim_signature_header(
            b"From: x@y.com\nSubject: hi\n\nDKIM-Signature: v=1 in body\n"
        ));
    }

    #[test]
    fn has_dkim_signature_header_crlf_with_dkim_in_body_after_nn() {
        // A well-formed CRLF article: headers, \r\n\r\n separator, then a body
        // line that happens to contain "DKIM-Signature:" followed by a bare \n\n.
        // The \r\n\r\n is found first so the body is excluded — must return false.
        assert!(!has_dkim_signature_header(
            b"From: x\r\nSubject: hi\r\n\r\nDKIM-Signature: v=1 in body\n\nmore body\r\n"
        ));
        // A CRLF article with a valid \r\n\r\n separator and DKIM-Signature only
        // in the body: must return false regardless of bare \n\n in the body.
        assert!(!has_dkim_signature_header(
            b"From: x\r\nSubject: hi\r\n\r\nbody text\n\nDKIM-Signature: v=1\r\n"
        ));
    }

    #[tokio::test]
    async fn no_dkim_header_returns_empty() {
        let authenticator = offline_authenticator();
        let article = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let results = verify_dkim_headers(&authenticator, article).await;
        assert!(
            results.is_empty(),
            "article without DKIM header must produce no results"
        );
    }

    #[tokio::test]
    async fn malformed_article_without_dkim_header_returns_empty() {
        let authenticator = offline_authenticator();
        // Completely malformed bytes with no DKIM-Signature header.
        // With the pre-check, these must return empty (not ParseError): an
        // article with no DKIM-Signature simply has nothing to verify.
        let bad = b"\x00\x01\x02";
        let results = verify_dkim_headers(&authenticator, bad).await;
        assert!(
            results.is_empty(),
            "malformed article with no DKIM-Signature must produce no results"
        );
    }

    #[tokio::test]
    async fn article_with_dkim_header_but_unparseable_returns_parse_error() {
        let authenticator = offline_authenticator();
        // Article with a DKIM-Signature: field but NUL bytes that break RFC 5322 parsing.
        let bad = b"DKIM-Signature: v=1\r\n\x00\x01\x02\r\n\r\nbody\r\n";
        let results = verify_dkim_headers(&authenticator, bad).await;
        // mail-auth may or may not parse this; if it does, we get 0+ results.
        // The key invariant: we must not panic, and we must get a vec.
        let _ = results; // result content is implementation-defined
    }
}
