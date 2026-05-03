//! Article ingress validation.
//!
//! Entry points:
//! - [`validate_article_ingress`] — all structural checks for POST/IHAVE
//! - [`check_duplicate`] — Message-ID deduplication against storage

use crate::article::Article;
use crate::error::{ProtocolError, ValidationError};
use crate::wildmat::GroupPolicy;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of groups permitted in the Newsgroups header.
///
/// An article crossposted to more than this many groups is rejected at ingress.
/// Without a cap, a peer can send an article with thousands of fabricated group
/// names and force the transit pipeline to perform one group-log append per
/// name — a DoS multiplier.
///
/// # DECISION (rbe3.17): MAX_NEWSGROUPS cap prevents crosspost DoS
///
/// Without this bound, a malicious peer sends one article with `Newsgroups:`
/// listing thousands of fabricated group names.  The pipeline performs one
/// `log_append` per group: one database write, one HLC tick, one CRDT DAG
/// update.  This is a DoS multiplier that converts one network message into
/// unbounded server work.  The limit of 100 is generous (legitimate
/// crossposts are almost always ≤5 groups) and tested at exactly MAX and MAX+1.
/// Do NOT remove or significantly raise this constant without re-auditing the
/// pipeline for per-group work.
pub const MAX_NEWSGROUPS: usize = 100;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for article ingress validation.
pub struct ValidationConfig {
    /// Maximum article body size in bytes. Default: 1 MiB.
    pub max_article_bytes: usize,
    /// If `Some`, an article is accepted only when at least one of its
    /// `Newsgroups` entries matches the filter.  Wildmat patterns are
    /// supported (e.g. `comp.*`, `!alt.*`).  If `None`, all valid group
    /// names are accepted.
    pub allowed_groups: GroupPolicy,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_article_bytes: 1024 * 1024, // 1 MiB
            allowed_groups: None,
        }
    }
}

// ── Message-ID format check ───────────────────────────────────────────────────

/// Returns `true` if `id` is a well-formed Message-ID.
///
/// Rules (pure string; no regex):
/// - Starts with `<`, ends with `>`
/// - Exactly one `@` between the angle brackets
/// - Local part (before `@`) non-empty, no whitespace, no `<` or `>`
/// - Domain part (after `@`) non-empty, no whitespace, no `<` or `>`
fn is_valid_message_id(id: &str) -> bool {
    let inner = match id.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        Some(s) => s,
        None => return false,
    };

    let at_count = inner.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return false;
    }

    let (local, domain) = inner.split_once('@').expect("one @ confirmed above");

    if local.is_empty() || domain.is_empty() {
        return false;
    }

    // DECISION (rbe3.12): NUL byte explicitly rejected in Message-ID
    //
    // Rust's char::is_whitespace() does NOT match '\0'.  RFC 5322 §2.2 forbids
    // NUL in header field values.  A NUL byte in a Message-ID used as a map key
    // or canonical-serialisation component would corrupt downstream storage —
    // some C string APIs treat NUL as string terminator, and the canonical
    // serialiser uses "\x00\n" as the header/body separator.  The explicit '\0'
    // check in `forbidden` is intentional; do NOT simplify to `is_whitespace()`
    // alone even if a linter suggests it.
    let forbidden = |c: char| c.is_whitespace() || c == '<' || c == '>' || c == '\0';

    if local.chars().any(forbidden) || domain.chars().any(forbidden) {
        return false;
    }

    true
}

/// Validate a Message-ID string at an NNTP ingress boundary.
///
/// Checks (in order):
/// 1. Length ≤ 998 bytes (RFC 5322 §2.1.1)
/// 2. Starts with `<`, ends with `>` — exactly one `@` inside
/// 3. Local part (before `@`) non-empty, no whitespace, no angle brackets
/// 4. Domain part (after `@`) non-empty, no whitespace, no angle brackets
///
/// Returns `Ok(())` on success, or `Err(ValidationError::InvalidMessageId(…))`
/// on failure.  This is the canonical validation entry point for all code
/// that receives a raw Message-ID string from the network (IHAVE, ARTICLE
/// <msgid>, TAKETHIS).
pub fn validate_message_id(id: &str) -> Result<(), ValidationError> {
    const MAX_MSGID_BYTES: usize = 998;
    if id.len() > MAX_MSGID_BYTES {
        return Err(ValidationError::InvalidMessageId(id.to_owned()));
    }
    if !is_valid_message_id(id) {
        return Err(ValidationError::InvalidMessageId(id.to_owned()));
    }
    Ok(())
}

// ── validate_article_ingress ──────────────────────────────────────────────────

/// Validate an Article at the NNTP ingress boundary (POST or IHAVE).
///
/// This is the single validation point called by both the POST and IHAVE
/// handlers. Returns `Ok(())` if the article passes all checks, or the first
/// `ProtocolError` encountered.
///
/// # DECISION (rbe3.22): single validation entry point for POST and IHAVE
///
/// POST and IHAVE both accept articles from untrusted sources and must apply
/// identical structural checks.  Having two separate validation paths risks
/// one drifting out of sync with the other — a check added to POST that is
/// missing from IHAVE could allow privilege escalation (e.g. injecting
/// articles with oversized fields via IHAVE that POST would reject).  A single
/// function called by both handlers guarantees consistency.  If a new check
/// is needed, it is added here once and applies to both paths automatically.
///
/// # Checks (in order)
/// 1. The 5 mandatory RFC 5536 headers (From, Date, Message-ID, Subject, Path)
///    present and non-empty; Newsgroups is the 6th mandatory header, checked
///    separately in step 3 below
/// 2. Message-ID format valid: must match `<local@domain>` with no whitespace
/// 3. Newsgroups not empty; crosspost count ≤ `MAX_NEWSGROUPS`; group name
///    format is guaranteed by the `GroupName` type at construction time
/// 4. If `config.allowed_groups` is `Some`, at least one group must match the filter
/// 5. All header field values ≤ 998 bytes (RFC 5322 §2.1.1)
/// 6. Article body size ≤ `config.max_article_bytes`
pub fn validate_article_ingress(
    article: &Article,
    config: &ValidationConfig,
) -> Result<(), ProtocolError> {
    let h = &article.header;

    // 1. Mandatory headers present and non-empty.
    if h.from.is_empty() {
        return Err(ValidationError::MissingMandatoryHeader("From".into()).into());
    }
    if h.date.is_empty() {
        return Err(ValidationError::MissingMandatoryHeader("Date".into()).into());
    }
    if h.message_id.is_empty() {
        return Err(ValidationError::MissingMandatoryHeader("Message-ID".into()).into());
    }
    if h.subject.is_empty() {
        return Err(ValidationError::MissingMandatoryHeader("Subject".into()).into());
    }
    if h.path.is_empty() {
        return Err(ValidationError::MissingMandatoryHeader("Path".into()).into());
    }

    // 2. Message-ID format.
    if validate_message_id(&h.message_id).is_err() {
        return Err(ValidationError::InvalidMessageId(h.message_id.clone()).into());
    }

    // 3. Newsgroups not empty and within the crosspost cap.
    if h.newsgroups.is_empty() {
        return Err(ValidationError::EmptyNewsgroups.into());
    }
    if h.newsgroups.len() > MAX_NEWSGROUPS {
        return Err(ValidationError::TooManyNewsgroups {
            count: h.newsgroups.len(),
            limit: MAX_NEWSGROUPS,
        }
        .into());
    }

    // 4. If allowed_groups filter is active, at least one destination group must
    //    match.  A crossposted article is accepted if any of its groups passes
    //    the filter; it is rejected only when none do.
    if let Some(ref filter) = config.allowed_groups {
        let any_match = h.newsgroups.iter().any(|g| filter.accepts(g.as_str()));
        if !any_match {
            return Err(ValidationError::InvalidGroupInNewsgroups(
                "none of the article's groups match the configured filter".into(),
            )
            .into());
        }
    }

    // 5. Header field values ≤ 998 bytes (RFC 5322 §2.1.1); no bare CR/LF or NUL.
    //
    // PRECONDITION: callers MUST unfold RFC 5322 obs-fold (CRLF followed by
    // whitespace) before constructing the `Article` passed to this function.
    // Any NNTP POST or IHAVE path must perform unfolding before Article
    // construction so the header values stored in the struct are already flat.
    // If a caller forgets to unfold, a folded header (containing CRLF+WSP)
    // will be REJECTED here by the bare-CR/LF check — this is intentional.
    // Folded headers in the `Article` struct would corrupt canonical
    // serialisation and break downstream line-oriented parsers.
    //
    // NUL (\x00) is forbidden in all header values. The canonical serialiser
    // uses "\x00\n" as the header/body separator; a NUL byte in a header value
    // would corrupt the canonical stream and produce an incorrect CID.
    const MAX_HEADER_VALUE: usize = 998;

    let mandatory_fields = [
        ("From", h.from.as_str()),
        ("Date", h.date.as_str()),
        ("Message-ID", h.message_id.as_str()),
        ("Subject", h.subject.as_str()),
        ("Path", h.path.as_str()),
    ];
    for (name, value) in mandatory_fields {
        if value.len() > MAX_HEADER_VALUE {
            return Err(ValidationError::HeaderFieldTooLong {
                field: name.into(),
                len: value.len(),
                limit: MAX_HEADER_VALUE,
            }
            .into());
        }
        if value.contains('\x00') || value.contains('\r') || value.contains('\n') {
            return Err(ValidationError::InvalidHeaderValue {
                field: name.into(),
                reason: "NUL byte or bare CR/LF forbidden in header values (RFC 5322 §2.2)".into(),
            }
            .into());
        }
    }
    // RFC 5322 §2.2: header names are printable US-ASCII (33–126) excluding
    // colon; a name with embedded CR/LF/NUL/colon would corrupt the canonical
    // byte stream used for signing.
    const MAX_HEADER_NAME: usize = 76;
    for (name, value) in &h.extra_headers {
        if name.is_empty() {
            return Err(ValidationError::InvalidHeaderValue {
                field: "(empty)".into(),
                reason: "header field name must not be empty (RFC 5322 §2.2)".into(),
            }
            .into());
        }
        if name.len() > MAX_HEADER_NAME {
            return Err(ValidationError::HeaderFieldTooLong {
                field: name.clone(),
                len: name.len(),
                limit: MAX_HEADER_NAME,
            }
            .into());
        }
        if name.contains('\x00') || name.contains('\r') || name.contains('\n') || name.contains(':')
        {
            return Err(ValidationError::InvalidHeaderValue {
                field: name.clone(),
                reason: "header field name contains NUL, CR, LF, or colon (RFC 5322 §2.2)".into(),
            }
            .into());
        }
        if value.len() > MAX_HEADER_VALUE {
            return Err(ValidationError::HeaderFieldTooLong {
                field: name.clone(),
                len: value.len(),
                limit: MAX_HEADER_VALUE,
            }
            .into());
        }
        // NUL bytes in extra-header values would corrupt the canonical
        // serialisation, which uses "\x00\n" as the header/body separator.
        if value.contains('\x00') || value.contains('\r') || value.contains('\n') {
            return Err(ValidationError::InvalidHeaderValue {
                field: name.clone(),
                reason: "NUL byte or bare CR/LF forbidden in header values (RFC 5322 §2.2)".into(),
            }
            .into());
        }
    }

    // 6. Body size limit.
    let body_len = article.body.len();
    if body_len > config.max_article_bytes {
        return Err(ValidationError::ArticleTooBig {
            size: body_len,
            limit: config.max_article_bytes,
        }
        .into());
    }

    Ok(())
}

// ── MsgIdStorage + check_duplicate ───────────────────────────────────────────

/// Minimal storage interface for Message-ID deduplication checks.
/// A subset of the full Message-ID→CID map, kept separate for testability.
pub trait MsgIdStorage {
    /// Returns true if the given Message-ID is already known.
    fn contains(&self, message_id: &str) -> bool;
}

/// Check whether a Message-ID is already present in storage.
///
/// Returns [`ProtocolError::DuplicateMessageId`] if the article is already
/// known. Called before any signing or IPFS operations.
pub fn check_duplicate(message_id: &str, storage: &dyn MsgIdStorage) -> Result<(), ProtocolError> {
    if storage.contains(message_id) {
        return Err(ProtocolError::DuplicateMessageId(message_id.into()));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::article::{Article, ArticleHeader, GroupName};
    use crate::wildmat::GroupFilter;
    use std::collections::HashSet;
    use std::sync::Arc;

    struct InMemoryMsgIdStore(HashSet<String>);
    impl MsgIdStorage for InMemoryMsgIdStore {
        fn contains(&self, id: &str) -> bool {
            self.0.contains(id)
        }
    }

    fn make_valid_article() -> Article {
        Article {
            header: ArticleHeader {
                from: "user@example.com".into(),
                date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
                message_id: "<abc123@example.com>".into(),
                newsgroups: vec![GroupName::new("comp.lang.rust").unwrap()],
                subject: "Test subject".into(),
                path: "news.example.com!user".into(),
                extra_headers: vec![],
            },
            body: b"Body text.\r\n".to_vec(),
        }
    }

    // ── valid article ─────────────────────────────────────────────────────────

    #[test]
    fn test_valid_article_passes() {
        let article = make_valid_article();
        let config = ValidationConfig::default();
        assert!(validate_article_ingress(&article, &config).is_ok());
    }

    // ── missing mandatory headers ─────────────────────────────────────────────

    #[test]
    fn test_missing_from_fails() {
        let mut article = make_valid_article();
        article.header.from = String::new();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::MissingMandatoryHeader(ref h))
                if h == "From"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_missing_date_fails() {
        let mut article = make_valid_article();
        article.header.date = String::new();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::MissingMandatoryHeader(ref h))
                if h == "Date"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_missing_message_id_fails() {
        let mut article = make_valid_article();
        article.header.message_id = String::new();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::MissingMandatoryHeader(ref h))
                if h == "Message-ID"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_missing_newsgroups_fails() {
        let mut article = make_valid_article();
        article.header.newsgroups = vec![];
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::EmptyNewsgroups)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_missing_subject_fails() {
        let mut article = make_valid_article();
        article.header.subject = String::new();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::MissingMandatoryHeader(ref h))
                if h == "Subject"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_missing_path_fails() {
        let mut article = make_valid_article();
        article.header.path = String::new();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::MissingMandatoryHeader(ref h))
                if h == "Path"
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── Message-ID format ─────────────────────────────────────────────────────

    #[test]
    fn test_invalid_message_id_no_brackets() {
        let mut article = make_valid_article();
        article.header.message_id = "test@example.com".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidMessageId(_))
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_invalid_message_id_no_at() {
        let mut article = make_valid_article();
        article.header.message_id = "<testexample.com>".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidMessageId(_))
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_invalid_message_id_space() {
        let mut article = make_valid_article();
        article.header.message_id = "<te st@example.com>".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidMessageId(_))
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_valid_message_id() {
        let mut article = make_valid_article();
        article.header.message_id = "<abc123@example.com>".into();
        assert!(validate_article_ingress(&article, &ValidationConfig::default()).is_ok());
    }

    // ── Header field length ───────────────────────────────────────────────────

    #[test]
    fn test_header_field_too_long() {
        let mut article = make_valid_article();
        article.header.subject = "x".repeat(999);
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::HeaderFieldTooLong { ref field, len: 999, limit: 998 })
                if field == "Subject"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_header_field_exactly_998_ok() {
        let mut article = make_valid_article();
        article.header.subject = "x".repeat(998);
        assert!(validate_article_ingress(&article, &ValidationConfig::default()).is_ok());
    }

    // ── Body size limit ───────────────────────────────────────────────────────

    #[test]
    fn test_body_too_big() {
        let mut article = make_valid_article();
        let limit = 16;
        article.body = vec![b'x'; limit + 1];
        let config = ValidationConfig {
            max_article_bytes: limit,
            allowed_groups: None,
        };
        let err = validate_article_ingress(&article, &config).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::ArticleTooBig {
                    size,
                    limit: lim,
                }) if size == limit + 1 && lim == limit
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_body_exactly_at_limit_ok() {
        let mut article = make_valid_article();
        let limit = 16;
        article.body = vec![b'x'; limit];
        let config = ValidationConfig {
            max_article_bytes: limit,
            allowed_groups: None,
        };
        assert!(validate_article_ingress(&article, &config).is_ok());
    }

    // ── allowed_groups filter ─────────────────────────────────────────────────

    #[test]
    fn test_allowed_groups_accepts_member() {
        let article = make_valid_article();
        let config = ValidationConfig {
            max_article_bytes: 1024 * 1024,
            allowed_groups: Some(Arc::new(GroupFilter::new(&["comp.lang.rust"]).unwrap())),
        };
        assert!(validate_article_ingress(&article, &config).is_ok());
    }

    #[test]
    fn test_allowed_groups_rejects_non_member() {
        let article = make_valid_article(); // newsgroups: ["comp.lang.rust"]
        let config = ValidationConfig {
            max_article_bytes: 1024 * 1024,
            // filter only accepts alt.test — comp.lang.rust does not match
            allowed_groups: Some(Arc::new(GroupFilter::new(&["alt.test"]).unwrap())),
        };
        let err = validate_article_ingress(&article, &config).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidGroupInNewsgroups(_))
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── validate_message_id ───────────────────────────────────────────────────

    #[test]
    fn validate_message_id_rejects_malformed_and_accepts_valid() {
        assert!(validate_message_id("<local@domain>").is_ok());
        assert!(validate_message_id("<a@b.c>").is_ok());

        assert!(validate_message_id("no-angles@example.com").is_err());
        assert!(validate_message_id("<no-at>").is_err());
        assert!(validate_message_id("<@empty-local>").is_err());
        assert!(validate_message_id("<local@>").is_err());
        assert!(validate_message_id("<has white space@example.com>").is_err());

        // 999 bytes: '<' + 997 'x' chars + '>' — exceeds the 998-byte limit.
        let long = format!("<{}@x>", "x".repeat(995));
        assert_eq!(long.len(), 999);
        assert!(validate_message_id(&long).is_err());
    }

    // RFC 5322 §2.2: NUL byte is not whitespace in Rust but is forbidden in headers.
    #[test]
    fn test_nul_byte_rejected_in_message_id() {
        // NUL in local part
        let id_with_nul = "<te\x00st@example.com>";
        let err = validate_message_id(id_with_nul).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidMessageId(_)),
            "unexpected error: {err:?}"
        );

        // NUL in domain part
        let id_nul_domain = "<test@exam\x00ple.com>";
        assert!(validate_message_id(id_nul_domain).is_err());
    }

    // ── bare CR/LF in header values ───────────────────────────────────────────

    #[test]
    fn test_obs_fold_in_mandatory_header_rejected() {
        // RFC 5322 obs-fold: CRLF followed by whitespace. Callers must unfold
        // before calling validate_article_ingress; if they do not, the folded
        // header is rejected by the bare-CR/LF check. This test documents that
        // behavior so a future change cannot accidentally accept folded headers.
        let mut article = make_valid_article();
        article.header.subject = "long subject\r\n that wraps".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue {
                    ref field,
                    ..
                }) if field == "Subject"
            ),
            "obs-fold (unfolded) header must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_nul_byte_in_mandatory_header_rejected() {
        let mut article = make_valid_article();
        article.header.from = "user\x00@example.com".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue {
                    ref field,
                    ..
                }) if field == "From"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_bare_cr_in_mandatory_header_rejected() {
        let mut article = make_valid_article();
        article.header.subject = "hello\rworld".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue {
                    ref field,
                    ..
                }) if field == "Subject"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_bare_lf_in_mandatory_header_rejected() {
        let mut article = make_valid_article();
        article.header.from = "user@ex\nample.com".into();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue {
                    ref field,
                    ..
                }) if field == "From"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_bare_cr_in_extra_header_rejected() {
        let mut article = make_valid_article();
        article.header.extra_headers = vec![("X-Custom".into(), "val\rue".into())];
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue {
                    ref field,
                    ..
                }) if field == "X-Custom"
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── extra-header name validation ─────────────────────────────────────────

    #[test]
    fn test_extra_header_name_with_crlf_rejected() {
        // A header name containing CRLF would corrupt canonical serialisation.
        let mut article = make_valid_article();
        article.header.extra_headers = vec![("X-Foo\r\nX-Injected: bar".into(), "value".into())];
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue { .. })
            ),
            "header name with CRLF must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_extra_header_name_with_colon_rejected() {
        // A header name containing a colon would be mis-parsed by line-oriented parsers.
        let mut article = make_valid_article();
        article.header.extra_headers = vec![("X-Bad:Name".into(), "value".into())];
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue { .. })
            ),
            "header name with colon must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_empty_extra_header_name_rejected() {
        let mut article = make_valid_article();
        article.header.extra_headers = vec![("".into(), "value".into())];
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::InvalidHeaderValue { .. })
            ),
            "empty header name must be rejected: {err:?}"
        );
    }

    // ── Newsgroups cap ────────────────────────────────────────────────────────

    #[test]
    fn test_too_many_newsgroups_rejected() {
        let mut article = make_valid_article();
        article.header.newsgroups = (0..=MAX_NEWSGROUPS)
            .map(|i| GroupName::new(&format!("comp.test.group{i}")).unwrap())
            .collect();
        let err = validate_article_ingress(&article, &ValidationConfig::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ProtocolError::ValidationFailed(ValidationError::TooManyNewsgroups {
                    count,
                    limit,
                }) if count == MAX_NEWSGROUPS + 1 && limit == MAX_NEWSGROUPS
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_exactly_max_newsgroups_accepted() {
        let mut article = make_valid_article();
        article.header.newsgroups = (0..MAX_NEWSGROUPS)
            .map(|i| GroupName::new(&format!("comp.test.group{i}")).unwrap())
            .collect();
        assert!(validate_article_ingress(&article, &ValidationConfig::default()).is_ok());
    }

    // ── check_duplicate ───────────────────────────────────────────────────────

    #[test]
    fn test_check_duplicate_returns_error_for_known() {
        let store = InMemoryMsgIdStore(["<abc123@example.com>".to_string()].into_iter().collect());
        let err = check_duplicate("<abc123@example.com>", &store).unwrap_err();
        assert!(
            matches!(err, ProtocolError::DuplicateMessageId(ref id) if id == "<abc123@example.com>"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_check_duplicate_returns_ok_for_unknown() {
        let store = InMemoryMsgIdStore(HashSet::new());
        assert!(check_duplicate("<new@example.com>", &store).is_ok());
    }
}
