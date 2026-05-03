//! Helpers for SMTP relay enqueue after a successful NNTP POST.
//!
//! After an article is stored to IPFS, this module extracts email recipients
//! from `To:` and `Cc:` headers and enqueues the article for outbound SMTP
//! relay delivery.  All relay operations are best-effort: failures are logged
//! at `warn` level and never propagate to the NNTP caller.

use std::sync::Arc;

use stoa_smtp::SmtpRelayQueue;

/// Collect email-address recipients from the `To:` and `Cc:` header fields of
/// `article_bytes`.
///
/// Only addresses that contain `@` are returned; Usenet newsgroup paths such as
/// `comp.lang.rust` are silently discarded.  The function scans only the header
/// section (everything before the first blank line).
///
/// Display names such as `"Alice <alice@example.com>"` are handled: the value
/// between `<` and `>` is extracted.  Plain addresses such as
/// `"alice@example.com"` are accepted directly.  Comma-separated lists within
/// a single header value are split.
pub fn extract_email_recipients(article_bytes: &[u8]) -> Vec<String> {
    let header_end = find_header_end(article_bytes);
    let header_bytes = &article_bytes[..header_end];
    let headers = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("smtp relay: article headers are not valid UTF-8; skipping relay");
            return Vec::new();
        }
    };

    let mut recipients = Vec::new();
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("to:") || lower.starts_with("cc:") {
            let value = line[line.find(':').unwrap_or(0) + 1..].trim();
            recipients.extend(parse_email_addrs(value));
        }
    }
    recipients
}

/// Extract the sender address from the `From:` header of `article_bytes`.
///
/// Returns an empty string if the header is absent or unparseable — the
/// empty string is a valid RFC 5321 reverse-path (MAIL FROM:<>) and is safe
/// to pass to `SmtpRelayQueue::enqueue`.
pub fn extract_mail_from(article_bytes: &[u8]) -> String {
    let header_end = find_header_end(article_bytes);
    let header_bytes = &article_bytes[..header_end];
    let headers = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };

    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("from:") {
            let value = line[line.find(':').unwrap_or(0) + 1..].trim();
            let addrs = parse_email_addrs(value);
            if let Some(addr) = addrs.into_iter().next() {
                return addr;
            }
        }
    }
    String::new()
}

/// Enqueue `article_bytes` for outbound SMTP relay if:
/// - `relay_queue` is `Some`, and
/// - the article has at least one email recipient in `To:` or `Cc:`.
///
/// Failures are non-fatal: logged at `warn` level, NNTP POST is unaffected.
pub async fn maybe_enqueue_smtp_relay(
    relay_queue: Option<&Arc<SmtpRelayQueue>>,
    article_bytes: &[u8],
) {
    let queue = match relay_queue {
        Some(q) => q,
        None => return,
    };

    let recipients = extract_email_recipients(article_bytes);
    if recipients.is_empty() {
        return;
    }

    let mail_from = extract_mail_from(article_bytes);
    let rcpts: Vec<&str> = recipients.iter().map(String::as_str).collect();

    if let Err(e) = queue.enqueue(article_bytes, &mail_from, &rcpts, false).await {
        tracing::warn!("smtp relay enqueue failed: {e}");
        stoa_smtp::metrics::inc_relay_enqueue_failure();
    }
}

/// Return the byte offset of the end of the header section (exclusive).
///
/// Looks for `\r\n\r\n` or `\n\n`; if neither is found, returns
/// `article_bytes.len()` (treat the whole thing as headers).
fn find_header_end(article_bytes: &[u8]) -> usize {
    match crate::post::find_header_boundary(article_bytes) {
        Some(body_start) => {
            let sep_len =
                if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                    4
                } else {
                    2
                };
            body_start - sep_len
        }
        None => article_bytes.len(),
    }
}

/// Parse an RFC 5322 address list and return only addresses containing `@`.
///
/// Accepts bare addresses (`user@example.com`), angle-bracket form
/// (`Display Name <user@example.com>`), quoted display names with commas
/// (`"Smith, John" <j@example.com>`), and RFC 5322 address groups.
/// Uses `mailparse::addrparse` so quoting and folding are handled correctly.
fn parse_email_addrs(value: &str) -> Vec<String> {
    match mailparse::addrparse(value) {
        Ok(list) => list
            .iter()
            .flat_map(|addr| match addr {
                mailparse::MailAddr::Single(info) => vec![info.addr.clone()],
                mailparse::MailAddr::Group(group) => {
                    group.addrs.iter().map(|i| i.addr.clone()).collect()
                }
            })
            .filter(|addr| addr.contains('@'))
            .collect(),
        Err(e) => {
            tracing::warn!("smtp relay: failed to parse address header {value:?}: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_email_recipients ─────────────────────────────────────────────

    #[test]
    fn plain_email_in_to_header() {
        let article = b"To: alice@example.com\r\nFrom: bob@example.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert_eq!(result, vec!["alice@example.com"]);
    }

    #[test]
    fn display_name_angle_bracket_address() {
        let article = b"To: Alice <alice@example.com>\r\nFrom: bob@example.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert_eq!(result, vec!["alice@example.com"]);
    }

    #[test]
    fn multiple_recipients_comma_separated() {
        let article =
            b"To: Alice <alice@example.com>, Bob <bob@example.com>\r\nFrom: c@d.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert_eq!(result, vec!["alice@example.com", "bob@example.com"]);
    }

    #[test]
    fn quoted_comma_in_display_name() {
        // "Smith, John" <john@example.com> — the comma inside the quoted display
        // name must not split the address into two tokens.
        let article = b"To: \"Smith, John\" <john@example.com>\r\nFrom: b@c.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert_eq!(result, vec!["john@example.com"]);
    }

    #[test]
    fn newsgroup_path_in_to_is_excluded() {
        let article = b"To: comp.lang.rust\r\nFrom: bob@example.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert!(
            result.is_empty(),
            "newsgroup path must not be treated as email: {result:?}"
        );
    }

    #[test]
    fn cc_header_email_is_included() {
        let article = b"To: comp.lang.rust\r\nCc: carol@example.com\r\nFrom: b@c.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert_eq!(result, vec!["carol@example.com"]);
    }

    #[test]
    fn no_to_or_cc_header_returns_empty() {
        let article = b"From: bob@example.com\r\nSubject: hi\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert!(result.is_empty());
    }

    #[test]
    fn non_utf8_headers_returns_empty() {
        // 0xFF is not valid UTF-8. from_utf8_lossy would replace it with U+FFFD
        // and potentially corrupt an email address. The correct behaviour is to
        // return an empty list and skip relay entirely.
        let article = b"To: alice\xFF@example.com\r\n\r\nBody";
        let result = extract_email_recipients(article);
        assert!(
            result.is_empty(),
            "non-UTF-8 headers must not produce relay recipients: {result:?}"
        );
    }

    // ── extract_mail_from ────────────────────────────────────────────────────

    #[test]
    fn plain_from_address() {
        let article = b"From: bob@example.com\r\n\r\nBody";
        assert_eq!(extract_mail_from(article), "bob@example.com");
    }

    #[test]
    fn display_name_from_address() {
        let article = b"From: Bob <bob@example.com>\r\n\r\nBody";
        assert_eq!(extract_mail_from(article), "bob@example.com");
    }

    #[test]
    fn missing_from_header_returns_empty() {
        let article = b"Subject: hi\r\n\r\nBody";
        assert_eq!(extract_mail_from(article), "");
    }

    // ── maybe_enqueue_smtp_relay ─────────────────────────────────────────────

    #[tokio::test]
    async fn no_queue_is_noop() {
        let article = b"To: alice@example.com\r\nFrom: bob@example.com\r\n\r\nBody";
        maybe_enqueue_smtp_relay(None, article).await;
    }

    #[tokio::test]
    async fn queue_none_with_newsgroup_only_is_noop() {
        let article = b"To: comp.lang.rust\r\nFrom: bob@example.com\r\n\r\nBody";
        maybe_enqueue_smtp_relay(None, article).await;
    }

    #[tokio::test]
    async fn enqueues_email_recipients() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![],
            std::time::Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");

        let article = b"To: alice@example.com\r\nFrom: bob@example.com\r\n\r\nBody text";
        maybe_enqueue_smtp_relay(Some(&queue), article).await;

        // With no peers configured, enqueue is a no-op (files are NOT written).
        // This validates the code path without needing a real SMTP peer.
        let mut entries = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
            .count();
        // No peers → no files written (SmtpRelayQueue::enqueue returns Ok immediately).
        assert_eq!(entries, 0, "no peers → no .env files expected");

        // Now test with a peer configured so files ARE written.
        let peer = stoa_smtp::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: 2525,
            tls: false,
            username: None,
            password: None,
        };
        let dir2 = tempfile::tempdir().expect("tempdir2");
        let queue2 = SmtpRelayQueue::new(
            dir2.path().to_path_buf(),
            vec![peer],
            std::time::Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue2");

        maybe_enqueue_smtp_relay(Some(&queue2), article).await;

        entries = std::fs::read_dir(dir2.path())
            .expect("read_dir2")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
            .count();
        assert_eq!(entries, 1, "one .env file must be written for one article");
    }

    #[tokio::test]
    async fn newsgroup_only_recipients_skip_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let peer = stoa_smtp::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: 2525,
            tls: false,
            username: None,
            password: None,
        };
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![peer],
            std::time::Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");

        let article = b"To: comp.lang.rust\r\nFrom: bob@example.com\r\n\r\nBody text";
        maybe_enqueue_smtp_relay(Some(&queue), article).await;

        let entries = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
            .count();
        assert_eq!(entries, 0, "newsgroup-only To: must not create queue files");
    }
}
