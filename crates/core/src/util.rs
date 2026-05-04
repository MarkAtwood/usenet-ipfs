//! Shared utility functions used across crates.

/// Format a Unix timestamp (seconds since epoch) as an RFC 2822 date string.
///
/// Output format: `Www, DD Mon YYYY HH:MM:SS +0000`
///
/// Uses the Rata Die civil-calendar algorithm; no external date library required.
pub fn epoch_to_rfc2822(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let s = secs;
    let days_since_epoch = s.div_euclid(86400);
    let day_secs = s.rem_euclid(86400) as u32;
    let sec = day_secs % 60;
    let min = (day_secs / 60) % 60;
    let hour = day_secs / 3600;
    // Jan 1 1970 was a Thursday (index 0).
    let wday = ((days_since_epoch % 7 + 7) % 7) as usize;

    // Civil date from days since epoch (Rata Die algorithm).
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[wday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        hour,
        min,
        sec
    )
}

/// Split raw article bytes at the blank-line header/body separator.
///
/// Returns `Some((header_bytes, body_bytes))` where neither slice includes the
/// separator itself.  Searches for `\r\n\r\n` first (canonical NNTP CRLF), then
/// falls back to `\n\n`.  Returns `None` if no separator is found.
pub fn split_headers_body(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return Some((&bytes[..i], &bytes[i + 4..]));
        }
    }
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\n\n") {
            return Some((&bytes[..i], &bytes[i + 2..]));
        }
    }
    None
}

/// Returns `true` if the given bind address resolves to a loopback interface.
///
/// Accepts both bare IP addresses (`"127.0.0.1"`, `"::1"`) and `"host:port"`
/// strings (IPv4 or bracketed IPv6 with port).  `"localhost"` is also
/// recognised as loopback.  Addresses that cannot be parsed default to `false`
/// (fail-safe — do not grant loopback privileges to unrecognised input).
pub fn is_loopback_addr(addr: &str) -> bool {
    // Fast path: bare IP address with no port (handles "::1", "127.0.0.1", …).
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // Slow path: "host:port" or "[IPv6]:port" form.
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

/// Returns `true` if the host extracted from a URL resolves to a loopback address.
///
/// Accepts URLs of the form `"scheme://host[:port][/path]"`.  Used to guard against
/// `allow_http = true` with credentials on a non-loopback endpoint — which would
/// transmit credentials in cleartext over the network.  Parse failures are treated
/// as non-loopback (fail-safe).
pub fn is_loopback_url_host(url: &str) -> bool {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    let host_part = if after_scheme.starts_with('[') {
        after_scheme
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        after_scheme.split(&['/', ':'][..]).next().unwrap_or("")
    };
    if host_part == "localhost" {
        return true;
    }
    host_part
        .parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}

/// Apply NNTP dot-stuffing to article bytes, producing CRLF-terminated output.
///
/// Prepends an extra `.` to every line that starts with `.` (RFC 3977 §3.1.1).
/// Accepts both bare-LF and CRLF input and normalises to CRLF output.  If the
/// input has no trailing newline the final partial line is emitted with a CRLF
/// appended, as required by RFC 3977 §3.1.1.
///
/// This is the single canonical implementation shared by the transit IHAVE
/// importer and the reader ARTICLE/HEAD/BODY/OVER response path.  Do NOT add
/// a second implementation elsewhere — divergent dot-stuffing logic causes
/// article corruption that is difficult to diagnose.
pub fn nntp_dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            // Strip a preceding \r so that CRLF input produces CRLF output
            // without a dangling bare \r on each line.
            let line_end = if i > 0 && bytes[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            let line = &bytes[start..line_end];
            if line.starts_with(b".") {
                out.push(b'.');
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
            start = i + 1;
        }
        i += 1;
    }
    // Remaining bytes after the last newline (input with no trailing newline).
    if start < bytes.len() {
        let line = &bytes[start..];
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_loopback_url_host --------------------------------------------
    // Oracle: same RFCs as is_loopback_addr.
    // Input format: full URLs like "http://host:port/path".

    #[test]
    fn url_host_loopback_ipv4() {
        assert!(is_loopback_url_host("http://127.0.0.1:8080/path"));
        assert!(is_loopback_url_host("http://127.0.0.1/path"));
    }

    #[test]
    fn url_host_loopback_ipv6() {
        assert!(is_loopback_url_host("http://[::1]:8080/path"));
        assert!(is_loopback_url_host("http://[::1]/path"));
    }

    #[test]
    fn url_host_loopback_localhost() {
        assert!(is_loopback_url_host("http://localhost:8080/stoa/blocks"));
        assert!(is_loopback_url_host("http://localhost/"));
    }

    #[test]
    fn url_host_non_loopback_public() {
        assert!(!is_loopback_url_host("http://dav.example.com/path"));
        assert!(!is_loopback_url_host("http://192.168.1.10:9000/minio"));
        assert!(!is_loopback_url_host("http://203.0.113.1/dav"));
    }

    #[test]
    fn url_host_no_scheme_is_non_loopback() {
        // Malformed URL without "://" is treated as non-loopback (fail-safe).
        assert!(!is_loopback_url_host("dav.example.com/path"));
    }

    // -- is_loopback_addr ------------------------------------------------
    // Oracle: RFC 5735 s3 (127.0.0.0/8), RFC 4291 s2.5.3 (::1).
    // Parse errors default to non-loopback (fail-safe).

    #[test]
    fn test_loopback_ipv4() {
        assert!(is_loopback_addr("127.0.0.1:9090"));
    }

    #[test]
    fn test_loopback_ipv6() {
        assert!(is_loopback_addr("[::1]:9090"));
    }

    #[test]
    fn test_non_loopback_any() {
        assert!(!is_loopback_addr("0.0.0.0:9090"));
    }

    #[test]
    fn test_non_loopback_private() {
        assert!(!is_loopback_addr("192.168.1.1:1119"));
    }

    #[test]
    fn test_parse_error() {
        assert!(!is_loopback_addr("not-an-addr"));
    }

    // Bare IP addresses (no port) — cajkm.21
    // Oracle: RFC 5735 s3 (127.0.0.0/8), RFC 4291 s2.5.3 (::1).

    #[test]
    fn test_bare_ipv6_loopback() {
        assert!(is_loopback_addr("::1"));
    }

    #[test]
    fn test_bare_ipv4_loopback() {
        assert!(is_loopback_addr("127.0.0.1"));
    }

    #[test]
    fn test_bare_ipv4_non_loopback() {
        assert!(!is_loopback_addr("192.168.1.1"));
    }

    // -- epoch_to_rfc2822 -------------------------------------------------

    #[test]
    fn epoch_zero_is_thu_01_jan_1970() {
        // Unix epoch (0) is Thursday, 1 January 1970 00:00:00 UTC.
        assert_eq!(epoch_to_rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2024-04-22 12:34:56 UTC, verified against an independent reference:
        // Python: datetime.utcfromtimestamp(1713789296).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Mon, 22 Apr 2024 12:34:56 +0000'
        assert_eq!(
            epoch_to_rfc2822(1_713_789_296),
            "Mon, 22 Apr 2024 12:34:56 +0000"
        );
    }

    #[test]
    fn negative_one_second_is_23_59_59() {
        // secs = -1 → 1969-12-31 23:59:59 UTC
        // Oracle: Python datetime.utcfromtimestamp(-1).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Wed, 31 Dec 1969 23:59:59 +0000'
        assert_eq!(epoch_to_rfc2822(-1), "Wed, 31 Dec 1969 23:59:59 +0000");
    }

    #[test]
    fn negative_3661_seconds_is_22_58_59() {
        // secs = -3661 → 1969-12-31 22:58:59 UTC
        // Oracle: Python datetime.utcfromtimestamp(-3661).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Wed, 31 Dec 1969 22:58:59 +0000'
        assert_eq!(epoch_to_rfc2822(-3661), "Wed, 31 Dec 1969 22:58:59 +0000");
    }

    #[test]
    fn zero_seconds_regression() {
        // Regression: rem_euclid must not break the epoch itself.
        assert_eq!(epoch_to_rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    // ── split_headers_body ────────────────────────────────────────────────────

    #[test]
    fn crlf_separator_splits_correctly() {
        let bytes = b"From: a@b.com\r\nSubject: Hi\r\n\r\nBody text.\r\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com\r\nSubject: Hi");
        assert_eq!(body, b"Body text.\r\n");
    }

    #[test]
    fn lf_separator_splits_correctly() {
        let bytes = b"From: a@b.com\nSubject: Hi\n\nBody text.\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com\nSubject: Hi");
        assert_eq!(body, b"Body text.\n");
    }

    #[test]
    fn crlf_takes_priority_over_lf() {
        // Article with \r\n\r\n: must not split on any embedded \n\n.
        let bytes = b"X: y\r\n\r\nbody\n\nnot a sep";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"X: y");
        assert_eq!(body, b"body\n\nnot a sep");
    }

    #[test]
    fn no_separator_returns_none() {
        let bytes = b"From: a@b.com\r\nSubject: Hi\r\n";
        assert!(split_headers_body(bytes).is_none());
    }

    #[test]
    fn empty_body_after_separator() {
        let bytes = b"From: a@b.com\r\n\r\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com");
        assert_eq!(body, b"");
    }

    // ── nntp_dot_stuff ────────────────────────────────────────────────────────

    #[test]
    fn dot_stuff_no_leading_dot_unchanged() {
        let input = b"hello\r\nworld\r\n";
        assert_eq!(nntp_dot_stuff(input), input.to_vec());
    }

    #[test]
    fn dot_stuff_leading_dot_line_stuffed() {
        let input = b"..foo\r\n";
        assert_eq!(nntp_dot_stuff(input), b"...foo\r\n".to_vec());
    }

    #[test]
    fn dot_stuff_multiple_lines() {
        assert_eq!(
            nntp_dot_stuff(b"normal\r\n.dotted\r\nnormal again\r\n"),
            b"normal\r\n..dotted\r\nnormal again\r\n".to_vec()
        );
    }

    /// RFC 3977 §3.1.1: every line must end with CRLF, including the final
    /// line even when the raw input lacks a trailing CRLF.
    #[test]
    fn dot_stuff_final_line_without_crlf_gets_crlf() {
        let output = nntp_dot_stuff(b"hello\r\nworld");
        assert_eq!(output, b"hello\r\nworld\r\n".to_vec());
    }

    /// CRLF input must not gain an extra bare `\n` (regression for 3vye.7).
    #[test]
    fn dot_stuff_crlf_input_no_extra_newline() {
        assert_eq!(
            nntp_dot_stuff(b"Line one\r\nLine two\r\n"),
            b"Line one\r\nLine two\r\n".to_vec()
        );
    }

    /// Bare-LF input is normalised to CRLF output.
    #[test]
    fn dot_stuff_bare_lf_input_normalised_to_crlf() {
        assert_eq!(
            nntp_dot_stuff(b"Line one\nLine two\n"),
            b"Line one\r\nLine two\r\n".to_vec()
        );
    }
}
