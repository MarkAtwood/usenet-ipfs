//! HeaderMapNode: structured DAG-CBOR representation of RFC 5322 headers.
//!
//! The canonical header map stores each header name (lowercased) mapped to
//! either a single string value or a list of values for multi-occurrence
//! headers such as `Received`. The BTreeMap ensures lexicographic key order
//! for deterministic DAG-CBOR serialization and stable CIDs.
//!
//! Date-bearing headers (`date`, `injection-date`, `nntp-posting-date`,
//! `expires`) are transformed from RFC 2822 to RFC 3339 format. If the date
//! cannot be parsed the raw string is stored unchanged — ingestion must not
//! fail on a malformed `Expires:` header.

use std::collections::BTreeMap;

use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// The value of a header field in the structured header map.
///
/// Single-occurrence headers (e.g. `From`, `Subject`) are stored as
/// `Single(String)`, which serializes to a plain CBOR text string.
/// Multi-occurrence headers (e.g. `Received`) are stored as
/// `Multi(Vec<String>)`, which serializes to a CBOR array of text strings.
/// The `#[serde(untagged)]` attribute means no enum tag appears in the CBOR
/// output — the variant is inferred from the CBOR type on deserialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderValue {
    Single(String),
    Multi(Vec<String>),
}

/// A structured map of RFC 5322 header fields for an NNTP article.
///
/// Keys are header names lowercased to ASCII. Values are `HeaderValue::Single`
/// for headers that appear exactly once, or `HeaderValue::Multi` for headers
/// that appear more than once. `BTreeMap` guarantees ascending lexicographic
/// key order, producing deterministic DAG-CBOR bytes and a stable CID.
pub type HeaderMapNode = BTreeMap<String, HeaderValue>;

/// Header names that contain standalone RFC 2822 dates and should be
/// transformed to RFC 3339 format.
const DATE_HEADERS: &[&str] = &["date", "injection-date", "nntp-posting-date", "expires"];

/// Build a structured header map from raw RFC 5322 header bytes.
///
/// - Header names are lowercased to ASCII; names outside `[A-Za-z0-9-]` are
///   dropped to prevent injection of malformed keys into the IPLD DAG.
/// - RFC 2047 encoded words in values are decoded to UTF-8.
/// - Date-bearing headers (`date`, `injection-date`, `nntp-posting-date`,
///   `expires`) are transformed from RFC 2822 to RFC 3339.  Unparseable
///   dates fall back to the raw string so ingestion never fails.
/// - Headers with the same name accumulate into `HeaderValue::Multi`; a
///   single-occurrence header is stored as `HeaderValue::Single`.
///
/// Returns an empty map if `raw_headers` is empty or cannot be parsed.
pub fn build_header_map(raw_headers: &[u8]) -> HeaderMapNode {
    let parsed = match mailparse::parse_headers(raw_headers) {
        Ok((headers, _)) => headers,
        Err(_) => return BTreeMap::new(),
    };

    let mut acc: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for hdr in &parsed {
        let raw_key = hdr.get_key();
        if !is_valid_header_name(&raw_key) {
            continue;
        }
        let key = raw_key.to_ascii_lowercase();
        // mailparse::get_value() decodes RFC 2047 encoded words automatically.
        let value = if DATE_HEADERS.contains(&key.as_str()) {
            let raw = hdr.get_value();
            rfc2822_to_rfc3339(&raw).unwrap_or(raw)
        } else {
            hdr.get_value()
        };
        acc.entry(key).or_default().push(value);
    }

    acc.into_iter()
        .map(|(k, mut v)| {
            if v.len() == 1 {
                (k, HeaderValue::Single(v.remove(0)))
            } else {
                (k, HeaderValue::Multi(v))
            }
        })
        .collect()
}

/// Returns true if `name` is a valid RFC 7230 header field name.
///
/// RFC 7230 §3.2 defines `field-name = token` where
/// `token = 1*tchar` and
/// `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///          "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`.
/// In practice, the characters used in real-world headers are
/// alphanumerics, hyphens, and underscores (e.g. `X_Spam_Status`).
/// The full tchar set is accepted here to avoid silently dropping valid headers.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '_' | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '.' | '^'
                        | '`' | '|' | '~'
                )
        })
}

/// Transform an RFC 2822 date string to RFC 3339.
///
/// Returns `Some(rfc3339)` on success, `None` on parse failure so the caller
/// can fall back to the raw string.
///
/// Python oracle:
/// ```python
/// from email.utils import parsedate_to_datetime
/// dt = parsedate_to_datetime("Mon, 01 Jan 2024 00:00:00 +0000")
/// print(dt.isoformat())  # 2024-01-01T00:00:00+00:00
/// ```
/// Note: chrono emits `Z` for UTC offsets (+00:00), Python emits `+00:00`.
/// Both are valid RFC 3339 representations of the same instant.
fn rfc2822_to_rfc3339(s: &str) -> Option<String> {
    DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HeaderValue serialization ─────────────────────────────────────────────

    #[test]
    fn single_value_roundtrip() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "from".into(),
            HeaderValue::Single("alice@example.com".into()),
        );
        map.insert("subject".into(), HeaderValue::Single("Hello world".into()));

        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn multi_value_roundtrip() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "received".into(),
            HeaderValue::Multi(vec![
                "from a.example by b.example".into(),
                "from c.example by d.example".into(),
            ]),
        );

        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn empty_map_roundtrip() {
        let map: HeaderMapNode = BTreeMap::new();
        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn keys_are_sorted() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert("zebra".into(), HeaderValue::Single("z".into()));
        map.insert("apple".into(), HeaderValue::Single("a".into()));
        map.insert("middle".into(), HeaderValue::Single("m".into()));

        let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["apple", "middle", "zebra"]);
    }

    #[test]
    fn serialization_is_deterministic() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "from".into(),
            HeaderValue::Single("alice@example.com".into()),
        );
        map.insert(
            "received".into(),
            HeaderValue::Multi(vec!["hop1".into(), "hop2".into()]),
        );

        let bytes1 = serde_ipld_dagcbor::to_vec(&map).expect("encode 1");
        let bytes2 = serde_ipld_dagcbor::to_vec(&map).expect("encode 2");
        assert_eq!(bytes1, bytes2, "serialization must be byte-identical");
    }

    // ── build_header_map ──────────────────────────────────────────────────────

    // Test article header block: Content-Type + one From + two Received headers.
    const SAMPLE_HEADERS: &[u8] = b"\
From: alice@example.com\r\n\
Subject: Test article\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\
Received: from a.example by b.example\r\n\
Received: from c.example by d.example\r\n\
\r\n";

    #[test]
    fn header_name_lowercased() {
        let map = build_header_map(SAMPLE_HEADERS);
        assert!(map.contains_key("from"), "From -> from");
        assert!(map.contains_key("subject"), "Subject -> subject");
        assert!(
            map.contains_key("content-type"),
            "Content-Type -> content-type"
        );
        assert!(!map.contains_key("From"), "must not have mixed-case key");
    }

    #[test]
    fn single_occurrence_is_single_variant() {
        let map = build_header_map(SAMPLE_HEADERS);
        assert!(
            matches!(map.get("from"), Some(HeaderValue::Single(_))),
            "From appears once -> Single"
        );
    }

    #[test]
    fn multi_occurrence_is_multi_variant() {
        let map = build_header_map(SAMPLE_HEADERS);
        match map.get("received") {
            Some(HeaderValue::Multi(v)) => {
                assert_eq!(v.len(), 2);
                assert!(v[0].contains("a.example"));
                assert!(v[1].contains("c.example"));
            }
            other => panic!("expected Multi, got {:?}", other),
        }
    }

    #[test]
    fn empty_input_produces_empty_map() {
        let map = build_header_map(b"");
        assert!(map.is_empty());
    }

    #[test]
    fn rfc2047_encoded_word_in_header() {
        let raw = format!("Subject: {}\r\n\r\n", "=?utf-8?Q?Hello_world?=");
        let map = build_header_map(raw.as_bytes());
        assert_eq!(
            map.get("subject"),
            Some(&HeaderValue::Single("Hello world".into()))
        );
    }

    // ── Date transform (za1) ──────────────────────────────────────────────────

    #[test]
    fn date_header_rfc2822_to_rfc3339_utc() {
        // Python oracle:
        //   from email.utils import parsedate_to_datetime
        //   parsedate_to_datetime("Mon, 01 Jan 2024 00:00:00 +0000").isoformat()
        //   -> '2024-01-01T00:00:00+00:00'
        // chrono emits +00:00 (not Z) for this offset — both are valid RFC 3339.
        let raw = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("date") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s == "2024-01-01T00:00:00+00:00" || s == "2024-01-01T00:00:00Z",
                    "unexpected RFC 3339 output: {s}"
                );
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    #[test]
    fn date_header_rfc2822_to_rfc3339_negative_offset() {
        // Python oracle:
        //   parsedate_to_datetime("Wed, 03 Jan 2024 12:00:00 -0500").isoformat()
        //   -> '2024-01-03T12:00:00-05:00'
        let raw = b"Date: Wed, 03 Jan 2024 12:00:00 -0500\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("date") {
            Some(HeaderValue::Single(s)) => {
                assert_eq!(s, "2024-01-03T12:00:00-05:00");
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    #[test]
    fn unparseable_date_stored_as_raw() {
        let raw = b"Expires: not-a-date-at-all\r\n\r\n";
        let map = build_header_map(raw);
        assert_eq!(
            map.get("expires"),
            Some(&HeaderValue::Single("not-a-date-at-all".into()))
        );
    }

    #[test]
    fn received_header_not_date_transformed() {
        let raw = b"Received: from a.example by b.example; Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("received") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s.contains("a.example"),
                    "Received should be stored verbatim, not transformed: {s}"
                );
                assert!(
                    !s.starts_with("20"),
                    "Received should not be transformed to date-only: {s}"
                );
            }
            other => panic!("expected Single received, got {:?}", other),
        }
    }

    #[test]
    fn injection_date_transformed() {
        let raw = b"Injection-Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("injection-date") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s.starts_with("2024-01-01"),
                    "Injection-Date should be RFC 3339: {s}"
                );
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    // ── Security: header name validation ────────────────────────────────────

    #[test]
    fn invalid_header_names_are_dropped() {
        // Header names with control chars, colons, or spaces must be dropped.
        let raw = b"X-Valid: ok\r\nX Bad: dropped\r\nX\x00Null: dropped\r\n\r\n";
        let map = build_header_map(raw);
        assert!(map.contains_key("x-valid"), "valid header present");
        assert!(!map.contains_key("x bad"), "space in name must be dropped");
        // null-containing keys can't be tested as string keys easily, but the
        // filter runs before insertion, so the key would never reach the map.
    }

    #[test]
    fn underscore_in_header_name_is_accepted() {
        // RFC 7230 §3.2 tchar includes '_'.  Real-world headers like
        // X_Spam_Status must not be silently dropped.
        let raw = b"X_Spam_Status: No\r\nX-Normal: ok\r\n\r\n";
        let map = build_header_map(raw);
        assert!(
            map.contains_key("x_spam_status"),
            "X_Spam_Status must be accepted (tchar allows underscore)"
        );
        assert!(map.contains_key("x-normal"), "hyphenated header still accepted");
    }
}
