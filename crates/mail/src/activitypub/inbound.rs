//! ActivityPub inbound — `Create{Note}` to RFC 5322 article injection.
//!
//! Translates an ActivityPub `Create{Note}` activity into a raw RFC 5322
//! article and injects it via the same IPFS write pipeline used by NNTP POST
//! and JMAP upload.
//!
//! # Deduplication
//!
//! Each activity's `id` field is stored in `activitypub_received`.  If the
//! same `id` is received again, the activity is silently discarded.
//!
//! # HTTP Signature Verification
//!
//! When `ActivityPubConfig.verify_http_signatures` is `true` (default), inbound
//! POST requests must carry a valid `Signature:` header.  The referenced public
//! key is fetched from the `keyId` URL and the signature is verified against
//! the signed components.  If verification fails, the request is rejected with
//! 401.  Set `verify_http_signatures = false` to skip verification (dev mode).

use axum::http::HeaderMap;
use chrono::Utc;
use serde_json::Value;
use sqlx::AnyPool;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Deduplication store ────────────────────────────────────────────────────────

/// Records received activity IDs to prevent duplicate injection.
pub struct ReceivedActivityStore {
    pool: AnyPool,
}

impl ReceivedActivityStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Returns `true` and records the `activity_id` if it is new.
    /// Returns `false` if it was already received.
    pub async fn record_if_new(&self, activity_id: &str) -> Result<bool, sqlx::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let rows_affected = sqlx::query(
            "INSERT OR IGNORE INTO activitypub_received (activity_id, received_at) VALUES (?, ?)",
        )
        .bind(activity_id)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows_affected > 0)
    }
}

// ── Note → RFC 5322 translation ───────────────────────────────────────────────

/// Build a raw RFC 5322 article from a `Note` object.
///
/// Returns `(message_id, newsgroups, article_bytes)` or an error string.
pub fn note_to_article(
    note: &Value,
    group_name: &str,
    base_url: &str,
) -> (String, Vec<String>, Vec<u8>) {
    let content = note["content"]
        .as_str()
        .or_else(|| {
            note["contentMap"]
                .as_object()
                .and_then(|m| m.values().next()?.as_str())
        })
        .unwrap_or("")
        .to_string();

    let from = note["attributedTo"]
        .as_str()
        .map(attributed_to_email)
        .unwrap_or_else(|| "unknown@activitypub.invalid".to_string());

    let subject = note["summary"]
        .as_str()
        .or_else(|| note["name"].as_str())
        .unwrap_or("(no subject)")
        .to_string();

    let published = note["published"].as_str().unwrap_or("").to_string();

    let in_reply_to = note["inReplyTo"]
        .as_str()
        .map(|u| decode_msgid_from_url(u, base_url, group_name));

    // Generate a stable Message-ID from the Note id, or fabricate one.
    let note_id = note["id"].as_str().unwrap_or("").to_string();
    let message_id = if note_id.is_empty() {
        format!("<{}@activitypub.invalid>", Uuid::new_v4())
    } else {
        // Derive from note_id: replace non-RFC5321 chars.
        let sanitized = note_id
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .replace('/', "-")
            .replace(['<', '>', ' ', '\n', '\r'], "_");
        format!("<ap.{sanitized}>")
    };

    // Strip HTML tags from content for plaintext body.
    let body = strip_html(&content);

    // Strip CR and LF from all attacker-controlled values before embedding
    // them in RFC 5322 header field values.  A value containing \r or \n
    // would allow injection of arbitrary headers into the generated article.
    let safe_from = from.replace(['\r', '\n'], "");
    let safe_group_name = group_name.replace(['\r', '\n'], "");
    let safe_subject = subject.replace(['\r', '\n'], "");
    let date = if published.is_empty() {
        Utc::now().format("%a, %d %b %Y %H:%M:%S +0000").to_string()
    } else {
        published.replace(['\r', '\n'], "")
    };

    let mut article = String::new();
    article.push_str(&format!("From: {safe_from}\r\n"));
    article.push_str(&format!("Newsgroups: {safe_group_name}\r\n"));
    article.push_str(&format!("Subject: {safe_subject}\r\n"));
    article.push_str(&format!("Message-ID: {message_id}\r\n"));
    article.push_str(&format!("Date: {date}\r\n"));
    if let Some(ref irt) = in_reply_to {
        let safe_irt = irt.replace(['\r', '\n'], "");
        article.push_str(&format!("In-Reply-To: {safe_irt}\r\n"));
    }
    article.push_str("X-ActivityPub: inbound\r\n");
    article.push_str("\r\n");
    article.push_str(&body);

    (
        message_id,
        vec![group_name.to_string()],
        article.into_bytes(),
    )
}

/// Attempt to reconstruct a Message-ID from a Note URL.
///
/// Inverts the encoding in `outbound::percent_encode_msgid`.
pub(super) fn decode_msgid_from_url(url: &str, base_url: &str, group_name: &str) -> String {
    let prefix = format!("{base_url}/ap/groups/{group_name}/articles/");
    if let Some(encoded) = url.strip_prefix(&prefix) {
        percent_decode(encoded)
    } else {
        // Unknown URL format — use as-is wrapped in angle brackets.
        format!("<{url}>")
    }
}

/// Percent-decode a URL-encoded string.
///
/// Converts any `%XX` sequence where `XX` is a valid hex pair into the
/// corresponding byte value. Invalid sequences are passed through unchanged.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Convert an `attributedTo` URL to a synthetic RFC 5322 mailbox address.
///
/// For `https://host/path/to/user`, produces `user@host`.
/// Falls back to `unknown@activitypub.invalid` if the URL cannot be parsed.
fn attributed_to_email(url: &str) -> String {
    // Strip scheme.
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Split host from path.
    let (host, path) = if let Some(slash) = without_scheme.find('/') {
        (&without_scheme[..slash], &without_scheme[slash..])
    } else {
        // No path component at all.
        return format!("unknown@{}", without_scheme);
    };

    if host.is_empty() {
        return "unknown@activitypub.invalid".to_string();
    }

    // Last non-empty path segment becomes the local part.
    let local = path
        .split('/')
        .rfind(|s| !s.is_empty())
        .unwrap_or("unknown");

    format!("{local}@{host}")
}

// ── HTTP Signature verification ───────────────────────────────────────────────

/// Verify the HTTP Signature on an inbound request.
///
/// Fetches the `keyId` URL to obtain the actor's RSA public key (with
/// TTL-based caching via `pub_key_cache`), then verifies the signature
/// against the reconstructed signed-string.
///
/// Returns `Ok(actor_url)` on success, `Err(reason)` on failure.
pub async fn verify_http_signature(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    http_client: &reqwest::Client,
    pub_key_cache: &RwLock<HashMap<String, (String, Instant)>>,
) -> Result<String, String> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing Signature header".to_string())?;

    let key_id = parse_sig_param(sig_header, "keyId")
        .ok_or_else(|| "Signature header missing keyId".to_string())?;

    let signed_headers_spec =
        parse_sig_param(sig_header, "headers").unwrap_or("(request-target) host date".to_string());

    // stoa-ftx6h.9: enforce a minimum signed-header set regardless of what
    // the (attacker-controlled) headers= parameter says.  Without this, an
    // attacker can omit (request-target) or date and replay the signature
    // against a different path or at an arbitrary time.
    enforce_minimum_signed_headers(&signed_headers_spec, method)?;

    let sig_b64 = parse_sig_param(sig_header, "signature")
        .ok_or_else(|| "Signature header missing signature".to_string())?;

    // Reconstruct the signed string (needed for both cache-hit and miss paths).
    let signed_string = build_signed_string(method, path, headers, body, &signed_headers_spec)?;

    // stoa-ftx6h.13: validate that the actor URL derived from keyId lives on
    // the same host as keyId itself.  This must be done before any cache
    // lookup or fetch so that an attacker cannot slip through on a cache hit.
    let actor_url = key_id.split('#').next().unwrap_or(&key_id).to_string();
    validate_keyid_domain(&key_id, &actor_url)?;

    // Fast path: try cache under read lock.
    {
        let cache = pub_key_cache.read().await;
        if let Some((pem, fetched_at)) = cache.get(&key_id) {
            if fetched_at.elapsed() < crate::activitypub::PUB_KEY_CACHE_TTL {
                verify_rsa_sha256(pem, &signed_string, &sig_b64)?;
                return Ok(actor_url);
            }
        }
    }

    // Slow path: acquire write lock and double-check before fetching.
    // Holding the write lock during the fetch prevents O(concurrent requests)
    // duplicate fetches on a cache miss (TOCTOU between read unlock and write
    // lock).  Readers are blocked only for the duration of the HTTP call,
    // which is rare (only on cache miss or TTL expiry).
    let pem = {
        let mut cache = pub_key_cache.write().await;
        if let Some((pem, fetched_at)) = cache.get(&key_id) {
            if fetched_at.elapsed() < crate::activitypub::PUB_KEY_CACHE_TTL {
                // A concurrent request already populated the cache.
                pem.clone()
            } else {
                // Stale — fetch fresh while holding write lock.
                let fresh = fetch_public_key(&key_id, &actor_url, http_client).await?;
                cache.insert(key_id.clone(), (fresh.clone(), Instant::now()));
                fresh
            }
        } else {
            // Not in cache — fetch while holding write lock.
            let fresh = fetch_public_key(&key_id, &actor_url, http_client).await?;
            cache.insert(key_id.clone(), (fresh.clone(), Instant::now()));
            fresh
        }
    };
    verify_rsa_sha256(&pem, &signed_string, &sig_b64)?;
    Ok(actor_url)
}

/// Parse a named parameter from a `Signature:` header value.
///
/// Uses a quoted-string-aware tokenizer: commas inside double-quoted values
/// are treated as literal characters, not field separators.  This handles
/// values such as `headers="(request-target) host, date"` correctly.
fn parse_sig_param(header: &str, name: &str) -> Option<String> {
    for token in split_sig_params(header) {
        let token = token.trim();
        if let Some(rest) = token.strip_prefix(&format!("{name}=")) {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

/// Split a `Signature:` header value on commas that are outside double-quoted
/// strings.  Characters inside `"..."` are never treated as separators.
fn split_sig_params(header: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    let bytes = header.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                parts.push(&header[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&header[start..]);
    parts
}

/// Maximum response body size for actor document fetches (64 KiB).
///
/// ActivityPub actor documents are small JSON objects; 64 KiB is generous.
/// Rejecting larger responses prevents a malicious actor server from
/// exhausting server memory by returning a gigabyte-sized response body.
const ACTOR_FETCH_MAX_BYTES: usize = 64 * 1024;

/// Fetch and extract the RSA public key PEM from an ActivityPub actor document.
///
/// `actor_url` is the canonical actor URL derived from `key_id` (the part
/// before any `#` fragment).  The fetched document's `id` field must lie on
/// the same host as `key_id`; if it does not, the fetch is rejected to prevent
/// cross-domain key substitution (stoa-ftx6h.13).
async fn fetch_public_key(
    key_id: &str,
    actor_url: &str,
    http_client: &reqwest::Client,
) -> Result<String, String> {
    let resp = http_client
        .get(actor_url)
        .header("Accept", "application/activity+json, application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to fetch actor: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("actor fetch returned {}", resp.status()));
    }

    // Reject up front if the server advertises a body larger than our cap.
    if resp
        .content_length()
        .map(|n| n > ACTOR_FETCH_MAX_BYTES as u64)
        .unwrap_or(false)
    {
        return Err(format!(
            "actor document too large (Content-Length exceeds {ACTOR_FETCH_MAX_BYTES} bytes)"
        ));
    }

    // Fetch body with a hard cap so a lying server cannot OOM us.
    let buf = resp
        .bytes()
        .await
        .map_err(|e| format!("error reading actor response body: {e}"))?;
    if buf.len() > ACTOR_FETCH_MAX_BYTES {
        return Err(format!(
            "actor document body exceeded {ACTOR_FETCH_MAX_BYTES} bytes; aborting fetch"
        ));
    }

    let actor: Value =
        serde_json::from_slice(&buf).map_err(|e| format!("failed to parse actor JSON: {e}"))?;

    // stoa-ftx6h.13: validate that the fetched document's canonical `id`
    // lives on the same host as the keyId.  A response whose `id` points to
    // a different domain than the keyId URL indicates cross-domain key
    // substitution and must be rejected.
    if let Some(doc_id) = actor["id"].as_str() {
        validate_keyid_domain(key_id, doc_id).map_err(|e| {
            format!("fetched actor document id domain mismatch: {e}")
        })?;
    } else {
        return Err("fetched actor document has no 'id' field".to_string());
    }

    let pem = actor["publicKey"]["publicKeyPem"]
        .as_str()
        .ok_or_else(|| "actor has no publicKey.publicKeyPem".to_string())?
        .to_string();

    Ok(pem)
}

/// Enforce that the `headers=` list from the Signature header contains the
/// minimum required components.
///
/// Required always: `(request-target)`, `host`, `date`.
/// Required for POST and PUT (body-carrying methods): `digest`.
///
/// This prevents an attacker from omitting critical headers from the signed
/// string, which would allow replay across different paths or stale requests.
fn enforce_minimum_signed_headers(signed_headers_spec: &str, method: &str) -> Result<(), String> {
    let lower: Vec<&str> = signed_headers_spec.split_whitespace().collect();
    for required in &["(request-target)", "host", "date"] {
        if !lower.contains(required) {
            return Err(format!(
                "Signature headers= list missing required component: {required}"
            ));
        }
    }
    let method_upper = method.to_uppercase();
    if method_upper == "POST" || method_upper == "PUT" {
        if !lower.contains(&"digest") {
            return Err(
                "Signature headers= list missing required 'digest' for body-carrying request"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Validate that the host of `key_id` and `actor_url` match.
///
/// An attacker can set `keyId` to their own server and host a crafted key.
/// If the derived `actor_url` (the part before `#`) resolves to a different
/// host than `key_id`, someone is attempting cross-domain key substitution.
pub fn validate_keyid_domain(key_id: &str, actor_url: &str) -> Result<(), String> {
    let key_host = extract_host(key_id)
        .ok_or_else(|| format!("keyId has no parseable host: {key_id}"))?;
    let actor_host = extract_host(actor_url)
        .ok_or_else(|| format!("actor_url has no parseable host: {actor_url}"))?;
    if key_host != actor_host {
        return Err(format!(
            "keyId host ({key_host}) does not match actor_url host ({actor_host}); \
             cross-domain key substitution rejected"
        ));
    }
    Ok(())
}

/// Extract the host (and optional port) from an `http://` or `https://` URL.
///
/// Returns `None` if the URL has no recognisable scheme+host.
fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Host ends at the first '/', '?', '#', or end-of-string.
    let host = without_scheme
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Build the signed string from the request components.
fn build_signed_string(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    signed_headers_spec: &str,
) -> Result<String, String> {
    use data_encoding::BASE64;
    use sha2::{Digest, Sha256};

    let mut parts = Vec::new();
    for header_name in signed_headers_spec.split_whitespace() {
        match header_name {
            "(request-target)" => {
                parts.push(format!(
                    "(request-target): {} {}",
                    method.to_lowercase(),
                    path
                ));
            }
            "digest" => {
                let hash = Sha256::digest(body);
                let computed = format!("SHA-256={}", BASE64.encode(&hash));
                // stoa-ftx6h.8: if the Signature headers= list includes
                // "digest", the actual Digest header MUST be present.
                // Silently substituting the computed hash would let an
                // attacker omit the Digest header and swap the body without
                // invalidating the signature.
                let provided = headers
                    .get("digest")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        "Digest header required by Signature but absent".to_string()
                    })?;
                if provided != computed {
                    return Err(format!(
                        "Digest mismatch: provided={provided}, computed={computed}"
                    ));
                }
                parts.push(format!("digest: {computed}"));
            }
            name => {
                let val = headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                parts.push(format!("{name}: {val}"));
            }
        }
    }
    Ok(parts.join("\n"))
}

/// Verify an RSA-SHA256 signature.
fn verify_rsa_sha256(pub_key_pem: &str, signed_string: &str, sig_b64: &str) -> Result<(), String> {
    use data_encoding::BASE64;
    use rsa::{
        pkcs1::DecodeRsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier,
        RsaPublicKey,
    };
    use sha2::Sha256;

    let sig_bytes = BASE64
        .decode(sig_b64.as_bytes())
        .map_err(|e| format!("invalid base64 in signature: {e}"))?;

    let pub_key = RsaPublicKey::from_pkcs1_pem(pub_key_pem)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid signature bytes: {e}"))?;
    verifying_key
        .verify(signed_string.as_bytes(), &sig)
        .map_err(|e| format!("signature verification failed: {e}"))?;
    Ok(())
}

// ── HTML stripping ─────────────────────────────────────────────────────────────

/// Remove HTML tags and decode basic entities to get plaintext.
fn strip_html(html: &str) -> String {
    // Only block-level tags produce a newline; inline tags (strong, em, a, etc.) do not.
    const BLOCK_TAGS: &[&str] = &[
        "p",
        "div",
        "br",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "ul",
        "ol",
        "blockquote",
        "pre",
        "hr",
        "tr",
        "td",
        "th",
    ];

    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_buf = String::new();
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag_buf.clear();
            }
            '>' => {
                in_tag = false;
                // Strip leading '/' for closing tags, then take the tag name.
                let name = tag_buf
                    .trim_start_matches('/')
                    .split_ascii_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if BLOCK_TAGS.contains(&name.as_str()) {
                    out.push('\n');
                }
                tag_buf.clear();
            }
            _ if in_tag => tag_buf.push(ch),
            _ => out.push(ch),
        }
    }
    // Decode basic HTML entities.
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_to_article_basic() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/alice/statuses/123",
            "attributedTo": "https://mastodon.social/users/alice",
            "content": "<p>Hello, newsgroups!</p>",
            "summary": "Re: hello",
            "published": "2026-04-27T12:00:00Z"
        });
        let (msgid, newsgroups, bytes) =
            note_to_article(&note, "comp.lang.rust", "https://news.example.com");
        let article = String::from_utf8(bytes).unwrap();
        assert!(article.contains("From: alice@mastodon.social"));
        assert!(article.contains("Newsgroups: comp.lang.rust"));
        assert!(article.contains("Subject: Re: hello"));
        assert!(article.contains("Hello, newsgroups!"));
        assert!(!msgid.is_empty());
        assert_eq!(newsgroups, vec!["comp.lang.rust".to_string()]);
    }

    #[test]
    fn note_to_article_strips_html() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/alice/statuses/456",
            "attributedTo": "https://mastodon.social/users/alice",
            "content": "<p>Hello <strong>world</strong>!</p>"
        });
        let (_, _, bytes) = note_to_article(&note, "comp.test", "https://news.example.com");
        let article = String::from_utf8(bytes).unwrap();
        assert!(article.contains("Hello"));
        assert!(article.contains("world"));
        assert!(!article.contains("<p>"), "should strip HTML tags");
    }

    #[test]
    fn strip_html_basic() {
        assert_eq!(strip_html("<p>Hello</p>"), "\nHello\n");
        assert_eq!(strip_html("plain text"), "plain text");
        assert_eq!(strip_html("&amp;&lt;&gt;"), "&<>");
    }

    #[test]
    fn note_to_article_missing_published_generates_date() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/bob/statuses/789",
            "attributedTo": "https://mastodon.social/users/bob",
            "content": "No timestamp here"
        });
        let (_, _, bytes) = note_to_article(&note, "comp.test", "https://news.example.com");
        let article = String::from_utf8(bytes).unwrap();
        assert!(
            article.contains("Date: "),
            "Date header must be present even without published"
        );
    }

    #[test]
    fn decode_msgid_percent20() {
        let base = "https://news.example.com";
        let group = "comp.test";
        let url = format!("{base}/ap/groups/{group}/articles/%3Chello%20world%40example.com%3E");
        let decoded = decode_msgid_from_url(&url, base, group);
        assert_eq!(decoded, "<hello world@example.com>");
    }

    #[test]
    fn attributed_to_email_roundtrip() {
        assert_eq!(
            attributed_to_email("https://mastodon.social/users/alice"),
            "alice@mastodon.social"
        );
        assert_eq!(
            attributed_to_email("https://example.org/users/deeply/nested/bob"),
            "bob@example.org"
        );
        // No path component — host used as domain, local part is "unknown".
        assert_eq!(
            attributed_to_email("https://activitypub.invalid"),
            "unknown@activitypub.invalid"
        );
    }

    #[tokio::test]
    async fn dedup_prevents_double_injection() {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        let store = ReceivedActivityStore::new(pool);
        assert!(store
            .record_if_new("https://mastodon.social/activities/abc")
            .await
            .unwrap());
        assert!(!store
            .record_if_new("https://mastodon.social/activities/abc")
            .await
            .unwrap());
        assert!(store
            .record_if_new("https://mastodon.social/activities/xyz")
            .await
            .unwrap());
    }

    // ── parse_sig_param ──────────────────────────────────────────────────────

    #[test]
    fn parse_sig_param_simple() {
        let header = r#"keyId="https://example.com/key",algorithm="rsa-sha256",signature="abc123""#;
        assert_eq!(
            parse_sig_param(header, "keyId"),
            Some("https://example.com/key".to_string())
        );
        assert_eq!(
            parse_sig_param(header, "algorithm"),
            Some("rsa-sha256".to_string())
        );
        assert_eq!(
            parse_sig_param(header, "signature"),
            Some("abc123".to_string())
        );
        assert_eq!(parse_sig_param(header, "missing"), None);
    }

    #[test]
    fn parse_sig_param_comma_inside_quoted_value() {
        // A comma inside a quoted string must NOT be treated as a separator.
        let header = r#"keyId="https://example.com/key",headers="(request-target) host, date",signature="xyz""#;
        assert_eq!(
            parse_sig_param(header, "headers"),
            Some("(request-target) host, date".to_string()),
            "comma inside quoted headers value must not split the token"
        );
        assert_eq!(
            parse_sig_param(header, "signature"),
            Some("xyz".to_string()),
            "token after quoted-comma value must still be found"
        );
    }

    // ── enforce_minimum_signed_headers (stoa-ftx6h.9) ───────────────────────

    #[test]
    fn enforce_min_headers_ok() {
        assert!(
            enforce_minimum_signed_headers("(request-target) host date", "GET").is_ok()
        );
    }

    #[test]
    fn enforce_min_headers_missing_request_target() {
        let err = enforce_minimum_signed_headers("host date", "GET").unwrap_err();
        assert!(
            err.contains("(request-target)"),
            "error must name the missing component: {err}"
        );
    }

    #[test]
    fn enforce_min_headers_missing_host() {
        let err = enforce_minimum_signed_headers("(request-target) date", "GET").unwrap_err();
        assert!(err.contains("host"), "error must name the missing component: {err}");
    }

    #[test]
    fn enforce_min_headers_missing_date() {
        let err = enforce_minimum_signed_headers("(request-target) host", "GET").unwrap_err();
        assert!(err.contains("date"), "error must name the missing component: {err}");
    }

    #[test]
    fn enforce_min_headers_post_requires_digest() {
        let err =
            enforce_minimum_signed_headers("(request-target) host date", "POST").unwrap_err();
        assert!(
            err.contains("digest"),
            "POST without digest must be rejected: {err}"
        );
    }

    #[test]
    fn enforce_min_headers_post_with_digest_ok() {
        assert!(
            enforce_minimum_signed_headers("(request-target) host date digest", "POST").is_ok()
        );
    }

    // ── validate_keyid_domain (stoa-ftx6h.13) ───────────────────────────────

    #[test]
    fn validate_keyid_domain_same_host_ok() {
        assert!(validate_keyid_domain(
            "https://mastodon.social/users/alice#main-key",
            "https://mastodon.social/users/alice"
        )
        .is_ok());
    }

    #[test]
    fn validate_keyid_domain_cross_domain_rejected() {
        let err = validate_keyid_domain(
            "https://mastodon.social/users/alice#main-key",
            "https://evil.example.com/users/alice",
        )
        .unwrap_err();
        assert!(
            err.contains("mastodon.social") && err.contains("evil.example.com"),
            "error must name both hosts: {err}"
        );
    }

    #[test]
    fn validate_keyid_domain_fragment_stripped_ok() {
        // actor_url == key_id with fragment stripped — must pass.
        assert!(validate_keyid_domain(
            "https://example.com/users/bob#main-key",
            "https://example.com/users/bob"
        )
        .is_ok());
    }

    // ── build_signed_string digest required (stoa-ftx6h.8) ──────────────────

    #[test]
    fn build_signed_string_digest_absent_is_error() {
        use axum::http::HeaderMap;
        let headers = HeaderMap::new(); // no Digest header
        let err = build_signed_string(
            "POST",
            "/inbox",
            &headers,
            b"hello body",
            "(request-target) host date digest",
        )
        .unwrap_err();
        assert!(
            err.contains("Digest header required"),
            "absent Digest header must be an error: {err}"
        );
    }

    #[test]
    fn build_signed_string_digest_present_and_correct() {
        use axum::http::{HeaderMap, HeaderValue};
        use data_encoding::BASE64;
        use sha2::{Digest as _, Sha256};

        let body = b"hello body";
        let hash = Sha256::digest(body);
        let digest_val = format!("SHA-256={}", BASE64.encode(&hash));

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("date", HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"));
        headers.insert(
            "digest",
            HeaderValue::from_str(&digest_val).unwrap(),
        );

        let result = build_signed_string(
            "POST",
            "/inbox",
            &headers,
            body,
            "(request-target) host date digest",
        );
        assert!(result.is_ok(), "correct Digest header must be accepted: {result:?}");
        let signed = result.unwrap();
        assert!(signed.contains("digest: SHA-256="));
    }

    #[test]
    fn build_signed_string_digest_mismatch_is_error() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert("digest", HeaderValue::from_static("SHA-256=AAAA"));

        let err = build_signed_string(
            "POST",
            "/inbox",
            &headers,
            b"hello body",
            "(request-target) host date digest",
        )
        .unwrap_err();
        assert!(
            err.contains("Digest mismatch"),
            "wrong Digest header must be an error: {err}"
        );
    }
}
