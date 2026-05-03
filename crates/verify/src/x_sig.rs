//! Verify `X-Stoa-Sig` Ed25519 article signatures.
//!
//! The header format is:
//! ```text
//! X-Stoa-Sig: <base64url-no-pad>
//! ```
//! The signature is computed over the article bytes with the sig header
//! removed, using the operator's Ed25519 key.  Verification succeeds if any
//! of the supplied trusted keys matches.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::types::{ArticleVerification, SigType, VerifResult};

/// Header name without colon, available for external use (e.g. test harnesses
/// that construct signed articles).
#[allow(dead_code)]
pub(crate) const SIG_HEADER: &str = "X-Stoa-Sig";
const SIG_HEADER_PREFIX: &str = "X-Stoa-Sig:";

/// Try to verify `X-Stoa-Sig` in `article_bytes` against each key in
/// `trusted_keys` in order.
///
/// Returns one `ArticleVerification`:
/// - `Pass` if any key verifies successfully; `identity` is the hex pubkey.
/// - `NoKey` if the header is absent and `trusted_keys` is non-empty.
/// - `ParseError` if the header value is malformed.
/// - `Fail` if all keys were tried and none verified.
///
/// Returns an empty vec when `trusted_keys` is empty AND the header is absent.
pub fn verify_x_sig(
    trusted_keys: &[VerifyingKey],
    article_bytes: &[u8],
) -> Vec<ArticleVerification> {
    let extracted = match extract_sig_header(article_bytes) {
        Ok(v) => v,
        Err(ExtractError::NotFound) => {
            // No X-Stoa-Sig header → no verification to record.
            return vec![];
        }
        Err(ExtractError::NonUtf8) => {
            return vec![ArticleVerification {
                sig_type: SigType::XUsenetIpfsSig,
                result: VerifResult::ParseError {
                    reason: "article headers contain non-UTF-8 bytes".to_owned(),
                },
                identity: None,
            }];
        }
        Err(ExtractError::BadBase64(e)) => {
            return vec![ArticleVerification {
                sig_type: SigType::XUsenetIpfsSig,
                result: VerifResult::ParseError {
                    reason: format!("X-Stoa-Sig value is not valid base64url: {e}"),
                },
                identity: None,
            }];
        }
        Err(ExtractError::Duplicate) => {
            return vec![ArticleVerification {
                sig_type: SigType::XUsenetIpfsSig,
                result: VerifResult::ParseError {
                    reason: "duplicate X-Stoa-Sig headers; article is malformed".to_owned(),
                },
                identity: None,
            }];
        }
    };

    if trusted_keys.is_empty() {
        return vec![ArticleVerification {
            sig_type: SigType::XUsenetIpfsSig,
            result: VerifResult::NoKey,
            identity: None,
        }];
    }

    let sig = match Signature::from_slice(&extracted.sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return vec![ArticleVerification {
                sig_type: SigType::XUsenetIpfsSig,
                result: VerifResult::ParseError {
                    reason: format!("invalid signature bytes: {e}"),
                },
                identity: None,
            }];
        }
    };

    for key in trusted_keys {
        if key
            .verify_strict(&extracted.article_without_sig, &sig)
            .is_ok()
        {
            let key_id = pubkey_hex_id(key);
            return vec![ArticleVerification {
                sig_type: SigType::XUsenetIpfsSig,
                result: VerifResult::Pass,
                identity: Some(key_id),
            }];
        }
    }

    vec![ArticleVerification {
        sig_type: SigType::XUsenetIpfsSig,
        result: VerifResult::Fail {
            reason: format!(
                "signature did not verify against any of {} trusted key(s)",
                trusted_keys.len()
            ),
        },
        identity: None,
    }]
}

struct Extracted {
    sig_bytes: Vec<u8>,
    article_without_sig: Vec<u8>,
}

enum ExtractError {
    NotFound,
    NonUtf8,
    BadBase64(base64::DecodeError),
    /// More than one `X-Stoa-Sig` header was found; the article is malformed.
    Duplicate,
}

fn extract_sig_header(article_bytes: &[u8]) -> Result<Extracted, ExtractError> {
    let body_start = find_header_boundary(article_bytes);

    let header_section = &article_bytes[..body_start.unwrap_or(article_bytes.len())];
    let header_str = std::str::from_utf8(header_section).map_err(|_| ExtractError::NonUtf8)?;

    let mut sig_value_buf = String::new();
    let mut sig_line_start: Option<usize> = None;
    let mut sig_line_end: Option<usize> = None;

    // RFC 5322 §2.2.3: folded headers have continuation lines that begin with
    // at least one WSP character (space or tab).  Collect those too so the full
    // value is decoded and the entire folded block is excised from the signed
    // bytes.
    let mut cursor = 0usize;
    let mut in_sig = false;
    let mut sig_count = 0u32;
    for raw_line in header_str.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if in_sig {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of the folded sig header.
                sig_value_buf.push_str(line.trim());
                sig_line_end = Some(cursor + raw_line.len());
                cursor += raw_line.len();
                continue;
            } else {
                // Not a continuation — folded header is complete.
                in_sig = false;
            }
        }
        if let Some(sig_rest) = line.strip_prefix(SIG_HEADER_PREFIX) {
            sig_count += 1;
            if sig_count > 1 {
                // Duplicate X-Stoa-Sig header — reject the article.
                return Err(ExtractError::Duplicate);
            }
            sig_value_buf.push_str(sig_rest.trim());
            sig_line_start = Some(cursor);
            sig_line_end = Some(cursor + raw_line.len());
            in_sig = true;
        }
        cursor += raw_line.len();
    }

    if sig_line_start.is_none() {
        return Err(ExtractError::NotFound);
    }
    let value = sig_value_buf.as_str();
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(ExtractError::BadBase64)?;

    let start = sig_line_start.unwrap();
    let end = sig_line_end.unwrap();
    let mut without = Vec::with_capacity(article_bytes.len() - (end - start));
    without.extend_from_slice(&article_bytes[..start]);
    without.extend_from_slice(&article_bytes[end..]);

    Ok(Extracted {
        sig_bytes,
        article_without_sig: without,
    })
}

fn find_header_boundary(data: &[u8]) -> Option<usize> {
    // Find \r\n\r\n
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| data.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
}

/// Hex-encoded SHA-256 of the raw 32-byte verifying key bytes.
pub fn pubkey_hex_id(key: &VerifyingKey) -> String {
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn sign_article(key: &SigningKey, article_bytes: &[u8]) -> Vec<u8> {
        let sig: ed25519_dalek::Signature = key.sign(article_bytes);
        let sig_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let sig_line = format!("{SIG_HEADER}: {sig_value}\r\n");
        let body_start = find_header_boundary(article_bytes).unwrap_or(article_bytes.len());
        let sep_len =
            if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                2
            } else {
                1
            };
        let insert_at = body_start - sep_len;
        let mut out = Vec::with_capacity(article_bytes.len() + sig_line.len());
        out.extend_from_slice(&article_bytes[..insert_at]);
        out.extend_from_slice(sig_line.as_bytes());
        out.extend_from_slice(&article_bytes[insert_at..]);
        out
    }

    fn article() -> Vec<u8> {
        b"From: test@example.com\r\nSubject: Test\r\n\r\nBody.\r\n".to_vec()
    }

    #[test]
    fn pass_with_correct_key() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let signed = sign_article(&key, &article());
        let results = verify_x_sig(&[pubkey], &signed);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].result.is_pass(),
            "expected Pass, got {:?}",
            results[0].result
        );
    }

    #[test]
    fn fail_with_wrong_key() {
        let key_a = test_key();
        let key_b = SigningKey::from_bytes(&[0x13u8; 32]);
        let signed = sign_article(&key_a, &article());
        let results = verify_x_sig(&[key_b.verifying_key()], &signed);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, VerifResult::Fail { .. }));
    }

    #[test]
    fn no_header_returns_empty() {
        let results = verify_x_sig(&[test_key().verifying_key()], &article());
        assert!(results.is_empty(), "no sig header must return empty vec");
    }

    #[test]
    fn empty_trusted_keys_with_header_returns_no_key() {
        let signed = sign_article(&test_key(), &article());
        let results = verify_x_sig(&[], &signed);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].result, VerifResult::NoKey);
    }

    #[test]
    fn folded_sig_header_is_unfolded_and_verified() {
        // Build a well-formed article, sign it, then manually fold the
        // X-Stoa-Sig header across two lines.  Verification must still pass
        // and the excised byte range must cover both lines.
        let key = test_key();
        let pubkey = key.verifying_key();
        let signed = sign_article(&key, &article());
        // Locate the sig header in the signed bytes and fold it.
        let sig_str = std::str::from_utf8(&signed).unwrap().to_owned();
        let sig_line_start = sig_str.find("X-Stoa-Sig:").unwrap();
        let sig_line_end = sig_str[sig_line_start..].find('\n').unwrap() + sig_line_start + 1;
        let sig_line = &sig_str[sig_line_start..sig_line_end]; // "X-Stoa-Sig: <value>\r\n"
                                                               // Split the value at midpoint and create a folded version.
        let colon_pos = sig_line.find(':').unwrap();
        let value = sig_line[colon_pos + 1..]
            .trim_end_matches(['\r', '\n'])
            .trim();
        let mid = value.len() / 2;
        let folded = format!("X-Stoa-Sig: {}\r\n\t{}\r\n", &value[..mid], &value[mid..]);
        let folded_article = format!(
            "{}{}{}",
            &sig_str[..sig_line_start],
            folded,
            &sig_str[sig_line_end..]
        );
        let results = verify_x_sig(&[pubkey], folded_article.as_bytes());
        assert_eq!(results.len(), 1, "must produce exactly one result");
        assert!(
            results[0].result.is_pass(),
            "folded sig must verify as Pass, got {:?}",
            results[0].result
        );
    }

    #[test]
    fn second_key_passes_when_first_fails() {
        let key_a = SigningKey::from_bytes(&[0x01u8; 32]);
        let key_b = SigningKey::from_bytes(&[0x02u8; 32]);
        let signed = sign_article(&key_b, &article());
        let results = verify_x_sig(&[key_a.verifying_key(), key_b.verifying_key()], &signed);
        assert_eq!(results.len(), 1);
        assert!(results[0].result.is_pass());
        // identity must be key_b's fingerprint
        assert_eq!(
            results[0].identity,
            Some(pubkey_hex_id(&key_b.verifying_key()))
        );
    }

    /// Independent oracle: signature computed by Python `cryptography` library.
    ///
    /// Test vector generated with:
    /// ```python
    /// from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    /// import base64
    /// key = Ed25519PrivateKey.from_private_bytes(bytes([0x42] * 32))
    /// msg = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
    /// sig = key.sign(msg)
    /// base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    /// # => '7bQmP8369jPqINGUCn6JerQhzjXefPbLowYe6ob4zvNwbGap2dyAjh2kZJ4f-EkeK1m9Z8yv6a5Ooz2y3RIVAg'
    /// ```
    ///
    /// The signed bytes are the article WITHOUT the X-Stoa-Sig header line.
    /// The sig header is inserted manually — `sign_article` is NOT used, so this
    /// test exercises `extract_sig_header` excision against a known-good external
    /// signature rather than a self-referential round-trip.
    #[test]
    fn external_oracle_python_sig_verifies() {
        // Public key for seed [0x42; 32], cross-checked against Python output:
        // key.public_key().public_bytes(Raw, Raw).hex()
        // => "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let pubkey = signing_key.verifying_key();
        assert_eq!(
            hex::encode(pubkey.as_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
            "Rust pubkey must match Python-derived pubkey for seed [0x42;32]"
        );

        // Article with sig header inserted between Subject and blank line.
        // The sig value was computed by Python over the bytes WITHOUT this header.
        let article_with_sig = concat!(
            "From: test@example.com\r\n",
            "Subject: Test\r\n",
            "X-Stoa-Sig: 7bQmP8369jPqINGUCn6JerQhzjXefPbLowYe6ob4zvNwbGap2dyAjh2kZJ4f",
            "-EkeK1m9Z8yv6a5Ooz2y3RIVAg\r\n",
            "\r\n",
            "Body.\r\n",
        );

        let results = verify_x_sig(&[pubkey], article_with_sig.as_bytes());
        assert_eq!(results.len(), 1);
        assert!(
            results[0].result.is_pass(),
            "Python-generated sig must verify; extract_sig_header must excise exactly \
             the sig header line. Got: {:?}",
            results[0].result
        );
    }
}
