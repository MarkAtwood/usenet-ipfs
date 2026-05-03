//! Operator key rotation: publish a signed rotation announcement article.

use sha2::Digest;

/// Configuration for the key rotation command.
pub struct RotateConfig {
    /// Path to the old private key PEM file.
    pub old_key_path: std::path::PathBuf,
    /// Path to the new public key PEM file.
    pub new_key_path: std::path::PathBuf,
    /// Gossipsub group to publish the announcement to.
    pub group: String,
}

pub use stoa_core::signing::load_signing_key;

/// Load a public key from a PKCS#8 SubjectPublicKeyInfo PEM file.
///
/// Returns `(VerifyingKey, fingerprint_hex)` where the fingerprint is the
/// SHA-256 of the full SubjectPublicKeyInfo DER bytes, hex-encoded (64 chars).
/// This matches the fingerprint format produced by `transit keygen`.
pub fn load_verifying_key(
    pem_path: &std::path::Path,
) -> Result<(ed25519_dalek::VerifyingKey, String), String> {
    let pem_text = std::fs::read_to_string(pem_path)
        .map_err(|e| format!("cannot read {}: {e}", pem_path.display()))?;

    let der = decode_pem(&pem_text, "PUBLIC KEY")
        .ok_or_else(|| format!("not a valid PUBLIC KEY PEM: {}", pem_path.display()))?;

    // SubjectPublicKeyInfo DER for ed25519: 12-byte fixed header + 32-byte public key.
    if der.len() != 44 {
        return Err(format!(
            "unexpected SPKI DER length {} (expected 44): {}",
            der.len(),
            pem_path.display()
        ));
    }

    let key_bytes: [u8; 32] = der[12..44]
        .try_into()
        .map_err(|_| "public key slice length mismatch".to_string())?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("invalid public key bytes: {e}"))?;

    // Fingerprint: SHA-256 of the full SPKI DER bytes, hex-encoded.
    let digest = sha2::Sha256::digest(&der);
    let fingerprint = hex::encode(digest);

    Ok((verifying_key, fingerprint))
}

/// Build a key rotation announcement article.
///
/// The article body contains the new public key PEM block.
/// The article is NOT signed here — signing happens in the caller via
/// `cmd_key_rotate`.
///
/// Line endings are CRLF throughout per RFC 5322.
pub fn build_rotation_article(
    old_fingerprint: &str,
    new_fingerprint: &str,
    new_pubkey_pem: &str,
    group: &str,
    timestamp_ms: u64,
    node_id: &str,
) -> Vec<u8> {
    let message_id = format!("<rotate-{timestamp_ms}@{node_id}.stoa>");

    // RFC 2822 date: format timestamp_ms as "Dow, DD Mon YYYY HH:MM:SS +0000"
    let date_rfc2822 = {
        use chrono::{DateTime, Utc};
        let secs = (timestamp_ms / 1000) as i64;
        DateTime::<Utc>::from_timestamp(secs, 0)
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
            .format("%a, %d %b %Y %H:%M:%S +0000")
            .to_string()
    };

    let mut out = String::new();
    out.push_str("From: key-rotation@stoa\r\n");
    out.push_str(&format!("Date: {date_rfc2822}\r\n"));
    out.push_str(&format!("Newsgroups: {group}\r\n"));
    out.push_str("Subject: Key rotation announcement\r\n");
    out.push_str(&format!("Message-ID: {message_id}\r\n"));
    out.push_str("X-Key-Rotation: new-key\r\n");
    out.push_str(&format!("X-Old-Key-Fingerprint: {old_fingerprint}\r\n"));
    out.push_str(&format!("X-New-Key-Fingerprint: {new_fingerprint}\r\n"));
    out.push_str("\r\n");
    out.push_str(new_pubkey_pem);

    out.into_bytes()
}

/// Execute the key rotation: load keys, build announcement, sign, and return
/// the announcement bytes.
///
/// Does NOT publish to IPFS or gossipsub — the caller is responsible for that.
///
/// Returns `(article_bytes, old_fingerprint, new_fingerprint)`.
pub fn cmd_key_rotate(
    config: &RotateConfig,
    timestamp_ms: u64,
    node_id: &str,
) -> Result<(Vec<u8>, String, String), String> {
    // Load old signing key and derive its fingerprint from the verifying key.
    let old_signing_key = load_signing_key(&config.old_key_path).map_err(|e| e.to_string())?;
    let old_verifying_key = old_signing_key.verifying_key();

    // Reconstruct old fingerprint the same way keygen does:
    // SHA-256 of the SPKI DER bytes for the old public key.
    let mut old_spki = Vec::with_capacity(44);
    old_spki.extend_from_slice(&crate::cli::key_support::SPKI_ED25519_HEADER);
    old_spki.extend_from_slice(old_verifying_key.as_bytes());
    let old_fingerprint = hex::encode(sha2::Sha256::digest(&old_spki));

    // Load new verifying key and its fingerprint.
    let (_new_vk, new_fingerprint) = load_verifying_key(&config.new_key_path)?;

    // Read new public key PEM text for the article body.
    let new_pubkey_pem = std::fs::read_to_string(&config.new_key_path)
        .map_err(|e| format!("cannot read {}: {e}", config.new_key_path.display()))?;

    // Build the rotation announcement article.
    let article_bytes = build_rotation_article(
        &old_fingerprint,
        &new_fingerprint,
        &new_pubkey_pem,
        &config.group,
        timestamp_ms,
        node_id,
    );

    // Sign the article bytes with the old key and attach the signature as an
    // X-Stoa-Sig header (base64url-no-pad encoded) immediately before the
    // header/body separator.  This matches the format expected by
    // stoa_verify::x_sig::verify_x_sig.
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    let signature = old_signing_key.sign(&article_bytes);
    let sig_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let sig_line = format!("X-Stoa-Sig: {sig_value}\r\n");

    // Insert the sig header just before the blank line that separates headers
    // from body.  The article built by build_rotation_article always has
    // \r\n\r\n as the separator.
    let insert_at = article_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2) // point at the second \r\n (the blank line itself)
        .unwrap_or(article_bytes.len());
    let mut signed_bytes = Vec::with_capacity(article_bytes.len() + sig_line.len());
    signed_bytes.extend_from_slice(&article_bytes[..insert_at]);
    signed_bytes.extend_from_slice(sig_line.as_bytes());
    signed_bytes.extend_from_slice(&article_bytes[insert_at..]);

    Ok((signed_bytes, old_fingerprint, new_fingerprint))
}

// ── PEM helpers ──────────────────────────────────────────────────────────────

/// Decode a PEM block with the given `label`.
///
/// Returns `None` if the PEM markers are absent or base64 decoding fails.
fn decode_pem(pem_text: &str, label: &str) -> Option<Vec<u8>> {
    use base64::Engine;

    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let start = pem_text.find(&begin)? + begin.len();
    let stop = pem_text.find(&end)?;

    if stop <= start {
        return None;
    }

    let b64: String = pem_text[start..stop]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD.decode(&b64).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rotation_article_has_required_headers() {
        let article = build_rotation_article(
            "abcdef1234567890",
            "fedcba0987654321",
            "-----BEGIN PUBLIC KEY-----\nfakekey\n-----END PUBLIC KEY-----\n",
            "stoa.keyrotation",
            1_700_000_000_000,
            "testnode",
        );
        let text = String::from_utf8_lossy(&article);
        assert!(text.contains("Date: "), "missing Date header: {text}");
        assert!(
            text.contains("X-Key-Rotation: new-key"),
            "missing X-Key-Rotation: {text}"
        );
        assert!(
            text.contains("X-Old-Key-Fingerprint: abcdef1234567890"),
            "missing old fingerprint"
        );
        assert!(
            text.contains("X-New-Key-Fingerprint: fedcba0987654321"),
            "missing new fingerprint"
        );
        assert!(
            text.contains("Newsgroups: stoa.keyrotation"),
            "missing Newsgroups"
        );
        assert!(text.contains("Message-ID:"), "missing Message-ID");
    }

    fn test_key_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("operator.key")
    }

    #[test]
    fn load_signing_key_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = crate::cli::keygen::generate_keypair(&path, false).unwrap();

        let key = load_signing_key(&result.private_key_path).expect("should load signing key");

        use ed25519_dalek::Signer;
        let sig = key.sign(b"test message");
        let vk = key.verifying_key();
        use ed25519_dalek::Verifier;
        assert!(
            vk.verify(b"test message", &sig).is_ok(),
            "signature should verify"
        );
    }

    #[test]
    fn load_verifying_key_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = crate::cli::keygen::generate_keypair(&path, false).unwrap();

        let (vk, fp) =
            load_verifying_key(&result.public_key_path).expect("should load verifying key");
        assert_eq!(fp.len(), 64, "fingerprint should be 64 hex chars");
        assert_eq!(
            fp, result.fingerprint,
            "fingerprint should match keygen output"
        );
        let _ = vk;
    }

    #[test]
    fn cmd_key_rotate_returns_valid_article() {
        let old_dir = tempfile::TempDir::new().unwrap();
        let new_dir = tempfile::TempDir::new().unwrap();

        let old_result =
            crate::cli::keygen::generate_keypair(&old_dir.path().join("operator.key"), false)
                .unwrap();
        let new_result =
            crate::cli::keygen::generate_keypair(&new_dir.path().join("operator.key"), false)
                .unwrap();

        let config = RotateConfig {
            old_key_path: old_result.private_key_path,
            new_key_path: new_result.public_key_path.clone(),
            group: "stoa.keyrotation".to_string(),
        };

        let (article_bytes, old_fp, new_fp) =
            cmd_key_rotate(&config, 1_700_000_000_000, "testnode").unwrap();

        let text = String::from_utf8_lossy(&article_bytes);
        assert!(text.contains("X-Key-Rotation: new-key"));
        assert!(text.contains(&format!("X-Old-Key-Fingerprint: {old_fp}")));
        assert!(text.contains(&format!("X-New-Key-Fingerprint: {new_fp}")));
        assert_eq!(old_fp, old_result.fingerprint, "old fingerprint mismatch");
        assert_eq!(new_fp, new_result.fingerprint, "new fingerprint mismatch");
    }

    #[test]
    fn article_uses_crlf_line_endings() {
        let article = build_rotation_article(
            "aabbcc",
            "ddeeff",
            "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----\n",
            "stoa.keyrotation",
            42,
            "node1",
        );
        let text = String::from_utf8_lossy(&article);
        // Every header line must end with \r\n.
        assert!(
            text.contains("From: key-rotation@stoa\r\n"),
            "From header must use CRLF"
        );
        assert!(
            text.contains("Subject: Key rotation announcement\r\n"),
            "Subject header must use CRLF"
        );
        // Header/body separator must be \r\n\r\n.
        assert!(
            text.contains("\r\n\r\n"),
            "header/body separator must be CRLF"
        );
    }
}
