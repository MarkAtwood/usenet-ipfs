//! UUCP `#! rnews` batch format parser and related types.
//!
//! Implements the batch format specified in INN2 and C News documentation.
//! Security invariants:
//!   - UUCP-G1: decompressed batch size capped at MAX_BATCH_DECOMPRESSED_BYTES
//!   - UUCP-G3: article count per batch capped at MAX_BATCH_ARTICLES

/// Maximum number of articles in a single rnews batch (UUCP-G3).
pub const MAX_BATCH_ARTICLES: usize = 1000;

/// Maximum total decompressed size of a rnews batch in bytes (UUCP-G1).
/// Protects against gzip bombs in compressed (#! gunbatch) batches.
///
/// Note: this cap applies only to compressed batches. An uncompressed batch
/// can contain up to MAX_BATCH_ARTICLES × MAX_RNEWS_ARTICLE_BYTES = ~1 GiB.
/// The asymmetry is intentional: the 50 MiB cap exists to bound memory use
/// during decompression (gzip bomb defense); uncompressed batches are read
/// directly from the OS without an intermediate decompressed-content buffer.
pub const MAX_BATCH_DECOMPRESSED_BYTES: usize = 50 * 1024 * 1024; // 50 MiB

/// Maximum size of a single article in bytes.
/// Must match `MAX_ARTICLE_BYTES` in `peering/ingestion.rs`.
pub const MAX_RNEWS_ARTICLE_BYTES: usize = 1_048_576; // 1 MiB

/// Errors produced by the rnews batch parser and decompressor.
#[derive(Debug, thiserror::Error)]
pub enum RnewsError {
    /// Batch contains more articles than the configured limit.
    #[error("batch exceeds article count limit: {count} > {limit}")]
    BatchTooLarge { count: usize, limit: usize },

    /// Decompressed output exceeds the configured size limit.
    /// Indicates a likely gzip/compress bomb.
    #[error("decompressed output exceeds size limit: {bytes} > {limit}")]
    DecompressedTooLarge { bytes: usize, limit: usize },

    /// Compression format is recognised but not supported by this implementation.
    #[error("unsupported compression format: {0}")]
    UnsupportedCompression(String),

    /// The batch data is structurally invalid.
    #[error("malformed batch: {0}")]
    MalformedBatch(String),

    /// An I/O error occurred while reading the batch.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Decompress a `#! gunbatch` payload (gzip, RFC 1952).
///
/// # Security invariant UUCP-G1
/// Returns `Err(RnewsError::DecompressedTooLarge)` if the decompressed output
/// would exceed `MAX_BATCH_DECOMPRESSED_BYTES` before completing. Uses a
/// streaming `.take()` wrapper so the cap is enforced without allocating the
/// full oversized output first.
pub fn decompress_gunbatch(compressed: &[u8]) -> Result<Vec<u8>, RnewsError> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let decoder = GzDecoder::new(compressed);
    // .take(limit + 1): if the stream has more than limit bytes, we'll read
    // exactly limit+1 bytes and then check. This enforces the cap without
    // allocating beyond limit+1.
    let limit = MAX_BATCH_DECOMPRESSED_BYTES;
    let mut limited = decoder.take((limit + 1) as u64);
    let mut out = Vec::with_capacity(compressed.len().min(limit));
    limited.read_to_end(&mut out)?;

    if out.len() > limit {
        return Err(RnewsError::DecompressedTooLarge {
            bytes: out.len(),
            limit,
        });
    }
    Ok(out)
}

/// Decompress a `#! cunbatch` payload (Unix compress / LZW, `.Z` format).
///
/// Unix compress (LZW) is not supported in this version. Returns
/// `Err(RnewsError::UnsupportedCompression)`.
///
/// LZW support is tracked in a future spike issue under the stoa-9qqyc epic.
pub fn decompress_cunbatch(_compressed: &[u8]) -> Result<Vec<u8>, RnewsError> {
    Err(RnewsError::UnsupportedCompression(
        "cunbatch (Unix compress .Z) is not supported; use gunbatch (gzip) instead".to_string(),
    ))
}

/// Parse a `#! rnews` batch (possibly compressed) into a vector of raw article
/// byte vectors.
///
/// Compression is detected by the leading marker:
/// - `#! gunbatch\n` — gzip-compressed batch; decompressed before parsing.
/// - `#! cunbatch\n` — Unix compress (LZW); returns
///   `Err(RnewsError::UnsupportedCompression)`.
/// - Anything else is treated as an uncompressed plain rnews batch.
///
/// # Security invariants
/// - UUCP-G1: decompressed size capped at `MAX_BATCH_DECOMPRESSED_BYTES`
///   (enforced inside `decompress_gunbatch`).
/// - UUCP-G3: article count capped at `MAX_BATCH_ARTICLES`.
/// - UUCP-G4: individual article size capped at `MAX_RNEWS_ARTICLE_BYTES`.
pub fn parse_rnews_batch(input: &[u8]) -> Result<Vec<Vec<u8>>, RnewsError> {
    const GUNBATCH_MARKER: &[u8] = b"#! gunbatch\n";
    const CUNBATCH_MARKER: &[u8] = b"#! cunbatch\n";

    if input.starts_with(GUNBATCH_MARKER) {
        let decompressed = decompress_gunbatch(&input[GUNBATCH_MARKER.len()..])?;
        parse_rnews_batch_plain(&decompressed)
    } else if input.starts_with(CUNBATCH_MARKER) {
        return Err(RnewsError::UnsupportedCompression(
            "cunbatch (Unix compress .Z) is not supported; use gunbatch (gzip) instead".to_string(),
        ));
    } else {
        parse_rnews_batch_plain(input)
    }
}

/// Parse an uncompressed `#! rnews` batch into raw article byte vectors.
fn parse_rnews_batch_plain(input: &[u8]) -> Result<Vec<Vec<u8>>, RnewsError> {
    const RNEWS_HEADER_PREFIX: &[u8] = b"#! rnews ";

    let mut articles: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;

    while pos < input.len() {
        // Find the newline that terminates the header line.
        let nl = input[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| {
                RnewsError::MalformedBatch("unexpected EOF: no newline in header line".to_string())
            })?;

        let line = &input[pos..pos + nl];
        pos += nl + 1;

        // Validate the header prefix.
        if !line.starts_with(RNEWS_HEADER_PREFIX) {
            return Err(RnewsError::MalformedBatch(format!(
                "expected #! rnews header, got: {:?}",
                &line[..line.len().min(40)]
            )));
        }

        // Parse the byte count from the remainder of the header line.
        let count_bytes = &line[RNEWS_HEADER_PREFIX.len()..];
        let count_str = std::str::from_utf8(count_bytes).map_err(|_| {
            RnewsError::MalformedBatch("article byte count is not valid UTF-8".to_string())
        })?;
        let count_u64 = count_str.parse::<u64>().map_err(|_| {
            RnewsError::MalformedBatch(format!(
                "article byte count is not a valid integer: {:?}",
                count_str
            ))
        })?;
        if count_u64 > MAX_RNEWS_ARTICLE_BYTES as u64 {
            return Err(RnewsError::MalformedBatch(format!(
                "article byte count {} exceeds limit {}",
                count_u64, MAX_RNEWS_ARTICLE_BYTES
            )));
        }
        let count = count_u64 as usize;

        // Checked bounds arithmetic before slice indexing.
        let article_end = pos
            .checked_add(count)
            .ok_or_else(|| RnewsError::MalformedBatch("byte count overflow".to_string()))?;
        if article_end > input.len() {
            return Err(RnewsError::MalformedBatch(format!(
                "truncated: declared {} bytes but only {} remain",
                count,
                input.len() - pos
            )));
        }

        // Each article is copied into a new Vec. For a max-size uncompressed
        // batch (1000 × 1 MiB) this doubles peak RSS vs. holding slices into
        // the original input. Eliminating the copy requires changing
        // parse_rnews_batch's public signature to Vec<&'a [u8]>, which is a
        // breaking API change deferred to a future refactor (stoa-paxfh.14).
        articles.push(input[pos..article_end].to_vec());
        pos = article_end;

        // Cap check AFTER pushing so that the 1001st article is counted.
        if articles.len() > MAX_BATCH_ARTICLES {
            return Err(RnewsError::BatchTooLarge {
                count: articles.len(),
                limit: MAX_BATCH_ARTICLES,
            });
        }
    }

    Ok(articles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_gunbatch_roundtrip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let plaintext = b"hello world, this is a test rnews batch payload";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_gunbatch(&compressed).expect("should decompress successfully");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decompress_gunbatch_rejects_corrupt_data() {
        let garbage = b"this is not gzip data at all";
        let result = decompress_gunbatch(garbage);
        assert!(result.is_err(), "corrupt gzip should return Err");
    }

    #[test]
    fn decompress_cunbatch_unsupported() {
        let result = decompress_cunbatch(b"some data");
        assert!(
            matches!(result, Err(RnewsError::UnsupportedCompression(_))),
            "cunbatch must return UnsupportedCompression"
        );
    }

    // ---- helpers for parse_rnews_batch tests ----

    // Duplicated in tests/rnews_ingest.rs — keep in sync.
    // Rust cannot share #[cfg(test)] helpers across the lib/integration boundary.
    fn make_article(
        from: &str,
        newsgroups: &str,
        msgid: &str,
        subject: &str,
        body: &str,
    ) -> Vec<u8> {
        format!(
            "From: {from}\r\nNewsgroups: {newsgroups}\r\nMessage-ID: {msgid}\r\nSubject: {subject}\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n{body}\r\n"
        )
        .into_bytes()
    }

    // Duplicated in tests/rnews_ingest.rs — keep in sync.
    // Rust cannot share #[cfg(test)] helpers across the lib/integration boundary.
    fn make_batch(articles: &[Vec<u8>]) -> Vec<u8> {
        let mut batch = Vec::new();
        for art in articles {
            let header = format!("#! rnews {}\n", art.len());
            batch.extend_from_slice(header.as_bytes());
            batch.extend_from_slice(art);
        }
        batch
    }

    #[test]
    fn parse_batch_empty_input() {
        assert_eq!(parse_rnews_batch(b"").unwrap(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn parse_batch_two_articles() {
        let art1 = make_article(
            "alice@example.com",
            "misc.test",
            "<test-001@example.com>",
            "Test 1",
            "Body 1",
        );
        let art2 = make_article(
            "bob@example.com",
            "misc.test",
            "<test-002@example.com>",
            "Test 2",
            "Body 2",
        );
        let batch = make_batch(&[art1.clone(), art2.clone()]);
        let result = parse_rnews_batch(&batch).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], art1);
        assert_eq!(result[1], art2);
    }

    #[test]
    fn parse_batch_count_cap() {
        // 1001 articles of 1 byte each — should fail with BatchTooLarge
        let batch = (0..1001usize).fold(Vec::new(), |mut acc, _| {
            acc.extend_from_slice(b"#! rnews 1\n");
            acc.push(b'X');
            acc
        });
        let result = parse_rnews_batch(&batch);
        assert!(
            matches!(
                result,
                Err(RnewsError::BatchTooLarge {
                    count: 1001,
                    limit: 1000
                })
            ),
            "expected BatchTooLarge{{count:1001,limit:1000}}, got: {:?}",
            result
        );
    }

    #[test]
    fn parse_batch_malformed_no_count() {
        // Header prefix present but no byte count follows
        let result = parse_rnews_batch(b"#! rnews\n");
        assert!(
            matches!(result, Err(RnewsError::MalformedBatch(_))),
            "expected MalformedBatch, got: {:?}",
            result
        );
    }

    #[test]
    fn parse_batch_truncated() {
        // Declare 100 bytes but only provide 10
        let mut batch = Vec::new();
        batch.extend_from_slice(b"#! rnews 100\n");
        batch.extend_from_slice(b"0123456789"); // only 10 bytes
        let result = parse_rnews_batch(&batch);
        assert!(
            matches!(result, Err(RnewsError::MalformedBatch(_))),
            "expected MalformedBatch, got: {:?}",
            result
        );
    }

    #[test]
    fn parse_batch_count_too_large() {
        // Declare an article larger than MAX_RNEWS_ARTICLE_BYTES
        let header = format!("#! rnews {}\n", MAX_RNEWS_ARTICLE_BYTES + 1);
        let result = parse_rnews_batch(header.as_bytes());
        assert!(
            matches!(result, Err(RnewsError::MalformedBatch(_))),
            "expected MalformedBatch, got: {:?}",
            result
        );
    }

    /// Test that the cap is enforced. We compress a string that will expand
    /// beyond MAX_BATCH_DECOMPRESSED_BYTES.
    ///
    /// NOTE: This test generates a ~50 MiB compressed stream which takes a
    /// few seconds. It is marked #[ignore] for normal CI; run with
    /// `cargo test -- --ignored` when needed.
    #[test]
    #[ignore]
    fn decompress_gunbatch_cap_enforced() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Compress MAX+1 bytes of zeros (highly compressible — tiny gzip)
        let oversized = vec![0u8; MAX_BATCH_DECOMPRESSED_BYTES + 1];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&oversized).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_gunbatch(&compressed);
        assert!(
            matches!(result, Err(RnewsError::DecompressedTooLarge { .. })),
            "should return DecompressedTooLarge, got: {:?}",
            result
        );
    }
}
