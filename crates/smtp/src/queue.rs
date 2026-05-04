use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use stoa_core::InjectionSource;
use tracing::{info, warn};

use mail_auth::common::headers::HeaderWriter;

use crate::nntp_client::{self, NntpClientConfig, NntpClientError};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Return a unique file stem (without extension) for a new queue entry.
///
/// Format: `{nanoseconds_since_epoch}_{sequence:016x}`
fn unique_stem() -> String {
    let ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{ns}_{seq:016x}")
}

/// Metadata sidecar for a queued NNTP article.
///
/// Written as `<stem>.env` (JSON) alongside `<stem>.msg` (raw article bytes).
/// When the drain processes a `.msg` file, it reads the corresponding `.env`
/// to learn the injection source.  If no `.env` exists (e.g. queue files
/// written before this feature), the source defaults to `SmtpSieve`.
#[derive(Debug, Serialize, Deserialize)]
struct NntpEnvelope {
    #[serde(default = "stoa_core::default_injection_source")]
    pub injection_source: InjectionSource,
}

/// Extract the value of the `Message-Id:` header from RFC 822 article bytes.
///
/// Scans the header section (up to the blank line) for a line whose field name
/// is `message-id` (case-insensitive).  Returns the bare message-id token
/// (stripped of surrounding `<>` and whitespace) if found, or `None` if the
/// header is absent.
pub(crate) fn extract_message_id(bytes: &[u8]) -> Option<String> {
    let header_end = find_header_end(bytes);
    let headers = &bytes[..header_end];

    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(rest) = strip_field_name(line, b"message-id") {
            let value = std::str::from_utf8(rest).unwrap_or("").trim();
            // Strip enclosing angle brackets if present.
            return Some(
                value
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string(),
            );
        }
    }
    None
}

/// Return the byte offset of the end of the header section (the blank line
/// separator, inclusive), or the full length of `bytes` if no blank line is found.
pub(crate) fn find_header_end(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() {
        // Look for \r\n\r\n or \n\n
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return i + 4;
        }
        if bytes[i..].starts_with(b"\n\n") {
            return i + 2;
        }
        // Advance to next line
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        i += 1; // skip the '\n'
    }
    bytes.len()
}

/// Return the byte offset of the end of the header block, excluding the blank
/// line separator — i.e. through the final header line's `\r\n`.
///
/// This is the correct slice bound for passing to a header parser:
/// `&bytes[..header_section_end(bytes)]` contains all headers without the
/// trailing blank line.  Returns the full length of `bytes` if no blank line is found.
pub(crate) fn header_section_end(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .or_else(|| bytes.windows(2).position(|w| w == b"\n\n").map(|p| p + 1))
        .unwrap_or(bytes.len())
}

/// If `line` starts with `field_name:` (case-insensitive), return the bytes
/// after the colon.  The field name must be followed immediately by `:`.
pub(crate) fn strip_field_name<'a>(line: &'a [u8], field_name: &[u8]) -> Option<&'a [u8]> {
    if line.len() <= field_name.len() {
        return None;
    }
    let prefix = &line[..field_name.len()];
    let after = &line[field_name.len()..];
    if prefix.eq_ignore_ascii_case(field_name) && after.first() == Some(&b':') {
        Some(&after[1..])
    } else {
        None
    }
}

/// Durable filesystem-backed queue for outbound NNTP article delivery.
///
/// Articles are written atomically to `queue_dir` (write-to-tmp, then rename).
/// A background drain task picks them up and posts to the NNTP reader.
/// Files that fail delivery are left in place and retried on the next cycle.
/// On startup the drain task scans the directory for files left over from
/// a previous crash — no messages are lost across restarts.
pub struct NntpQueue {
    queue_dir: PathBuf,
    notify: tokio::sync::Notify,
    dkim_signer: Option<crate::config::DkimSignerArc>,
}

impl NntpQueue {
    /// Create a new queue rooted at `queue_dir`, creating the directory if absent.
    pub fn new(
        queue_dir: impl Into<PathBuf>,
        dkim_signer: Option<crate::config::DkimSignerArc>,
    ) -> std::io::Result<Arc<Self>> {
        let queue_dir = queue_dir.into();
        std::fs::create_dir_all(&queue_dir)?;
        Ok(Arc::new(Self {
            queue_dir,
            notify: tokio::sync::Notify::new(),
            dkim_signer,
        }))
    }

    /// Enqueue article bytes for NNTP delivery.
    ///
    /// Write order is load-bearing for crash safety.  The drain loop enumerates
    /// `.msg` files; `.env` must therefore exist before `.msg` goes live.
    ///
    /// 1. Write body to `<stem>.msg.tmp`
    /// 2. Write envelope to `<stem>.env.tmp`, rename to `<stem>.env` (committed)
    /// 3. Rename `<stem>.msg.tmp` → `<stem>.msg` (now visible to drain)
    ///
    /// A crash after step 3 but before step 3 completes leaves a `.msg.tmp`
    /// which is cleaned up by `drain_once` at startup — safe to delete because
    /// the corresponding `.msg` was never promoted.
    ///
    /// A crash between steps 2 and 3 leaves a `.env` with no `.msg`.  The drain
    /// skips it (reads `.msg` which does not exist yet and moves on).  On the
    /// next startup the `.msg.tmp` cleanup handles any leftover tmp file.
    ///
    /// Returns `Err` if the write fails; callers should respond with a 452
    /// transient error so the sending MTA will retry.
    pub async fn enqueue(
        &self,
        article_bytes: &[u8],
        injection_source: InjectionSource,
    ) -> std::io::Result<()> {
        let stem = unique_stem();
        let msg_tmp = self.queue_dir.join(format!("{stem}.msg.tmp"));
        let msg_dst = self.queue_dir.join(format!("{stem}.msg"));
        let env_tmp = self.queue_dir.join(format!("{stem}.env.tmp"));
        let env_dst = self.queue_dir.join(format!("{stem}.env"));
        // Step 1: write body to tmp.
        tokio::fs::write(&msg_tmp, article_bytes).await?;
        // Step 2: commit envelope — must be visible before .msg goes live.
        let env = NntpEnvelope { injection_source };
        let env_json = serde_json::to_vec(&env).map_err(std::io::Error::other)?;
        tokio::fs::write(&env_tmp, &env_json).await?;
        tokio::fs::rename(&env_tmp, &env_dst).await?;
        // Step 3: promote body — drain can now see this entry.
        tokio::fs::rename(&msg_tmp, &msg_dst).await?;
        self.notify.notify_one();
        Ok(())
    }

    /// Start the background drain task.
    ///
    /// Scans the queue directory immediately on startup (crash recovery), then
    /// wakes again on each new enqueue notification or after `retry_interval`,
    /// whichever comes first.
    pub fn start_drain(self: Arc<Self>, nntp_config: NntpClientConfig, retry_interval: Duration) {
        tokio::spawn(async move {
            loop {
                self.drain_once(&nntp_config).await;
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(retry_interval) => {}
                }
            }
        });
    }

    async fn drain_once(&self, nntp_config: &NntpClientConfig) {
        let mut dir = match tokio::fs::read_dir(&self.queue_dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!(dir = %self.queue_dir.display(), "nntp queue: read_dir failed: {e}");
                return;
            }
        };
        loop {
            match dir.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    // Remove any .msg.tmp or .env.tmp files left by a previous crash.
                    // These represent incomplete writes; the corresponding committed
                    // file was never created, so there is nothing to deliver.
                    if path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".msg.tmp") || n.ends_with(".env.tmp"))
                    {
                        if let Err(e) = tokio::fs::remove_file(&path).await {
                            warn!(path = %path.display(), "nntp queue: failed to remove orphan tmp file: {e}");
                        } else {
                            warn!(path = %path.display(), "nntp queue: removed orphan tmp file from previous crash");
                        }
                        continue;
                    }
                    if path.extension().is_some_and(|e| e == "msg") {
                        let env_path = path.with_extension("env");
                        let injection_source = match tokio::fs::read(&env_path).await {
                            Ok(env_bytes) => serde_json::from_slice::<NntpEnvelope>(&env_bytes)
                                .map(|e| e.injection_source)
                                .unwrap_or_else(|_| stoa_core::default_injection_source()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                stoa_core::default_injection_source()
                            }
                            Err(e) => {
                                warn!(path = %env_path.display(), "nntp queue: failed to read .env file: {e}, using default injection source");
                                stoa_core::default_injection_source()
                            }
                        };
                        match tokio::fs::read(&path).await {
                            Ok(bytes) => {
                                // Build the final outbound article in a single allocation.
                                //
                                // When a DKIM signer is present:
                                //   1. Build a body buffer (inject header + article bytes).
                                //   2. Sign that slice (the content the DKIM header covers).
                                //   3. Build the final buffer: DKIM header first, then body.
                                //      Two extend_from_slice calls; no O(n) rotate.
                                //
                                // When no signer is present, size the buffer exactly and
                                // write inject header + article bytes directly.
                                const DKIM_HEADER_ESTIMATE: usize = 512;
                                let inject_header =
                                    format!("X-Stoa-Injection-Source: {injection_source}\r\n");
                                let article = if let Some(signer) = &self.dkim_signer {
                                    // Build inject-header+body slice to sign.
                                    let mut body =
                                        Vec::with_capacity(inject_header.len() + bytes.len());
                                    body.extend_from_slice(inject_header.as_bytes());
                                    body.extend_from_slice(&bytes);
                                    // Sign the inject-header+body slice.
                                    match signer.sign(&body) {
                                        Ok(sig) => {
                                            let dkim_hdr = sig.to_header();
                                            let dkim_bytes = dkim_hdr.as_bytes();
                                            // Build final buffer: DKIM header first, then body.
                                            let mut buf = Vec::with_capacity(
                                                DKIM_HEADER_ESTIMATE + body.len(),
                                            );
                                            buf.extend_from_slice(dkim_bytes);
                                            buf.extend_from_slice(&body);
                                            buf
                                        }
                                        Err(e) => {
                                            let message_id = extract_message_id(&body);
                                            // DKIM signing failure is permanent (deterministic
                                            // Ed25519 key — if signing fails, it will always
                                            // fail). Article is held in queue for operator
                                            // intervention; no dead-letter path exists for
                                            // NntpQueue.
                                            warn!(
                                                message_id = %message_id.unwrap_or_default(),
                                                "DKIM signing failed, holding for operator intervention: {e}"
                                            );
                                            continue;
                                        }
                                    }
                                } else {
                                    let mut buf =
                                        Vec::with_capacity(inject_header.len() + bytes.len());
                                    buf.extend_from_slice(inject_header.as_bytes());
                                    buf.extend_from_slice(&bytes);
                                    buf
                                };
                                let message_id = extract_message_id(&article).unwrap_or_default();
                                match nntp_client::post_article(nntp_config, &article, &message_id)
                                    .await
                                {
                                    Ok(()) => {
                                        if let Err(e) = tokio::fs::remove_file(&path).await {
                                            warn!(
                                                path = %path.display(),
                                                "nntp queue: failed to remove delivered file: {e}"
                                            );
                                        } else {
                                            if let Err(e) = tokio::fs::remove_file(&env_path).await
                                            {
                                                warn!(
                                                    path = %env_path.display(),
                                                    "nntp queue: failed to remove delivered .env file: {e}"
                                                );
                                            }
                                            info!("nntp queue: article delivered");
                                        }
                                    }
                                    Err(NntpClientError::PermanentRejection(ref resp)) => {
                                        warn!(
                                            path = %path.display(),
                                            message_id,
                                            "nntp queue: article permanently rejected (437), \
                                             removing: {resp}"
                                        );
                                        if let Err(e) = tokio::fs::remove_file(&path).await {
                                            warn!(
                                                path = %path.display(),
                                                "nntp queue: failed to remove rejected file: {e}"
                                            );
                                        } else if let Err(e) =
                                            tokio::fs::remove_file(&env_path).await
                                        {
                                            warn!(
                                                path = %env_path.display(),
                                                "nntp queue: failed to remove rejected .env file: {e}"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            path = %path.display(),
                                            "nntp queue: delivery failed, will retry: {e}"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(path = %path.display(), "nntp queue: failed to read file: {e}");
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(dir = %self.queue_dir.display(), "nntp queue: read_dir entry error: {e}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::common::headers::HeaderWriter;
    use stoa_core::InjectionSource;

    const TEST_MSG: &[u8] =
        b"From: sender@example.com\r\nTo: recip@example.com\r\nSubject: Test\r\n\
Date: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\
MIME-Version: 1.0\r\n\r\nHello\r\n";

    #[test]
    fn test_dkim_nntp_signing_prepends_header() {
        let signer = crate::test_support::test_rfc8463_signer();
        let sig = signer.sign(TEST_MSG).expect("sign");
        let header = sig.to_header();
        assert!(
            header.starts_with("DKIM-Signature:"),
            "expected DKIM-Signature header, got: {header}"
        );
        assert!(
            header.contains("a=ed25519-sha256"),
            "expected ed25519-sha256 algorithm tag, got: {header}"
        );
        // Verify the signed bytes are header prepended before message.
        let mut signed = Vec::with_capacity(header.len() + TEST_MSG.len());
        signed.extend_from_slice(header.as_bytes());
        signed.extend_from_slice(TEST_MSG);
        assert!(signed.starts_with(b"DKIM-Signature:"));
    }

    #[test]
    fn test_dkim_nntp_signing_absent() {
        // Without a signer, the outbound article is inject-header + original bytes.
        // Build the expected bytes the same way drain_once does in the no-signer branch.
        let inject_header = format!(
            "X-Stoa-Injection-Source: {}\r\n",
            InjectionSource::SmtpSieve
        );
        let mut article = Vec::with_capacity(inject_header.len() + TEST_MSG.len());
        article.extend_from_slice(inject_header.as_bytes());
        article.extend_from_slice(TEST_MSG);
        // The article starts with the injection header and contains no DKIM-Signature.
        assert!(
            article.starts_with(b"X-Stoa-Injection-Source:"),
            "non-DKIM path must not prepend DKIM-Signature"
        );
        assert!(
            !article.windows(15).any(|w| w == b"DKIM-Signature:"),
            "non-DKIM path must not contain DKIM-Signature header"
        );
    }

    #[test]
    fn test_dkim_no_body_length_tag() {
        let signer = crate::test_support::test_rfc8463_signer();
        let sig = signer.sign(TEST_MSG).expect("sign");
        let header = sig.to_header();
        assert!(
            !header.contains("l="),
            "DKIM-Signature must not contain body length tag (l=), got: {header}"
        );
    }

    #[tokio::test]
    async fn enqueue_creates_msg_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
        queue
            .enqueue(b"article bytes", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "msg"))
            .collect();
        assert_eq!(files.len(), 1, "expected exactly one .msg file");
        let contents = std::fs::read(files[0].path()).expect("read file");
        assert_eq!(contents, b"article bytes");
    }

    #[tokio::test]
    async fn enqueue_multiple_creates_distinct_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
        queue
            .enqueue(b"article one", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue 1");
        queue
            .enqueue(b"article two", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue 2");

        let count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "msg"))
            .count();
        assert_eq!(count, 2, "expected two distinct .msg files");
    }

    #[tokio::test]
    async fn no_tmp_files_after_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
        queue
            .enqueue(b"data", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let tmp_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "tmp"))
            .count();
        assert_eq!(tmp_count, 0, "no .tmp files should remain after enqueue");
    }

    #[tokio::test]
    async fn new_creates_queue_dir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("sub").join("queue");
        NntpQueue::new(&queue_dir, None).expect("NntpQueue::new should create dir");
        assert!(
            queue_dir.is_dir(),
            "queue_dir should exist after NntpQueue::new"
        );
    }

    // --- extract_message_id ---

    #[test]
    fn extract_message_id_present() {
        let article =
            b"From: a@b.com\r\nMessage-Id: <foo@bar.example>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(
            extract_message_id(article),
            Some("foo@bar.example".to_string())
        );
    }

    #[test]
    fn extract_message_id_case_insensitive() {
        let article = b"message-id: <lower@case.test>\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(
            extract_message_id(article),
            Some("lower@case.test".to_string())
        );
    }

    #[test]
    fn extract_message_id_missing() {
        let article = b"From: a@b.com\r\nSubject: no mid\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), None);
    }

    #[test]
    fn extract_message_id_no_angle_brackets() {
        let article = b"Message-Id: plain@id.test\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(
            extract_message_id(article),
            Some("plain@id.test".to_string())
        );
    }
}
