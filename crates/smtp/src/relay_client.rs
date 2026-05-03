use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine as _;
use pin_project::pin_project;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;

use hickory_resolver::TokioResolver;

use crate::config::{MtaStsMode, SmtpRelayPeerConfig};
use crate::mta_sts_dns::lookup_mta_sts_txt;
use crate::mta_sts_fetcher::fetch_mta_sts_policy_body;
use crate::mta_sts_mx::check_mx_against_policy;
use crate::mta_sts_policy::parse_mta_sts_policy;
use crate::relay_error::SmtpRelayError;
use crate::tlsrpt::{TlsrptFailureType, TlsrptRecorder};
use stoa_core::util::nntp_dot_stuff;

// ─── MTA-STS enforcement ──────────────────────────────────────────────────────

/// Whether the outbound relay connection is TLS-encrypted.
///
/// Passed to [`MtaStsEnforcer::enforce_for_delivery`] so that MTA-STS
/// enforcement can verify the connection is encrypted before permitting
/// `enforce`-mode delivery (RFC 8461 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTlsStatus {
    /// The relay connection is TLS-encrypted.
    Connected,
    /// The relay connection is plaintext (no TLS).
    Plain,
}

/// How often to re-check the DNS TXT `id=` on a cache hit (RFC 8461 §4.1 SHOULD).
/// Checking every delivery adds one DNS RTT per message; once per minute is enough
/// to detect policy rotation quickly without making per-message DNS a bottleneck.
const ID_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Cached policy entry used by `MtaStsEnforcer`.
struct CachedStsEntry {
    /// The `id=` from the DNS TXT record at the time this policy was fetched.
    /// Used to detect RFC 8461 §4.1 policy rotation (id= change forces re-fetch).
    policy_id: String,
    mode: MtaStsMode,
    /// Shared behind `Arc` so cache-hit paths clone the pointer, not the vec.
    mx_patterns: Arc<Vec<String>>,
    /// When the DNS TXT `id=` was last verified against the live record.
    /// Throttles re-checks to at most once per [`ID_CHECK_INTERVAL`].
    last_id_check: Instant,
    /// When this cache entry expires (derived from the policy `max_age`).
    valid_until: Instant,
}

/// In-memory MTA-STS policy cache and enforcement for outbound relay.
///
/// One instance is created at startup and shared via `Arc`.  Each call to
/// [`MtaStsEnforcer::enforce_for_delivery`] checks the in-memory cache first;
/// on a cache miss it performs a DNS TXT lookup and HTTPS policy fetch, then
/// applies the enforcement rules from RFC 8461 §4.
///
/// On any DNS or fetch error the enforcer logs a warning and allows delivery to
/// proceed — RFC 8461 §2 says policy fetch failures MUST NOT block delivery.
///
/// # Cache persistence
///
/// The cache is in-memory only and is **not** persisted to disk.  On process
/// restart all cached policies are discarded; the first outbound delivery to
/// each domain after restart triggers a live DNS + HTTPS policy fetch.  Under
/// high restart frequency this creates additional load on remote policy servers
/// and adds latency on the first post-restart delivery to each domain.
pub struct MtaStsEnforcer {
    resolver: TokioResolver,
    http_client: reqwest::Client,
    cache: Mutex<HashMap<String, CachedStsEntry>>,
    fetch_timeout_ms: u64,
    max_body_bytes: usize,
    tlsrpt: Arc<TlsrptRecorder>,
}

impl MtaStsEnforcer {
    pub fn new(fetch_timeout_ms: u64, max_body_bytes: usize) -> Result<Self, crate::MtaStsError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| crate::MtaStsError::DnsLookupFailed { message: format!("resolver init failed: {e}") })?
            .build();
        // reqwest::Client holds a connection pool; build once and reuse.
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                crate::MtaStsError::PolicyFetchFailed { message: format!("HTTP client init failed: {e}") }
            })?;
        Ok(Self {
            resolver,
            http_client,
            cache: Mutex::new(HashMap::new()),
            fetch_timeout_ms,
            max_body_bytes,
            tlsrpt: Arc::new(TlsrptRecorder::new()),
        })
    }

    /// Apply MTA-STS enforcement for a single delivery attempt.
    ///
    /// `rcpt_domain` — the domain part of the recipient address (e.g. `"example.com"`).
    /// `peer_host`   — the hostname of the relay peer (matched against MX patterns).
    /// `peer_tls`    — TLS status of the relay connection.
    ///
    /// Returns `Ok(())` when delivery is allowed, `Err(Permanent(...))` when
    /// the enforce policy blocks delivery.
    pub async fn enforce_for_delivery(
        &self,
        rcpt_domain: &str,
        peer_host: &str,
        peer_tls: PeerTlsStatus,
    ) -> Result<(), SmtpRelayError> {
        // Step 1: Check the in-memory cache.
        //
        // NOTE: std::sync::Mutex guard is dropped at the end of the block,
        // before any .await point.  Do not hold the guard across an await —
        // that would deadlock a Tokio worker thread.
        let cached = {
            let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            // Opportunistic eviction: purge entries whose TTL has expired to bound
            // memory use (the cache otherwise grows without bound for long-lived
            // processes delivering to many distinct domains).
            let now = Instant::now();
            guard.retain(|_, entry| now < entry.valid_until);
            guard
                .get(rcpt_domain)
                .map(|entry| {
                    (
                        entry.policy_id.clone(),
                        entry.mode, // MtaStsMode is Copy
                        entry.mx_patterns.clone(),
                        entry.last_id_check,
                    )
                })
        };

        let (mode, mx_patterns) = match cached {
            Some((cached_id, mode, mx_patterns, last_id_check)) => {
                // Step 2 (cache hit): RFC 8461 §4.1 SHOULD verify id= periodically to
                // detect policy rotation.  Checking on every delivery adds a DNS RTT per
                // message; once per ID_CHECK_INTERVAL is sufficient and avoids making
                // DNS a per-message bottleneck.  Tolerate DNS failure — a valid cached
                // entry must never block delivery due to a transient DNS problem.
                if last_id_check.elapsed() >= ID_CHECK_INTERVAL {
                    match lookup_mta_sts_txt(&self.resolver, rcpt_domain).await {
                        Ok(Some(txt)) if txt.policy_id != cached_id => {
                            // Policy has rotated — discard stale entry and re-fetch.
                            // NOTE: guard dropped immediately.
                            self.cache
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .remove(rcpt_domain);
                            match self.load_fresh_policy(rcpt_domain, &txt).await {
                                Some(p) => p,
                                None => return Ok(()), // fetch failed; don't block delivery
                            }
                        }
                        // id= unchanged, no TXT record, or DNS error — refresh check
                        // timestamp so we don't retry again immediately.
                        _ => {
                            // NOTE: guard dropped immediately.
                            if let Some(entry) = self
                                .cache
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .get_mut(rcpt_domain)
                            {
                                entry.last_id_check = Instant::now();
                            }
                            (mode, mx_patterns)
                        }
                    }
                } else {
                    // DNS check not due yet — use cached policy directly.
                    (mode, mx_patterns)
                }
            }
            None => {
                // Step 2 (cache miss): DNS TXT lookup followed by HTTPS policy fetch.
                let txt = match lookup_mta_sts_txt(&self.resolver, rcpt_domain).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return Ok(()),
                    Err(e) => {
                        warn!("MTA-STS DNS lookup failed for {rcpt_domain}: {e}");
                        return Ok(()); // RFC 8461 §2: fetch failures must not block delivery
                    }
                };
                match self.load_fresh_policy(rcpt_domain, &txt).await {
                    Some(p) => p,
                    None => return Ok(()),
                }
            }
        };

        // Step 3: Apply enforcement rules.
        match mode {
            MtaStsMode::None => Ok(()),
            MtaStsMode::Testing => {
                if peer_tls == PeerTlsStatus::Plain {
                    warn!("MTA-STS testing: TLS not enabled for peer {peer_host} to {rcpt_domain}");
                } else if !check_mx_against_policy(peer_host, &mx_patterns) {
                    warn!("MTA-STS testing: peer {peer_host} not in MX policy for {rcpt_domain}");
                }
                Ok(())
            }
            MtaStsMode::Enforce => {
                if peer_tls == PeerTlsStatus::Plain {
                    self.tlsrpt.record_failure(
                        rcpt_domain,
                        TlsrptFailureType::StarttlsNotSupported,
                        Some(peer_host),
                        None,
                    );
                    return Err(SmtpRelayError::Permanent(format!(
                        "MTA-STS enforce: TLS required for {rcpt_domain} but relay is plaintext"
                    )));
                }
                if !check_mx_against_policy(peer_host, &mx_patterns) {
                    self.tlsrpt.record_failure(
                        rcpt_domain,
                        TlsrptFailureType::StsPolicyInvalid,
                        Some(peer_host),
                        None,
                    );
                    return Err(SmtpRelayError::Permanent(format!(
                        "MTA-STS enforce: peer host {peer_host} \
                         does not match MX policy for {rcpt_domain}"
                    )));
                }
                Ok(())
            }
        }
    }

    /// Fetch the MTA-STS policy from HTTPS and insert it into the cache.
    ///
    /// `txt` is the DNS TXT record whose `id=` is stored with the cached entry.
    /// Returns `None` on any fetch or parse failure (caller must not block delivery).
    async fn load_fresh_policy(
        &self,
        rcpt_domain: &str,
        txt: &crate::MtaStsTxtRecord,
    ) -> Option<(MtaStsMode, Arc<Vec<String>>)> {
        let body = match fetch_mta_sts_policy_body(
            &self.http_client,
            rcpt_domain,
            self.fetch_timeout_ms,
            self.max_body_bytes,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!("MTA-STS policy fetch failed for {rcpt_domain}: {e}");
                return None;
            }
        };

        let policy = match parse_mta_sts_policy(&body, self.max_body_bytes) {
            Ok(p) => p,
            Err(e) => {
                warn!("MTA-STS policy parse failed for {rcpt_domain}: {e}");
                return None;
            }
        };

        // Enforce a minimum 60-second cache TTL regardless of max_age.
        // max_age: 0 would otherwise expire immediately, causing a DNS + HTTPS
        // re-fetch on every delivery — a remote-controlled amplification risk.
        let effective_age = (policy.max_age as u64).max(60);
        let valid_until = Instant::now() + Duration::from_secs(effective_age);
        let mx_arc = Arc::new(policy.mx_patterns);
        let entry = CachedStsEntry {
            policy_id: txt.policy_id.clone(),
            mode: policy.mode, // MtaStsMode is Copy
            mx_patterns: mx_arc.clone(),
            last_id_check: Instant::now(),
            valid_until,
        };
        // NOTE: guard dropped immediately after insert — no await follows.
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(rcpt_domain.to_owned(), entry);

        Some((policy.mode, mx_arc))
    }

    /// Return a clone of the shared TLSRPT recorder for this enforcer.
    ///
    /// Callers hold the `Arc` to read accumulated failure records for
    /// RFC 8460 report generation without requiring a reference to the enforcer.
    pub fn tlsrpt_recorder(&self) -> Arc<TlsrptRecorder> {
        self.tlsrpt.clone()
    }

    /// Seed the cache directly (test helper only).
    #[cfg(test)]
    pub fn seed_cache(
        &self,
        domain: &str,
        policy_id: &str,
        mode: MtaStsMode,
        mx_patterns: Vec<String>,
        max_age_secs: u64,
    ) {
        let valid_until = Instant::now() + Duration::from_secs(max_age_secs);
        let entry = CachedStsEntry {
            policy_id: policy_id.to_owned(),
            mode,
            mx_patterns: Arc::new(mx_patterns),
            last_id_check: Instant::now(),
            valid_until,
        };
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(domain.to_owned(), entry);
    }
}

/// Wraps either a plain TCP stream or a TLS stream so that a single concrete
/// type implements both [`AsyncRead`] and [`AsyncWrite`].  Using an enum here
/// avoids the heap allocation that `Box<dyn AsyncRead + …>` requires.
#[pin_project(project = TlsOrPlainProj)]
// TlsStream<TcpStream> is ~8 KiB; TcpStream is ~24 bytes.  An enum here avoids
// a heap allocation per connection that Box<dyn AsyncRead+AsyncWrite> would require.
#[allow(clippy::large_enum_variant)]
enum TlsOrPlain {
    Plain(#[pin] TcpStream),
    Tls(#[pin] tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for TlsOrPlain {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            TlsOrPlainProj::Plain(s) => s.poll_read(cx, buf),
            TlsOrPlainProj::Tls(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsOrPlain {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            TlsOrPlainProj::Plain(s) => s.poll_write(cx, buf),
            TlsOrPlainProj::Tls(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TlsOrPlainProj::Plain(s) => s.poll_flush(cx),
            TlsOrPlainProj::Tls(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TlsOrPlainProj::Plain(s) => s.poll_shutdown(cx),
            TlsOrPlainProj::Tls(s) => s.poll_shutdown(cx),
        }
    }
}

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// RFC 5321 §4.5.3.1.5 — maximum reply line length is 512 octets including CRLF.
const MAX_SMTP_LINE: usize = 512;

/// SMTP envelope for relay delivery.
#[derive(Debug, Clone)]
pub struct RelayEnvelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    /// When `true` the sender included `REQUIRETLS` in the MAIL FROM command
    /// (RFC 8689 §2).  The outbound relay MUST:
    ///
    /// 1. Connect over TLS (`peer.tls` must be `true`).
    /// 2. Verify the remote MTA advertised `REQUIRETLS` in its EHLO response.
    /// 3. Append the `REQUIRETLS` parameter to the forwarded MAIL FROM command.
    ///
    /// If either TLS condition is not met the delivery fails permanently
    /// (RFC 8689 §5).
    pub require_tls: bool,
}

/// Deliver an article to a relay peer via SMTP.
///
/// Wraps [`do_deliver`] with a 30-second overall timeout.
///
/// `local_hostname` is used as the EHLO domain (RFC 5321 §4.1.1.1).  Pass the
/// operator-configured `config.hostname`; a bare label is rejected by many
/// servers.  An empty string falls back to `"localhost"`.
///
/// `mta_sts` — optional MTA-STS enforcer.  When `Some`, MTA-STS policy is
/// checked for every unique recipient domain before connecting.  Pass `None`
/// to skip enforcement (e.g. when MTA-STS checking is disabled in config).
///
/// Returns [`SmtpRelayError::Permanent`] immediately if `envelope.rcpt_to` is
/// empty; RFC 5321 §3.3 requires at least one RCPT TO before DATA.
pub async fn deliver_via_relay(
    peer: &SmtpRelayPeerConfig,
    envelope: &RelayEnvelope,
    article_bytes: &[u8],
    local_hostname: &str,
    mta_sts: Option<&MtaStsEnforcer>,
) -> Result<(), SmtpRelayError> {
    if envelope.rcpt_to.is_empty() {
        return Err(SmtpRelayError::Permanent(
            "no recipients in envelope".to_string(),
        ));
    }
    timeout(
        OPERATION_TIMEOUT,
        do_deliver(peer, envelope, article_bytes, local_hostname, mta_sts),
    )
    .await
    .map_err(|_| {
        SmtpRelayError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SMTP relay delivery timed out after 30 seconds",
        ))
    })?
}

/// Extract the domain part of an email address.
fn recipient_domain(addr: &str) -> Option<&str> {
    addr.rsplit_once('@').map(|(_, domain)| domain)
}

async fn do_deliver(
    peer: &SmtpRelayPeerConfig,
    envelope: &RelayEnvelope,
    article_bytes: &[u8],
    local_hostname: &str,
    mta_sts: Option<&MtaStsEnforcer>,
) -> Result<(), SmtpRelayError> {
    // Early guard: REQUIRETLS requires TLS — check before TCP connect so
    // unit tests can verify this path without a live server.
    if envelope.require_tls && !peer.tls {
        return Err(SmtpRelayError::Permanent(
            "REQUIRETLS requested but relay.tls is false; \
             refusing to relay a REQUIRETLS message over a plaintext connection"
                .to_string(),
        ));
    }

    // MTA-STS enforcement (RFC 8461 §4): check all recipient domains before
    // TCP connect so a policy violation in enforce mode never touches the peer.
    // Deduplicate domains to avoid redundant DNS/cache lookups.
    if let Some(enforcer) = mta_sts {
        let tls_status = if peer.tls {
            PeerTlsStatus::Connected
        } else {
            PeerTlsStatus::Plain
        };
        let mut seen = std::collections::HashSet::new();
        for rcpt in &envelope.rcpt_to {
            if let Some(domain) = recipient_domain(rcpt) {
                if seen.insert(domain) {
                    enforcer
                        .enforce_for_delivery(domain, &peer.host, tls_status)
                        .await?;
                }
            }
        }
    }

    let tcp = TcpStream::connect(peer.host_port())
        .await
        .map_err(SmtpRelayError::Io)?;

    let stream: TlsOrPlain = if peer.tls {
        TlsOrPlain::Tls(tls_wrap(tcp, &peer.host).await?)
    } else {
        TlsOrPlain::Plain(tcp)
    };

    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);

    run_smtp_session(
        &mut reader,
        &mut wr,
        peer,
        envelope,
        article_bytes,
        local_hostname,
    )
    .await
}

/// Shared TLS client config built once per process.
///
/// Root CAs come from `webpki_roots`; the ring crypto provider is installed
/// before the config is constructed.  Building `ClientConfig` (including the
/// `RootCertStore` population) is expensive; sharing this across connections
/// avoids repeating that work on every outbound TLS handshake.
static TLS_CLIENT_CONFIG: std::sync::LazyLock<Arc<rustls::ClientConfig>> =
    std::sync::LazyLock::new(|| {
        // LazyLock already guarantees single execution — no OnceLock needed here.
        if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
            // Only fails if a provider was already installed — not fatal,
            // but indicates a programming mistake (double-init).
            tracing::warn!("rustls crypto provider already installed: {e:?}");
        }
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    });

/// Wrap a plain TCP stream with TLS using webpki root CAs.
async fn tls_wrap(
    tcp: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SmtpRelayError> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(&TLS_CLIENT_CONFIG));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| SmtpRelayError::TlsHandshake(format!("invalid hostname: {e}")))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| SmtpRelayError::TlsHandshake(e.to_string()))
}

/// Run the SMTP session over already-established reader/writer halves.
async fn run_smtp_session(
    reader: &mut BufReader<tokio::io::ReadHalf<TlsOrPlain>>,
    writer: &mut tokio::io::WriteHalf<TlsOrPlain>,
    peer: &SmtpRelayPeerConfig,
    envelope: &RelayEnvelope,
    article_bytes: &[u8],
    local_hostname: &str,
) -> Result<(), SmtpRelayError> {
    let mut line = String::new();

    // 1. Read server greeting — expect 220.
    // RFC 5321 §4.2: a server MAY send a multi-line greeting (220-text\r\n …
    // 220 text\r\n).  Drain all continuation lines (code + '-') before
    // treating the final line (code + ' ') as the definitive response.
    // Failing to drain leaves banner lines in the buffer where they would be
    // misinterpreted as responses to subsequent commands.
    loop {
        read_line(reader, &mut line).await?;
        let (code, cont, _text) = parse_smtp_line(&line)?;
        if cont {
            // Still in the multi-line greeting; keep reading.
            if code != 220 {
                return Err(SmtpRelayError::Permanent(format!(
                    "unexpected greeting code {code} in continuation: {}",
                    line.trim_end()
                )));
            }
            continue;
        }
        match code {
            220 => break,
            400..=499 => {
                return Err(SmtpRelayError::Transient(format!(
                    "greeting {code}: {}",
                    line.trim_end()
                )))
            }
            _ => {
                return Err(SmtpRelayError::Permanent(format!(
                    "greeting {code}: {}",
                    line.trim_end()
                )))
            }
        }
    }

    // 2. EHLO — RFC 5321 §4.1.1.1 requires an FQDN; use the operator-configured
    // hostname.  Fall back to "localhost" if the caller passes an empty string.
    let ehlo_domain = if local_hostname.is_empty() {
        "localhost"
    } else {
        local_hostname
    };
    let ehlo_cmd = format!("EHLO {ehlo_domain}\r\n");
    writer
        .write_all(ehlo_cmd.as_bytes())
        .await
        .map_err(SmtpRelayError::Io)?;

    // Read multi-line EHLO response; collect extension keywords.
    // RFC 5321 §4.1.1.1: the first response line is "250[-]Domain [greeting]"
    // — only continuation lines carry extension keywords.
    let mut extensions: Vec<String> = Vec::new();
    let mut ehlo_first = true;
    loop {
        line.clear();
        read_line(reader, &mut line).await?;
        let (code, cont, text) = parse_smtp_line(&line)?;
        if code / 100 == 5 {
            return Err(SmtpRelayError::Permanent(format!(
                "EHLO rejected {code}: {}",
                line.trim_end()
            )));
        }
        if code / 100 == 4 {
            return Err(SmtpRelayError::Transient(format!(
                "EHLO transient {code}: {}",
                line.trim_end()
            )));
        }
        // Skip the first line (domain greeting); push only extension keywords.
        if !ehlo_first {
            extensions.push(text.to_ascii_uppercase());
        }
        ehlo_first = false;
        if !cont {
            break;
        }
    }

    // 3. REQUIRETLS check (RFC 8689 §5).
    //
    // The pre-connect guard in do_deliver already ensured peer.tls=true when
    // require_tls=true, so the only remaining check here is that the remote MTA
    // advertised REQUIRETLS in its EHLO response.
    if envelope.require_tls {
        let advertises_requiretls = extensions.iter().any(|e| e == "REQUIRETLS");
        if !advertises_requiretls {
            return Err(SmtpRelayError::Permanent(
                "REQUIRETLS requested but peer did not advertise REQUIRETLS in EHLO".to_string(),
            ));
        }
    }

    // 4. AUTH PLAIN (if credentials configured).
    if let (Some(username), Some(password)) = (&peer.username, &peer.password) {
        // Refuse to send AUTH PLAIN over a plaintext connection.  SASL PLAIN
        // credentials are base64-encoded, not encrypted; sending them without
        // TLS exposes them on the wire.
        if !peer.tls {
            return Err(SmtpRelayError::Permanent(
                "AUTH credentials are configured but relay.tls is false; \
                 refusing to send credentials over a plaintext connection"
                    .to_string(),
            ));
        }

        // Check that peer advertised AUTH.
        let advertises_auth = extensions
            .iter()
            .any(|e| e == "AUTH" || e.starts_with("AUTH "));
        if !advertises_auth {
            return Err(SmtpRelayError::Permanent(
                "peer did not advertise AUTH but credentials are configured".to_string(),
            ));
        }

        // SASL PLAIN: \0authcid\0passwd  (authzid is empty)
        // NEVER log this value.
        let sasl_plain = {
            let mut buf = Vec::with_capacity(1 + username.len() + 1 + password.len());
            buf.push(0u8);
            buf.extend_from_slice(username.as_bytes());
            buf.push(0u8);
            buf.extend_from_slice(password.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(&buf)
        };

        let auth_cmd = format!("AUTH PLAIN {sasl_plain}\r\n");
        writer
            .write_all(auth_cmd.as_bytes())
            .await
            .map_err(SmtpRelayError::Io)?;

        line.clear();
        read_line(reader, &mut line).await?;
        let (code, _cont, _text) = parse_smtp_line(&line)?;
        match code {
            235 => {}
            535 => return Err(SmtpRelayError::AuthFailed),
            400..=499 => {
                return Err(SmtpRelayError::Transient(format!(
                    "AUTH transient {code}: {}",
                    line.trim_end()
                )))
            }
            _ => {
                return Err(SmtpRelayError::Permanent(format!(
                    "AUTH failed {code}: {}",
                    line.trim_end()
                )))
            }
        }
    }

    // 5. MAIL FROM
    // Validate the address before interpolating it into MAIL FROM:<...>.
    // Angle brackets are not valid inside an RFC 5321 mailbox address; their
    // presence would prematurely close the angle-bracket argument and allow
    // SMTP command injection (e.g. "> RCPT TO:attacker@evil.com\r\n").
    // CR and LF are also rejected for belt-and-suspenders.
    if envelope.mail_from.contains('\r')
        || envelope.mail_from.contains('\n')
        || envelope.mail_from.contains('<')
        || envelope.mail_from.contains('>')
    {
        return Err(SmtpRelayError::Permanent(format!(
            "MAIL FROM address contains invalid character: {:?}",
            envelope.mail_from
        )));
    }
    let mail_from_cmd = if envelope.require_tls {
        format!("MAIL FROM:<{}> REQUIRETLS\r\n", envelope.mail_from)
    } else {
        format!("MAIL FROM:<{}>\r\n", envelope.mail_from)
    };
    writer
        .write_all(mail_from_cmd.as_bytes())
        .await
        .map_err(SmtpRelayError::Io)?;

    line.clear();
    read_line(reader, &mut line).await?;
    let (code, _cont, _text) = parse_smtp_line(&line)?;
    check_250(code, &line, "MAIL FROM")?;

    // 6. RCPT TO (one per recipient)
    for addr in &envelope.rcpt_to {
        // Validate address before interpolating into RCPT TO:<...>.
        // '<' and '>' are not valid in RFC 5321 mailbox addresses; their
        // presence indicates a malformed or injected value that would
        // prematurely terminate the angle-bracket argument and allow SMTP
        // command injection.  CR/LF are also stripped for belt-and-suspenders.
        if addr.contains('>') || addr.contains('<') || addr.contains('\r') || addr.contains('\n') {
            return Err(SmtpRelayError::Permanent(format!(
                "recipient address contains invalid character: {addr:?}"
            )));
        }
        let rcpt_cmd = format!("RCPT TO:<{addr}>\r\n");
        writer
            .write_all(rcpt_cmd.as_bytes())
            .await
            .map_err(SmtpRelayError::Io)?;

        line.clear();
        read_line(reader, &mut line).await?;
        let (code, _cont, _text) = parse_smtp_line(&line)?;
        check_250(code, &line, "RCPT TO")?;
    }

    // 7. DATA
    writer
        .write_all(b"DATA\r\n")
        .await
        .map_err(SmtpRelayError::Io)?;

    line.clear();
    read_line(reader, &mut line).await?;
    let (code, _cont, _text) = parse_smtp_line(&line)?;
    match code {
        354 => {}
        400..=499 => {
            return Err(SmtpRelayError::Transient(format!(
                "DATA {code}: {}",
                line.trim_end()
            )))
        }
        _ => {
            return Err(SmtpRelayError::Permanent(format!(
                "DATA {code}: {}",
                line.trim_end()
            )))
        }
    }

    // 8. Dot-stuffed article body + terminator.
    // RFC 5321 §4.5.2 dot-stuffing is byte-for-byte identical to RFC 3977 §3.1.1
    // NNTP dot-stuffing: prefix every line that begins with '.' with an extra '.'.
    let stuffed = nntp_dot_stuff(article_bytes);
    writer
        .write_all(&stuffed)
        .await
        .map_err(SmtpRelayError::Io)?;
    // nntp_dot_stuff always ends its output with \r\n, so we only need
    // the bare ".\r\n" terminator.  Appending "\r\n.\r\n" would produce an
    // extra blank line in the received message body (RFC 5321 §4.1.1.4).
    writer
        .write_all(b".\r\n")
        .await
        .map_err(SmtpRelayError::Io)?;
    writer.flush().await.map_err(SmtpRelayError::Io)?;

    // 9. Read acceptance response.
    line.clear();
    read_line(reader, &mut line).await?;
    let (code, _cont, _text) = parse_smtp_line(&line)?;
    check_250(code, &line, "DATA body")?;

    // 10. QUIT (best-effort).
    let _ = writer.write_all(b"QUIT\r\n").await;

    Ok(())
}

/// Read one line from the SMTP server, enforcing the RFC 5321 line-length limit.
async fn read_line(
    reader: &mut BufReader<tokio::io::ReadHalf<TlsOrPlain>>,
    line: &mut String,
) -> Result<(), SmtpRelayError> {
    line.clear();
    reader.read_line(line).await.map_err(SmtpRelayError::Io)?;
    // RFC 5321 §4.5.3.1.5: reply line limit is 512 bytes including CRLF.
    // read_line includes the trailing '\n', so a valid 512-byte line has
    // len() == 512.  Use > (not >=) to accept the maximum valid length.
    if line.len() > MAX_SMTP_LINE {
        return Err(SmtpRelayError::ProtocolError(format!(
            "server response line exceeds {} bytes",
            MAX_SMTP_LINE
        )));
    }
    if line.is_empty() {
        return Err(SmtpRelayError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed by peer",
        )));
    }
    Ok(())
}

/// Map a non-250 response code to an appropriate error.
fn check_250(code: u16, line: &str, context: &str) -> Result<(), SmtpRelayError> {
    match code {
        250 => Ok(()),
        400..=499 => Err(SmtpRelayError::Transient(format!(
            "{context} {code}: {}",
            line.trim_end()
        ))),
        _ => Err(SmtpRelayError::Permanent(format!(
            "{context} {code}: {}",
            line.trim_end()
        ))),
    }
}

/// Parse one SMTP response line.
///
/// Returns `(code, is_continuation, text)`.  `is_continuation` is `true`
/// when the separator character is `-` (multi-line response; more lines
/// follow).  Returns `Err(ProtocolError)` if the line is malformed.
///
/// The 512-byte line limit is enforced by [`read_line`]; callers that
/// construct synthetic lines for unit tests bypass that check deliberately.
fn parse_smtp_line(line: &str) -> Result<(u16, bool, &str), SmtpRelayError> {
    // Enforce an absolute sanity limit even for synthetic callers.
    // RFC 5321 §4.5.3.1.5: reply line limit is 512 bytes including CRLF.
    // Use > (not >=) to match read_line and accept the maximum valid length.
    if line.len() > MAX_SMTP_LINE {
        return Err(SmtpRelayError::ProtocolError(format!(
            "response line exceeds {} bytes",
            MAX_SMTP_LINE
        )));
    }

    // Minimum: "XYZ " or "XYZ\r\n" (4 chars: 3 digits + separator).
    if line.len() < 4 {
        return Err(SmtpRelayError::ProtocolError(format!(
            "response line too short: {:?}",
            line
        )));
    }

    let code_str = &line[..3];
    if !code_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(SmtpRelayError::ProtocolError(format!(
            "non-numeric response code: {:?}",
            code_str
        )));
    }

    let code: u16 = code_str.parse().map_err(|_| {
        SmtpRelayError::ProtocolError(format!("unparseable response code: {:?}", code_str))
    })?;

    let sep = line.as_bytes()[3];
    let is_continuation = sep == b'-';
    if sep != b' ' && sep != b'-' && sep != b'\r' && sep != b'\n' {
        return Err(SmtpRelayError::ProtocolError(format!(
            "invalid separator byte 0x{:02x} after code",
            sep
        )));
    }

    let text = line[4..].trim_end_matches(['\r', '\n']);
    Ok((code, is_continuation, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ---- nntp_dot_stuff (SMTP dot-stuffing) ----
    // Oracle: RFC 5321 §4.5.2 — lines beginning with '.' receive an extra '.'.

    #[test]
    fn dot_stuff_prepends_dot_to_dot_lines() {
        let input = b".hello\r\nworld\r\n";
        let output = nntp_dot_stuff(input);
        assert_eq!(&output, b"..hello\r\nworld\r\n");
    }

    #[test]
    fn dot_stuff_leaves_non_dot_lines_unchanged() {
        let input = b"hello\r\nworld\r\n";
        let output = nntp_dot_stuff(input);
        assert_eq!(&output, input.as_ref());
    }

    #[test]
    fn dot_stuff_handles_multiple_dot_lines() {
        let input = b".a\r\nb\r\n.c\r\n";
        let output = nntp_dot_stuff(input);
        assert_eq!(&output, b"..a\r\nb\r\n..c\r\n");
    }

    #[test]
    fn dot_stuff_empty_input() {
        assert_eq!(nntp_dot_stuff(b""), b"");
    }

    #[test]
    fn dot_stuff_dot_not_at_line_start() {
        let input = b"hello.world\r\n";
        let output = nntp_dot_stuff(input);
        assert_eq!(&output, input.as_ref());
    }

    #[test]
    fn dot_stuff_leading_dot_first_line() {
        let input = b".first\r\nnormal\r\n";
        let output = nntp_dot_stuff(input);
        assert_eq!(&output, b"..first\r\nnormal\r\n");
    }

    // ---- parse_smtp_line ----
    // Oracle: RFC 5321 §4.2 — reply format is 3-digit code + SP/hyphen + text.

    #[test]
    fn parse_smtp_line_ok_250() {
        let (code, cont, text) = parse_smtp_line("250 OK\r\n").unwrap();
        assert_eq!(code, 250);
        assert!(!cont);
        assert_eq!(text, "OK");
    }

    #[test]
    fn parse_smtp_line_continuation() {
        let (code, cont, text) = parse_smtp_line("250-PIPELINING\r\n").unwrap();
        assert_eq!(code, 250);
        assert!(cont);
        assert_eq!(text, "PIPELINING");
    }

    #[test]
    fn parse_smtp_line_220_greeting() {
        let (code, cont, _text) = parse_smtp_line("220 mail.example.com ESMTP\r\n").unwrap();
        assert_eq!(code, 220);
        assert!(!cont);
    }

    #[test]
    fn parse_smtp_line_rejects_non_digit_code() {
        let err = parse_smtp_line("xyz OK\r\n").unwrap_err();
        assert!(matches!(err, SmtpRelayError::ProtocolError(_)));
    }

    #[test]
    fn parse_smtp_line_rejects_too_short() {
        let err = parse_smtp_line("25\r\n").unwrap_err();
        assert!(matches!(err, SmtpRelayError::ProtocolError(_)));
    }

    #[test]
    fn parse_smtp_line_rejects_too_long() {
        let long_line = "250 ".to_string() + &"x".repeat(510);
        let err = parse_smtp_line(&long_line).unwrap_err();
        assert!(matches!(err, SmtpRelayError::ProtocolError(_)));
    }

    #[test]
    fn parse_smtp_line_exactly_512_bytes_is_accepted() {
        // 512 bytes is the RFC 5321 §4.5.3.1.5 maximum (including CRLF).
        // A line of exactly 512 bytes must be accepted, not rejected.
        let line = "250 ".to_string() + &"x".repeat(508); // 4 + 508 = 512
        let (code, cont, _text) = parse_smtp_line(&line).unwrap();
        assert_eq!(code, 250);
        assert!(!cont);
    }

    #[test]
    fn parse_smtp_line_511_bytes_is_accepted() {
        // 511 bytes is under the limit (MAX_SMTP_LINE=512, > is the comparison).
        let line = "250 ".to_string() + &"x".repeat(507); // 4 + 507 = 511
        let (code, cont, _text) = parse_smtp_line(&line).unwrap();
        assert_eq!(code, 250);
        assert!(!cont);
    }

    // ---- full delivery: mock SMTP server, no auth ----

    #[tokio::test]
    async fn deliver_to_mock_smtp_server_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            conn.write_all(b"220 mock.smtp.test ESMTP\r\n")
                .await
                .unwrap();

            // EHLO
            let n = conn.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(cmd.starts_with("EHLO"), "expected EHLO, got: {cmd}");
            conn.write_all(b"250-mock.smtp.test\r\n250 OK\r\n")
                .await
                .unwrap();

            // MAIL FROM
            let n = conn.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(
                cmd.starts_with("MAIL FROM"),
                "expected MAIL FROM, got: {cmd}"
            );
            conn.write_all(b"250 OK\r\n").await.unwrap();

            // RCPT TO
            let n = conn.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(cmd.starts_with("RCPT TO"), "expected RCPT TO, got: {cmd}");
            conn.write_all(b"250 OK\r\n").await.unwrap();

            // DATA
            let n = conn.read(&mut buf).await.unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(cmd.starts_with("DATA"), "expected DATA, got: {cmd}");
            conn.write_all(b"354 Start mail input\r\n").await.unwrap();

            // Read until \r\n.\r\n
            let mut body: Vec<u8> = Vec::new();
            loop {
                let n = conn.read(&mut buf).await.unwrap();
                assert!(n > 0, "connection closed before DATA terminator");
                body.extend_from_slice(&buf[..n]);
                if body.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }
            conn.write_all(b"250 OK\r\n").await.unwrap();

            // QUIT (best-effort read)
            let _ = conn.read(&mut buf).await;
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            require_tls: false,
        };
        let article =
            b"From: from@example.com\r\nTo: to@example.com\r\nSubject: test\r\n\r\nHello\r\n";

        let result = deliver_via_relay(&peer, &envelope, article, "test.example.com", None).await;
        assert!(result.is_ok(), "delivery failed: {:?}", result.err());

        server.await.unwrap();
    }

    // ---- credentials over plaintext are rejected before AUTH is sent ----
    //
    // When tls=false and credentials are configured, deliver_via_relay must
    // return Permanent("refusing...") without sending AUTH PLAIN on the wire.
    // The mock only needs to handle EHLO; the client disconnects after that.

    #[tokio::test]
    async fn deliver_credentials_rejected_over_plaintext() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            conn.write_all(b"220 mock.smtp.test ESMTP\r\n")
                .await
                .unwrap();

            // EHLO — advertise AUTH PLAIN
            let _ = conn.read(&mut buf).await; // EHLO (best-effort; client disconnects after this)
            let _ = conn
                .write_all(b"250-mock.smtp.test\r\n250-AUTH PLAIN\r\n250 OK\r\n")
                .await;
            // Client disconnects here; any further reads return EOF.
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: Some("relay".to_string()),
            password: Some("secret".to_string()),
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            require_tls: false,
        };
        let article = b"From: from@example.com\r\nSubject: test\r\n\r\nBody\r\n";

        let result = deliver_via_relay(&peer, &envelope, article, "test.example.com", None).await;
        assert!(
            matches!(&result, Err(SmtpRelayError::Permanent(m)) if m.contains("refusing")),
            "expected Permanent(refusing...), got: {:?}",
            result
        );
    }

    // ---- credentials with tls=false: Permanent before AUTH is sent ----
    //
    // Even when the server advertises AUTH PLAIN, credentials must never be
    // sent over a plaintext connection.  The error must be Permanent (not
    // Transient) so the caller does not retry endlessly.

    #[tokio::test]
    async fn deliver_credentials_plaintext_returns_permanent_not_auth_failed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            conn.write_all(b"220 mock.smtp.test ESMTP\r\n")
                .await
                .unwrap();
            let _ = conn.read(&mut buf).await; // EHLO
            let _ = conn
                .write_all(b"250-mock.smtp.test\r\n250 AUTH PLAIN\r\n")
                .await;
            // Client disconnects here; further writes will silently fail.
            let _ = conn.read(&mut buf).await;
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: Some("user".to_string()),
            password: Some("wrong".to_string()),
        };
        let envelope = RelayEnvelope {
            mail_from: "f@example.com".to_string(),
            rcpt_to: vec!["t@example.com".to_string()],
            require_tls: false,
        };

        let result =
            deliver_via_relay(&peer, &envelope, b"body\r\n", "test.example.com", None).await;
        assert!(
            matches!(&result, Err(SmtpRelayError::Permanent(m)) if m.contains("refusing")),
            "expected Permanent(refusing...), got: {:?}",
            result
        );
    }

    // ---- 5xx on MAIL FROM returns Permanent ----

    #[tokio::test]
    async fn deliver_5xx_mail_from_returns_permanent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            conn.write_all(b"220 mock.smtp.test ESMTP\r\n")
                .await
                .unwrap();
            let _ = conn.read(&mut buf).await; // EHLO
            conn.write_all(b"250 mock.smtp.test\r\n").await.unwrap();
            let _ = conn.read(&mut buf).await; // MAIL FROM
            conn.write_all(b"550 Sender not accepted\r\n")
                .await
                .unwrap();
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "bad@example.com".to_string(),
            rcpt_to: vec!["t@example.com".to_string()],
            require_tls: false,
        };

        let result =
            deliver_via_relay(&peer, &envelope, b"body\r\n", "test.example.com", None).await;
        assert!(
            matches!(result, Err(SmtpRelayError::Permanent(_))),
            "expected Permanent, got: {:?}",
            result
        );
    }

    // ---- 4xx on RCPT TO returns Transient ----

    #[tokio::test]
    async fn deliver_4xx_rcpt_to_returns_transient() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];

            conn.write_all(b"220 mock.smtp.test ESMTP\r\n")
                .await
                .unwrap();
            let _ = conn.read(&mut buf).await; // EHLO
            conn.write_all(b"250 mock.smtp.test\r\n").await.unwrap();
            let _ = conn.read(&mut buf).await; // MAIL FROM
            conn.write_all(b"250 OK\r\n").await.unwrap();
            let _ = conn.read(&mut buf).await; // RCPT TO
            conn.write_all(b"452 Too many recipients\r\n")
                .await
                .unwrap();
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "f@example.com".to_string(),
            rcpt_to: vec!["t@example.com".to_string()],
            require_tls: false,
        };

        let result =
            deliver_via_relay(&peer, &envelope, b"body\r\n", "test.example.com", None).await;
        assert!(
            matches!(result, Err(SmtpRelayError::Transient(_))),
            "expected Transient, got: {:?}",
            result
        );
    }

    // ---- dot-stuffed content reaches the server ----

    #[tokio::test]
    async fn deliver_dot_stuffed_article_arrives_correctly() {
        use tokio::io::AsyncBufReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // The server uses a BufReader to read commands line-by-line, avoiding the
        // command-batching problem that arises with raw read() calls.
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = tokio::io::split(conn);
            let mut reader = tokio::io::BufReader::new(rd);
            let mut line = String::new();

            wr.write_all(b"220 mock.smtp.test ESMTP\r\n").await.unwrap();

            // EHLO
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("EHLO"), "expected EHLO, got: {line}");
            wr.write_all(b"250 mock.smtp.test\r\n").await.unwrap();

            // MAIL FROM
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(
                line.starts_with("MAIL FROM"),
                "expected MAIL FROM, got: {line}"
            );
            wr.write_all(b"250 OK\r\n").await.unwrap();

            // RCPT TO
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("RCPT TO"), "expected RCPT TO, got: {line}");
            wr.write_all(b"250 OK\r\n").await.unwrap();

            // DATA command
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("DATA"), "expected DATA, got: {line}");
            wr.write_all(b"354 Start mail input\r\n").await.unwrap();

            // Read body bytes until \r\n.\r\n terminator.
            let mut body: Vec<u8> = Vec::new();
            let mut tmp_buf = [0u8; 4096];
            loop {
                let n = reader.read(&mut tmp_buf).await.unwrap();
                assert!(n > 0, "connection closed before DATA terminator");
                body.extend_from_slice(&tmp_buf[..n]);
                if body.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }

            // The article line starting with '.' must have been double-dotted.
            // Oracle: RFC 5321 §4.5.2 — ".signature\r\n" → "..signature\r\n" (13 bytes)
            assert!(
                body.windows(13).any(|w| w == b"..signature\r\n"),
                "expected dot-stuffed '..signature' in body, got: {:?}",
                String::from_utf8_lossy(&body)
            );
            // No spurious blank line before the DATA terminator.
            // Oracle: RFC 5321 §4.1.1.4 — the leading CRLF of <CRLF>.<CRLF> is
            // the body's last line-ending, not an extra blank line.  Appending
            // "\r\n.\r\n" when the body already ends in "\r\n" produces the
            // sequence "\r\n\r\n.\r\n", which inserts an unwanted blank line.
            assert!(
                !body.windows(7).any(|w| w == b"\r\n\r\n.\r\n"),
                "spurious blank line found before DATA terminator: {:?}",
                String::from_utf8_lossy(&body)
            );
            wr.write_all(b"250 OK\r\n").await.unwrap();

            // QUIT (best-effort read)
            line.clear();
            let _ = reader.read_line(&mut line).await;
        });

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "f@example.com".to_string(),
            rcpt_to: vec!["t@example.com".to_string()],
            require_tls: false,
        };
        // Article with a dot-line that must be stuffed per RFC 5321 §4.5.2.
        let article = b"Subject: test\r\n\r\nnormal line\r\n.signature\r\n";

        let result = deliver_via_relay(&peer, &envelope, article, "test.example.com", None).await;
        assert!(result.is_ok(), "delivery failed: {:?}", result.err());

        server.await.unwrap();
    }

    // ---- empty rcpt_to: rejected before TCP connection ----
    // Oracle: RFC 5321 §3.3 — at least one RCPT TO is required before DATA.

    #[tokio::test]
    async fn deliver_with_empty_rcpt_to_returns_permanent_error() {
        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: 9999, // no server — must not connect
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec![],
            require_tls: false,
        };
        let result =
            deliver_via_relay(&peer, &envelope, b"article", "test.example.com", None).await;
        assert!(
            matches!(result, Err(SmtpRelayError::Permanent(_))),
            "expected Permanent error for empty rcpt_to, got: {:?}",
            result
        );
    }

    // ---- REQUIRETLS: plaintext connection is rejected (RFC 8689 §5) ----
    //
    // When require_tls=true and peer.tls=false, the relay guard must return
    // Permanent before attempting a TCP connection.

    #[tokio::test]
    async fn requiretls_rejected_over_plaintext_connection() {
        let peer = crate::config::SmtpRelayPeerConfig {
            host: "127.0.0.1".to_string(),
            port: 9999, // no server needed — must fail before TCP
            tls: false,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            require_tls: true,
        };
        let result =
            deliver_via_relay(&peer, &envelope, b"article", "test.example.com", None).await;
        assert!(
            matches!(&result, Err(SmtpRelayError::Permanent(m)) if m.contains("REQUIRETLS")),
            "expected Permanent(REQUIRETLS...), got: {:?}",
            result
        );
    }

    // ── stoa-2xeks.23: MTA-STS enforcement wiring ────────────────────────────

    // T1: enforce mode + MX mismatch → Permanent before TCP connect.
    // Oracle: RFC 8461 §4 — if peer host is not listed in the MTA-STS MX
    // patterns and mode=enforce, the delivery MUST fail permanently; the TCP
    // connection must never be opened.
    //
    // The test pre-seeds the enforcer cache to avoid a live DNS/HTTPS call.
    // Port 9999 has no listener, so any TCP connect would timeout; the test
    // verifies that the error is returned *before* the connection attempt
    // (no timeout needed).
    #[tokio::test]
    async fn mta_sts_enforce_mx_mismatch_returns_permanent() {
        let enforcer = MtaStsEnforcer::new(5_000, 65_536).expect("MtaStsEnforcer init");
        enforcer.seed_cache(
            "example.com",
            "testpolicyid",
            crate::config::MtaStsMode::Enforce,
            vec!["mail.example.com".to_string()],
            86_400,
        );

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "evil.attacker.com".to_string(), // not in MX policy
            port: 9999,                            // no listener — must fail before TCP connect
            tls: true,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            require_tls: false,
        };

        let result = deliver_via_relay(
            &peer,
            &envelope,
            b"article",
            "test.example.com",
            Some(&enforcer),
        )
        .await;
        assert!(
            matches!(&result, Err(SmtpRelayError::Permanent(m)) if m.contains("MTA-STS enforce")),
            "expected Permanent(MTA-STS enforce), got: {:?}",
            result
        );
    }

    // T2: enforce mode + MX matches + no live server → connect error (not MTA-STS error).
    // Oracle: RFC 8461 §4 — when the peer host IS in the MX policy, MTA-STS
    // enforcement passes and delivery proceeds to the TCP connect.  With no
    // listener the result is an I/O error, proving that enforcement did not
    // block delivery.
    #[tokio::test]
    async fn mta_sts_enforce_mx_matches_proceeds_to_connect() {
        let enforcer = MtaStsEnforcer::new(5_000, 65_536).expect("MtaStsEnforcer init");
        enforcer.seed_cache(
            "example.com",
            "testpolicyid",
            crate::config::MtaStsMode::Enforce,
            vec!["mail.example.com".to_string()],
            86_400,
        );

        let peer = crate::config::SmtpRelayPeerConfig {
            host: "mail.example.com".to_string(), // matches policy
            port: 9999,                           // no listener — connect will fail with I/O error
            tls: true,
            username: None,
            password: None,
        };
        let envelope = RelayEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            require_tls: false,
        };

        let result = deliver_via_relay(
            &peer,
            &envelope,
            b"article",
            "test.example.com",
            Some(&enforcer),
        )
        .await;
        // Must not be a MTA-STS error; connection failure (Io or Permanent TCP)
        // proves we got past enforcement.
        assert!(
            !matches!(&result, Err(SmtpRelayError::Permanent(m)) if m.contains("MTA-STS")),
            "MTA-STS enforcement must not block when MX matches; got: {:?}",
            result
        );
    }

    // T3: testing mode + MX mismatch → delivery is allowed (log only, no block).
    // Oracle: RFC 8461 §4.2 — in testing mode policy failures MUST NOT block
    // delivery; they are reported but do not cause a permanent error.
    #[tokio::test]
    async fn mta_sts_testing_mode_mx_mismatch_allows_delivery() {
        let enforcer = MtaStsEnforcer::new(5_000, 65_536).expect("MtaStsEnforcer init");
        enforcer.seed_cache(
            "example.com",
            "testpolicyid",
            crate::config::MtaStsMode::Testing,
            vec!["mail.example.com".to_string()],
            86_400,
        );

        // With testing mode, the MTA-STS check must not return an error even
        // though the peer is not in the policy.  We verify this by calling
        // enforce_for_delivery directly (no live server needed).
        let result = enforcer
            .enforce_for_delivery("example.com", "evil.attacker.com", PeerTlsStatus::Connected)
            .await;
        assert!(
            result.is_ok(),
            "testing mode must not block delivery; got: {:?}",
            result
        );
    }
}
