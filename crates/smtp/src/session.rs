use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;

use crate::dns_cache::DnsCache;
use crate::tls::TlsAcceptor;
use stoa_auth::CredentialStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use stoa_core::util::epoch_to_rfc2822;

use stoa_core::InjectionSource;

use crate::auth::verify_inbound;
use crate::config::Config;
use crate::metrics::{
    SMTP_CONNECTIONS_TOTAL, SMTP_DATA_BYTES_TOTAL, SMTP_MESSAGES_ACCEPTED_TOTAL,
    SMTP_MESSAGES_REJECTED_TOTAL,
};
use crate::queue::{header_section_end, NntpQueue};
use crate::{routing, store};

/// Combined read/write trait for SMTP stream objects.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Thread-safe cache of compiled Sieve scripts, keyed by username.
///
/// Scripts are compiled on first use and retained until the sieve admin API
/// explicitly invalidates the entry (on script PUT, DELETE, or activate).
/// This avoids recompiling the same script for every inbound message.
pub type SieveCache = Arc<Mutex<HashMap<String, Arc<stoa_sieve_native::CompiledScript>>>>;

/// Create a new, empty [`SieveCache`].
pub fn new_sieve_cache() -> SieveCache {
    Arc::new(Mutex::new(HashMap::new()))
}

const MAX_LINE_BYTES: usize = 4096;

/// Normalize an IPv4-mapped IPv6 address (`::ffff:x.x.x.x`) to its IPv4 form.
///
/// Uses `to_ipv4_mapped()` not `to_ipv4()` — the latter also matches deprecated
/// IPv4-compatible addresses (`::x.x.x.x` per RFC 4291 §2.5.4), which we do NOT want.
pub(crate) fn normalize_peer_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Result of reading one SMTP command line.
enum CmdLine {
    /// A complete line, including the trailing `\n`.
    Line(String),
    /// Client closed the connection (EOF) before a full line arrived.
    Eof,
    /// The line exceeded `MAX_LINE_BYTES`.  The remainder has been drained.
    TooLong,
    /// No data was received within the configured command timeout.
    Timeout,
}

/// Read one SMTP command line with length and timeout enforcement.
///
/// Reads byte-by-byte via the `BufReader` internal buffer — no extra syscall
/// per byte because `BufReader` fills its buffer in chunks.  Returns when
/// `\n` is found, the byte limit is exceeded (and drained), the timeout
/// fires, or EOF.
async fn read_command_line<R>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
    timeout_secs: u64,
) -> CmdLine
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        let mut buf: Vec<u8> = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            match reader.read(&mut byte).await {
                Ok(0) | Err(_) => return CmdLine::Eof,
                Ok(_) => {
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        return CmdLine::Line(String::from_utf8_lossy(&buf).into_owned());
                    }
                    if buf.len() >= max_bytes {
                        // Line is too long — drain the rest without buffering
                        // so the session can send 500 and remain coherent.
                        loop {
                            match reader.read(&mut byte).await {
                                Ok(0) | Err(_) => return CmdLine::Eof,
                                Ok(_) if byte[0] == b'\n' => return CmdLine::TooLong,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(CmdLine::Timeout)
}

#[derive(Debug)]
enum SessionState {
    Fresh,
    Greeted {
        ehlo_domain: String,
    },
    Mail {
        ehlo_domain: String,
        from: String,
        require_tls: bool,
    },
    Rcpt {
        ehlo_domain: String,
        from: String,
        to: Vec<String>,
        require_tls: bool,
    },
}

#[allow(clippy::too_many_arguments)]
/// Run a complete RFC 5321 SMTP session on the given stream.
///
/// `stream` may be a plain `TcpStream` (ports 25 / 587) or a TLS-wrapped
/// stream (port 465 SMTPS).  The generic bound keeps this zero-cost while
/// allowing both stream types without boxing.
///
/// `is_tls` records whether the session was accepted on the implicit-TLS
/// SMTPS listener or has completed a STARTTLS upgrade.  AUTH PLAIN is only
/// advertised and accepted when `is_tls = true` or `is_submission = true`,
/// preventing credentials from being sent in the clear on port 25 before
/// STARTTLS negotiation (RFC 4954 §4).
///
/// `credential_store` is the pre-built store used to verify AUTH PLAIN
/// credentials.  Built once at startup from `config.auth` and shared across
/// sessions.
///
/// `auth` is optional: when `Some`, every accepted message is passed through
/// the SPF/DKIM/DMARC/ARC pipeline before enqueuing.  When `None` the message
/// is enqueued without authentication (suitable for loopback submission or
/// unit tests).
///
/// `pool` is optional: when `Some`, the global Sieve script is evaluated and
/// the result is applied for all recipients.  When `None`, all messages are
/// treated as Keep (delivered to INBOX if `mail_pool` is set).
///
/// `mail_pool` is optional: when `Some`, INBOX delivery writes into the JMAP
/// mail store instead of the smtp-local store.  Falls back to `pool` on error.
///
/// `inbox_mailbox_id` is the pre-looked-up JMAP mailbox_id for the INBOX
/// special folder.  Callers populate this once at startup (from the mail DB)
/// so `sieve_delivery` never issues a per-message `SELECT … WHERE role='inbox'`
/// query.  `None` means JMAP delivery is not configured.
///
/// `is_submission`: `true` when the connection arrived on the submission port
/// (587).  AUTH PLAIN is advertised on submission sessions even without TLS so
/// that mail clients can authenticate for demo/dev deployments without TLS.
pub async fn run_session(
    stream: Box<dyn AsyncStream>,
    is_tls: bool,
    is_submission: bool,
    peer_addr: String,
    config: Arc<Config>,
    credential_store: Arc<CredentialStore>,
    nntp_queue: Arc<NntpQueue>,
    auth: Option<Arc<MessageAuthenticator>>,
    dns_cache: Arc<DnsCache>,
    pool: Option<SqlitePool>,
    mail_pool: Option<SqlitePool>,
    sieve_cache: Option<SieveCache>,
    inbox_mailbox_id: Option<String>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    SMTP_CONNECTIONS_TOTAL.inc();

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = format!("220 {} ESMTP stoa-smtp\r\n", config.hostname);
    if write_half.write_all(greeting.as_bytes()).await.is_err() {
        return;
    }

    // Parse the peer IP once; fall back to unroutable 0.0.0.0 if unparseable.
    // 0.0.0.0 is used (not 127.0.0.1) so that a parse failure cannot silently
    // match a 127.0.0.0/8 whitelist entry.
    let client_ip: IpAddr = peer_addr
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));

    // Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4 for CIDR matching.
    let client_ip = normalize_peer_ip(client_ip);

    // When DNSBL/FCrDNS/greylisting (usenet-ipfs-1d63/fxxx/mgzn) are wired in,
    // check this flag before applying those filters.
    // NOTE: whitelisted connections still require SMTP AUTH — this flag only bypasses
    // anti-spam filters, never authentication.
    let connection_whitelisted = config
        .peer_whitelist
        .iter()
        .any(|net| net.contains(&client_ip));
    if connection_whitelisted {
        tracing::info!(peer = %peer_addr, "connection whitelisted — spam filters will be bypassed once implemented");
    }
    // connection_whitelisted will also be consumed by greylisting (usenet-ipfs-mgzn)
    // to bypass RCPT TO delay — no suppressor needed here.

    let mut state = SessionState::Fresh;
    let mut authenticated_user: Option<String> = None;
    let mut auth_failures: u8 = 0;

    loop {
        let line_buf = match read_command_line(
            &mut reader,
            MAX_LINE_BYTES,
            config.limits.command_timeout_secs,
        )
        .await
        {
            CmdLine::Line(s) => s,
            CmdLine::Eof => {
                debug!(peer = %peer_addr, "client disconnected");
                break;
            }
            CmdLine::TooLong => {
                let _ = write_half.write_all(b"500 Line too long\r\n").await;
                break;
            }
            CmdLine::Timeout => {
                // RFC 5321 §4.2: use 421 when closing due to timeout.
                let _ = write_half
                    .write_all(b"421 4.4.2 Timeout - closing connection\r\n")
                    .await;
                break;
            }
        };

        // Strip trailing CRLF or LF.
        let line = line_buf.trim_end_matches(['\r', '\n']);
        if line.to_ascii_uppercase().starts_with("AUTH ") {
            debug!(peer = %peer_addr, cmd = "AUTH <redacted>", "received");
        } else {
            debug!(peer = %peer_addr, cmd = %line, "received");
        }

        // Split verb from arguments (verb is the first whitespace-delimited token).
        let (verb, args) = match line.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((v, a)) => (v.to_ascii_uppercase(), a.trim()),
            None => (line.to_ascii_uppercase(), ""),
        };

        match verb.as_str() {
            "EHLO" => {
                // Reject EHLO arguments containing CR, LF, or NUL: these
                // would allow header injection into the Received: trace we
                // prepend at DATA time.  Per RFC 5321 §4.1.1.1 the domain
                // argument must be a valid hostname or address literal.
                if args.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                    if write_half
                        .write_all(b"501 5.5.2 Syntax error in parameters\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // RFC 3207: advertise STARTTLS when tls_acceptor is Some.
                let starttls_line = if !is_tls && tls_acceptor.is_some() {
                    "250-STARTTLS\r\n"
                } else {
                    ""
                };
                // RFC 4954 §4: AUTH MUST NOT be advertised on a cleartext
                // connection that also offers STARTTLS.  Only advertise AUTH
                // after TLS is active (is_tls) or on the submission port where
                // plaintext auth is acceptable for dev deployments (is_submission).
                // tls_acceptor.is_some() alone (pre-upgrade) is not sufficient.
                let auth_line = if (is_tls || is_submission) && !credential_store.is_empty() {
                    "250-AUTH PLAIN\r\n"
                } else {
                    ""
                };
                let requiretls_line = if is_tls { "250-REQUIRETLS\r\n" } else { "" };
                let resp = format!(
                    "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-PIPELINING\r\n{}{}{}250 OK\r\n",
                    config.hostname, config.limits.max_message_bytes, starttls_line, auth_line, requiretls_line
                );
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted {
                    ehlo_domain: args.to_string(),
                };
            }

            "HELO" => {
                if args.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                    if write_half
                        .write_all(b"501 5.5.2 Syntax error in parameters\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let resp = format!("250 {}\r\n", config.hostname);
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted {
                    ehlo_domain: args.to_string(),
                };
            }

            "AUTH" => {
                // RFC 4954 §4: reject AUTH on cleartext connections that are
                // not the submission port.  Submission (is_submission=true)
                // advertises AUTH PLAIN in EHLO even without TLS, so the
                // handler must honour it.  Only reject when the connection is
                // neither TLS nor submission.
                if !is_tls && !is_submission {
                    if tls_acceptor.is_some() {
                        let _ = write_half
                            .write_all(b"530 5.7.0 Must issue a STARTTLS command first\r\n")
                            .await;
                    } else {
                        let _ = write_half.write_all(b"534 5.7.9 Encryption required for requested authentication mechanism\r\n").await;
                    }
                    break;
                }
                if authenticated_user.is_some() {
                    if write_half
                        .write_all(b"503 5.5.1 Already authenticated\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // Only SASL PLAIN is supported.
                let mechanism_upper = args.to_ascii_uppercase();
                if mechanism_upper == "PLAIN" || mechanism_upper.starts_with("PLAIN ") {
                    let initial_response = if args.len() > 5 { args[5..].trim() } else { "" };
                    let (b64, two_step) = if initial_response.is_empty() {
                        // Two-step: send empty challenge, read response.
                        if write_half.write_all(b"334 \r\n").await.is_err() {
                            break;
                        }
                        match read_command_line(
                            &mut reader,
                            MAX_LINE_BYTES,
                            config.limits.command_timeout_secs,
                        )
                        .await
                        {
                            CmdLine::Line(s) => {
                                (s.trim_end_matches(['\r', '\n']).to_string(), true)
                            }
                            _ => {
                                let _ = write_half
                                    .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                                    .await;
                                break;
                            }
                        }
                    } else {
                        (initial_response.to_string(), false)
                    };
                    if two_step && b64 == "*" {
                        if write_half
                            .write_all(b"501 5.7.0 Authentication exchange cancelled\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    match verify_sasl_plain(&credential_store, &b64).await {
                        Some(username) => {
                            info!(peer = %peer_addr, %username, "AUTH PLAIN succeeded");
                            auth_failures = 0;
                            authenticated_user = Some(username);
                            if write_half
                                .write_all(b"235 2.7.0 Authentication successful\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            auth_failures += 1;
                            warn!(peer = %peer_addr, auth_failures, "AUTH PLAIN failed");
                            if auth_failures >= 3 {
                                let _ = write_half
                                    .write_all(b"535 5.7.8 Too many authentication failures\r\n")
                                    .await;
                                break;
                            }
                            if write_half
                                .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                } else {
                    if write_half
                        .write_all(b"504 5.5.4 Unrecognized authentication type\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }

            "MAIL" => {
                // Must be in Greeted state.
                let ehlo_domain = match &state {
                    SessionState::Greeted { ehlo_domain } => ehlo_domain.clone(),
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                // RFC 4954 §6: when AUTH is configured, require it before
                // accepting MAIL FROM.  Without this check any unauthenticated
                // client can relay mail through the submission port.
                if !credential_store.is_empty() && authenticated_user.is_none() {
                    if write_half
                        .write_all(b"530 5.7.0 Authentication required\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // RFC 8689 §2: REQUIRETLS is only valid on a TLS-protected session.
                // Reject on plaintext with 530 5.7.0 rather than silently ignoring the
                // parameter, which would let a client believe the TLS requirement was honoured.
                if has_requiretls_param(args) && !is_tls {
                    if write_half
                        .write_all(b"530 5.7.0 REQUIRETLS requires TLS\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let from = parse_angle_addr(args);
                let require_tls = has_requiretls_param(args);
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
                state = SessionState::Mail {
                    ehlo_domain,
                    from,
                    require_tls,
                };
            }

            "RCPT" => {
                let to_addr = parse_angle_addr(args);

                match state {
                    SessionState::Mail {
                        ref ehlo_domain,
                        ref from,
                        require_tls,
                    } => {
                        let ehlo_domain = ehlo_domain.clone();
                        let from_clone = from.clone();
                        if write_half.write_all(b"250 OK\r\n").await.is_err() {
                            break;
                        }
                        state = SessionState::Rcpt {
                            ehlo_domain,
                            from: from_clone,
                            to: vec![to_addr],
                            require_tls,
                        };
                    }
                    SessionState::Rcpt { ref mut to, .. } => {
                        if to.len() >= config.limits.max_recipients {
                            if write_half
                                .write_all(b"452 Too many recipients\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            to.push(to_addr);
                            if write_half.write_all(b"250 OK\r\n").await.is_err() {
                                break;
                            }
                        }
                    }
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }

            "DATA" => {
                // Must be in Rcpt state with at least one recipient.
                let (ehlo_domain, from, to, require_tls) = match state {
                    SessionState::Rcpt {
                        ref ehlo_domain,
                        ref from,
                        ref to,
                        require_tls,
                    } if !to.is_empty() => {
                        (ehlo_domain.clone(), from.clone(), to.clone(), require_tls)
                    }
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };

                if write_half
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await
                    .is_err()
                {
                    break;
                }

                // Read dot-terminated message body (with timeout).
                let max_bytes = config.limits.max_message_bytes;
                let data_result = tokio::time::timeout(
                    Duration::from_secs(config.limits.command_timeout_secs),
                    read_data_body(&mut reader, max_bytes),
                )
                .await;
                let (mut raw_bytes, too_large) = match data_result {
                    Ok(result) => result,
                    Err(_) => {
                        let _ = write_half
                            .write_all(b"421 4.4.2 Timeout - closing connection\r\n")
                            .await;
                        break;
                    }
                };

                if too_large {
                    SMTP_MESSAGES_REJECTED_TOTAL
                        .with_label_values(&["size"])
                        .inc();
                    if write_half
                        .write_all(b"552 Message too large\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    state = SessionState::Greeted { ehlo_domain };
                    continue;
                }

                // ─── Mail loop detection (RFC 5321 §6.3) ─────────────────────
                // Count existing Received: headers.  Each hop prepends one; a
                // message with 25+ hops is certainly in a loop.  Reject with
                // 554 so no further resources are consumed.  The state resets
                // to Greeted so the session stays open for the next message.
                const MAX_HOPS: usize = 25;
                if count_received_headers(&raw_bytes) >= MAX_HOPS {
                    SMTP_MESSAGES_REJECTED_TOTAL
                        .with_label_values(&["loop"])
                        .inc();
                    if write_half
                        .write_all(b"554 5.4.6 Too many hops - mail loop detected\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    state = SessionState::Greeted { ehlo_domain };
                    continue;
                }
                // ─────────────────────────────────────────────────────────────

                // Run the inbound authentication pipeline if an authenticator
                // is configured.  On DMARC reject the session sends 550 and
                // resets to Greeted (the TCP connection stays open per RFC 5321
                // §6.1 — a 5xx on DATA is not a reason to terminate).
                //
                // The SieveEnv is populated by verify_inbound when auth runs;
                // it remains empty when no authenticator is configured so Sieve
                // scripts using environment tests degrade gracefully.
                let sieve_env = if let Some(ref authenticator) = auth {
                    let result = verify_inbound(
                        authenticator,
                        &dns_cache,
                        &raw_bytes,
                        client_ip,
                        &ehlo_domain,
                        &from,
                        &config.hostname,
                    )
                    .await;

                    if result.dmarc_reject {
                        warn!(
                            peer = %peer_addr,
                            from = %from,
                            "DMARC reject policy applied — rejecting message"
                        );
                        SMTP_MESSAGES_REJECTED_TOTAL
                            .with_label_values(&["policy"])
                            .inc();
                        if write_half
                            .write_all(b"550 5.7.1 Message rejected due to DMARC policy\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        state = SessionState::Greeted { ehlo_domain };
                        continue;
                    }

                    // Prepend Authentication-Results header to the message.
                    let header_bytes =
                        format!("Authentication-Results: {}\r\n", result.header).into_bytes();
                    let mut new_bytes = Vec::with_capacity(header_bytes.len() + raw_bytes.len());
                    new_bytes.extend_from_slice(&header_bytes);
                    new_bytes.extend_from_slice(&raw_bytes);
                    raw_bytes = new_bytes;

                    result.sieve_env
                } else {
                    stoa_sieve_native::SieveEnv::new()
                };

                // ─── Received: header (RFC 5321 §4.4 / RFC 3848 §2) ─────────
                // Every MTA that accepts a message MUST prepend a Received:
                // trace header.  This must be the outermost (first) header so
                // it is prepended last, after Authentication-Results.
                //
                // RFC 3848 §2: use "ESMTPS" when TLS was active, "ESMTP" when
                // not.  RFC 8689 §4.1: annotate "REQUIRETLS" in the with-clause
                // when the sender signalled REQUIRETLS on MAIL FROM.
                {
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let date_str = epoch_to_rfc2822(now_secs);
                    let with_clause = match (is_tls, require_tls) {
                        (true, true) => "ESMTPS (REQUIRETLS)",
                        (true, false) => "ESMTPS",
                        (false, _) => "ESMTP",
                    };
                    let received = format!(
                        "Received: from {} ([{}]) by {} with {}; {}\r\n",
                        ehlo_domain, client_ip, config.hostname, with_clause, date_str
                    );
                    let received_bytes = received.into_bytes();
                    let mut new_bytes = Vec::with_capacity(received_bytes.len() + raw_bytes.len());
                    new_bytes.extend_from_slice(&received_bytes);
                    new_bytes.extend_from_slice(&raw_bytes);
                    raw_bytes = new_bytes;
                }
                // ─────────────────────────────────────────────────────────────

                // NOTE: the presence of a Newsgroups: header in the incoming message
                // does NOT auto-route it to an NNTP newsgroup. NNTP posting is handled
                // explicitly via FileInto("newsgroup:...") in Sieve scripts. This is by
                // design — see stoa-euk.

                // ─── Sieve delivery ──────────────────────────────────────────
                // All inbound SMTP email is processed by Sieve.
                //
                // Actions:
                //   Reject   → 550, reset session (no accept)
                //   Discard  → 250 OK, message dropped
                //   Keep     → 250 OK, deliver to INBOX
                //   FileInto("newsgroup:X") → enqueue to durable NNTP queue
                //   FileInto(folder)        → deliver to named folder
                //
                // When no local user matches a recipient the message is
                // accepted (250 OK) but produces no Sieve actions — the
                // sending MTA's responsibility ends at 250.
                match sieve_delivery(
                    &config,
                    pool.as_ref(),
                    mail_pool.as_ref(),
                    inbox_mailbox_id.as_deref(),
                    &to,
                    &raw_bytes,
                    &from,
                    sieve_cache.as_ref(),
                    &nntp_queue,
                    &peer_addr,
                    &sieve_env,
                )
                .await
                {
                    SieveOutcome::Rejected(reason) => {
                        // Log the per-recipient rejection reason for operator
                        // diagnostics, but do NOT echo it back to the sender.
                        // In multi-recipient envelopes, exposing the per-user
                        // reason would reveal which recipient's Sieve policy
                        // triggered the reject, leaking BCC recipient identity.
                        let safe: String = reason
                            .chars()
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .take(200)
                            .collect();
                        warn!(peer = %peer_addr, from = %from, %safe, "Sieve reject");
                        SMTP_MESSAGES_REJECTED_TOTAL
                            .with_label_values(&["policy"])
                            .inc();
                        if write_half
                            .write_all(b"550 Message rejected by recipient policy\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    SieveOutcome::Accepted { nntp_queue_error } => {
                        let reply: &[u8] = if nntp_queue_error {
                            b"452 4.3.1 Queue write failed - try again later\r\n"
                        } else {
                            SMTP_MESSAGES_ACCEPTED_TOTAL.inc();
                            SMTP_DATA_BYTES_TOTAL.inc_by(raw_bytes.len() as f64);
                            b"250 OK\r\n"
                        };
                        if write_half.write_all(reply).await.is_err() {
                            break;
                        }
                    }
                    SieveOutcome::TransientError => {
                        SMTP_MESSAGES_REJECTED_TOTAL
                            .with_label_values(&["transient"])
                            .inc();
                        if write_half
                            .write_all(b"452 4.3.0 Mailbox temporarily unavailable\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                // ─────────────────────────────────────────────────────────────

                state = SessionState::Greeted { ehlo_domain };
            }

            "RSET" => {
                // RFC 5321 §4.1.1.5: RSET is only valid after EHLO/HELO.
                // Sending RSET before greeting is a bad command sequence.
                if matches!(state, SessionState::Fresh) {
                    if write_half
                        .write_all(b"503 Bad sequence of commands\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
                state = match state {
                    SessionState::Fresh => SessionState::Fresh,
                    SessionState::Greeted { ehlo_domain }
                    | SessionState::Mail { ehlo_domain, .. }
                    | SessionState::Rcpt { ehlo_domain, .. } => {
                        SessionState::Greeted { ehlo_domain }
                    }
                };
            }

            "NOOP" => {
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
            }

            "QUIT" => {
                let _ = write_half.write_all(b"221 Bye\r\n").await;
                break;
            }

            "STARTTLS" => {
                if is_tls {
                    if write_half
                        .write_all(b"503 5.5.1 STARTTLS already active\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let Some(ref acceptor) = tls_acceptor else {
                    if write_half
                        .write_all(b"454 TLS not available\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                };
                if write_half
                    .write_all(b"220 Ready to start TLS\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
                let plain_stream = reader.into_inner().unsplit(write_half);
                let tls_stream = match acceptor.accept(plain_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        info!(peer = %peer_addr, "STARTTLS handshake failed: {e}");
                        return;
                    }
                };
                Box::pin(run_session(
                    Box::new(tls_stream),
                    true,
                    is_submission,
                    peer_addr,
                    config,
                    credential_store,
                    nntp_queue,
                    auth,
                    dns_cache,
                    pool,
                    mail_pool,
                    sieve_cache,
                    inbox_mailbox_id,
                    None,
                ))
                .await;
                return;
            }

            _ => {
                if write_half
                    .write_all(b"500 Command unrecognized\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    info!(peer = %peer_addr, "session ended");
}

/// Verify a SASL PLAIN credential string against the credential store.
///
/// The PLAIN mechanism encodes credentials as base64(`authzid\0authcid\0passwd`)
/// per RFC 4616 §2.  `authzid` is usually empty (authorization identity equals
/// authentication identity).  A non-empty `authzid` is rejected — this server
/// does not support proxy authentication.
///
/// Returns `Some(username)` (ASCII-lowercased) on success, `None` on any
/// failure.  The password is never logged.
async fn verify_sasl_plain(store: &CredentialStore, b64_response: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64_response.trim())
        .ok()?;
    // Split on NUL: [authzid, authcid, passwd]
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authzid = std::str::from_utf8(parts[0]).ok()?;
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    // Empty authcid is not permitted by RFC 4616 §2.
    if authcid.is_empty() {
        return None;
    }
    // Non-empty authzid means proxy-auth — not supported, reject.
    if !authzid.is_empty() {
        return None;
    }
    if store.check(authcid, passwd).await {
        Some(authcid.to_ascii_lowercase())
    } else {
        None
    }
}

/// Load and evaluate the active Sieve script for `username`.
/// Defaults to [`Keep`](stoa_sieve_native::SieveAction::Keep) when no script
/// is stored or the script fails to compile.
/// Outcome of [`sieve_delivery`].
enum SieveOutcome {
    /// At least one recipient's Sieve script issued a `Reject` action.
    /// The inner string is the raw (unsanitised) rejection reason for logging;
    /// it must not be forwarded verbatim to the sender (BCC privacy).
    Rejected(String),
    /// No rejection; message was processed for all recipients.
    /// `nntp_queue_error` is `true` if at least one newsgroup enqueue failed.
    Accepted { nntp_queue_error: bool },
    /// Both the JMAP store and the smtp fallback store failed for a Keep
    /// action.  The caller must send `452` so the sending MTA retries.
    TransientError,
}

/// Derive a stable JMAP mailbox_id for a List/* mailbox name.
///
/// Algorithm: SHA-256(name as UTF-8) → first 16 bytes → BASE32_NOPAD.
/// Result is always 26 uppercase characters.  This is the same algorithm used
/// by `stoa_mail::mailbox::provision::mailbox_id_for_role` so that the two
/// crates agree on ids for the same logical mailbox.
///
/// Oracle: Python
///   `import hashlib, base64; base64.b32encode(hashlib.sha256(name.encode()).digest()[:16]).decode().rstrip('=')`
fn list_mailbox_id(name: &str) -> String {
    use data_encoding::BASE32_NOPAD;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    BASE32_NOPAD.encode(&digest[..16])
}

/// Evaluate the global Sieve script and apply the resulting actions.
///
/// The global script is keyed to `crate::config::GLOBAL_SCRIPT_KEY` in the `user_sieve_scripts`
/// table.  When no script is stored the default action is Keep (RFC 5228
/// §2.10.2).
///
/// Returns [`SieveOutcome::Rejected`] if the script issued a reject — the
/// caller is responsible for sending the 550 response and incrementing the
/// reject metric.  Returns [`SieveOutcome::Accepted`] otherwise, with a flag
/// indicating whether any newsgroup enqueue failed (caller sends 452 vs 250).
#[allow(clippy::too_many_arguments)]
async fn sieve_delivery(
    config: &Config,
    pool: Option<&SqlitePool>,
    mail_pool: Option<&SqlitePool>,
    inbox_mailbox_id: Option<&str>,
    to: &[String],
    raw_bytes: &[u8],
    from: &str,
    sieve_cache: Option<&SieveCache>,
    nntp_queue: &NntpQueue,
    peer_addr: &str,
    env: &stoa_sieve_native::SieveEnv,
) -> SieveOutcome {
    // Use the first recipient address for Sieve envelope matching.
    // In a single-user system all recipients share the same global policy.
    let envelope_to = to.first().map(|s| s.as_str()).unwrap_or("");

    // Evaluate the global script (keyed to crate::config::GLOBAL_SCRIPT_KEY).
    let actions = if let Some(db_pool) = pool {
        let sieve_timeout = tokio::time::Duration::from_millis(config.limits.sieve_eval_timeout_ms);
        match tokio::time::timeout(
            sieve_timeout,
            sieve_global(db_pool, raw_bytes, from, envelope_to, sieve_cache, env),
        )
        .await
        {
            Ok(actions) => actions,
            Err(_elapsed) => {
                tracing::warn!("Sieve evaluation timed out; defaulting to Keep");
                crate::metrics::SMTP_SIEVE_EVAL_TIMEOUTS_TOTAL.inc();
                vec![stoa_sieve_native::SieveAction::Keep]
            }
        }
    } else {
        vec![stoa_sieve_native::SieveAction::Keep]
    };

    // Reject-before-deliver: if the script issues Reject, return immediately.
    for action in &actions {
        if let stoa_sieve_native::SieveAction::Reject(r) = action {
            return SieveOutcome::Rejected(r.clone());
        }
    }

    // Apply Keep / FileInto / Discard actions once for the message.
    let mut nntp_queue_error = false;
    for action in actions {
        match action {
            stoa_sieve_native::SieveAction::Keep => {
                // If the message carries a List-Id: header, route it to a
                // per-list mailbox instead of INBOX.  The mailbox name is
                // "List/<list-id>" (flat, no dot-to-slash expansion).
                // The JMAP mailbox_id uses the same SHA-256(name)[..16] →
                // BASE32_NOPAD scheme as stoa_mail::mailbox::provision::mailbox_id_for_role.
                let (smtp_mailbox, jmap_mailbox_id): (String, String) =
                    if let Some(list_id) = routing::extract_list_id(raw_bytes) {
                        let name = format!("List/{list_id}");
                        let id = list_mailbox_id(&name);
                        (name, id)
                    } else {
                        (
                            "INBOX".to_string(),
                            inbox_mailbox_id.unwrap_or("").to_string(),
                        )
                    };

                if let Some(mp) = mail_pool {
                    // For INBOX: use the id cached at startup.
                    // For List/*: use the id derived on the fly with the same algorithm.
                    if !jmap_mailbox_id.is_empty() {
                        let insert_result = sqlx::query(
                            "INSERT INTO messages (mailbox_id, envelope_from, envelope_to, raw_message) VALUES (?,?,?,?)",
                        )
                        .bind(&jmap_mailbox_id)
                        .bind(from)
                        .bind(envelope_to)
                        .bind(raw_bytes)
                        .execute(mp)
                        .await;

                        match insert_result {
                            Ok(_) => {
                                let _ = sqlx::query(
                                    "INSERT INTO state_version (user_id, scope, version) VALUES (1, 'Email', 1) \
                                     ON CONFLICT(user_id, scope) DO UPDATE SET version = version + 1",
                                )
                                .execute(mp)
                                .await;
                            }
                            Err(e) => {
                                warn!(peer = %peer_addr, mailbox = %smtp_mailbox, "SMTP→JMAP write failed: {e}; falling through to smtp store");
                                if let Some(db_pool) = pool {
                                    if let Err(e2) = store::deliver(
                                        db_pool,
                                        crate::config::GLOBAL_SCRIPT_KEY,
                                        &smtp_mailbox,
                                        from,
                                        envelope_to,
                                        raw_bytes,
                                    )
                                    .await
                                    {
                                        warn!(peer = %peer_addr, mailbox = %smtp_mailbox, "deliver failed: {e2}; both delivery paths failed, returning transient error");
                                        return SieveOutcome::TransientError;
                                    }
                                } else {
                                    warn!(peer = %peer_addr, "SMTP→JMAP write failed and no smtp fallback pool; returning transient error");
                                    return SieveOutcome::TransientError;
                                }
                            }
                        }
                    } else {
                        warn!(peer = %peer_addr, "INBOX not in JMAP mailboxes table; falling back to smtp store");
                        if let Some(db_pool) = pool {
                            if let Err(e) = store::deliver(
                                db_pool,
                                crate::config::GLOBAL_SCRIPT_KEY,
                                &smtp_mailbox,
                                from,
                                envelope_to,
                                raw_bytes,
                            )
                            .await
                            {
                                warn!(peer = %peer_addr, mailbox = %smtp_mailbox, "fallback smtp store deliver failed: {e}; both delivery paths failed, returning transient error");
                                return SieveOutcome::TransientError;
                            }
                        } else {
                            warn!(peer = %peer_addr, "INBOX not in JMAP mailboxes table and no smtp fallback pool; returning transient error");
                            return SieveOutcome::TransientError;
                        }
                    }
                } else if let Some(db_pool) = pool {
                    if let Err(e) = store::deliver(
                        db_pool,
                        crate::config::GLOBAL_SCRIPT_KEY,
                        &smtp_mailbox,
                        from,
                        envelope_to,
                        raw_bytes,
                    )
                    .await
                    {
                        warn!(peer = %peer_addr, mailbox = %smtp_mailbox, "deliver failed: {e}");
                    }
                } else {
                    // No database configured but Keep action requires local
                    // delivery.  Return a 452 transient failure so the sending
                    // MTA retries — silently discarding mail here is data loss.
                    warn!(
                        peer = %peer_addr,
                        "Sieve Keep: no database configured, returning transient error"
                    );
                    return SieveOutcome::TransientError;
                }
            }
            stoa_sieve_native::SieveAction::FileInto(folder) => {
                if let Some(newsgroup) = folder.strip_prefix("newsgroup:") {
                    let article_result = if routing::has_newsgroups_header(raw_bytes) {
                        Ok((raw_bytes.to_vec(), InjectionSource::SmtpNewsgroups))
                    } else {
                        routing::add_newsgroups_header(raw_bytes, newsgroup)
                            .map(|a| (a, InjectionSource::SmtpSieve))
                    };
                    match article_result {
                        Err(e) => {
                            warn!(peer = %peer_addr, %newsgroup, "rejecting article: invalid newsgroup name: {e}");
                            nntp_queue_error = true;
                        }
                        Ok((article, injection_source)) => {
                            if let Err(e) = nntp_queue.enqueue(&article, injection_source).await {
                                warn!(peer = %peer_addr, %newsgroup, "NNTP queue write failed: {e}");
                                nntp_queue_error = true;
                            }
                        }
                    }
                } else if let Some(db_pool) = pool {
                    if let Err(e) = store::deliver(
                        db_pool,
                        crate::config::GLOBAL_SCRIPT_KEY,
                        &folder,
                        from,
                        envelope_to,
                        raw_bytes,
                    )
                    .await
                    {
                        warn!(peer = %peer_addr, %folder, "deliver to folder failed: {e}");
                    }
                } else {
                    // No database configured for non-newsgroup folder delivery.
                    // Silently discarding here would be data loss; return a
                    // temporary failure so the sending MTA retries once the
                    // operator has configured a mail store.
                    warn!(
                        peer = %peer_addr, %folder,
                        "Sieve FileInto: no database configured, returning transient error"
                    );
                    return SieveOutcome::TransientError;
                }
            }
            stoa_sieve_native::SieveAction::Discard => {
                info!(peer = %peer_addr, "Sieve discard — message dropped");
            }
            stoa_sieve_native::SieveAction::Reject(_) => {}
        }
    }

    SieveOutcome::Accepted { nntp_queue_error }
}

/// Load and evaluate the active global Sieve script.
///
/// The global script is keyed to `crate::config::GLOBAL_SCRIPT_KEY` in the `user_sieve_scripts`
/// table.  Defaults to [`Keep`](stoa_sieve_native::SieveAction::Keep) when no
/// script is stored or the script fails to compile.
async fn sieve_global(
    pool: &SqlitePool,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
    cache: Option<&SieveCache>,
    env: &stoa_sieve_native::SieveEnv,
) -> Vec<stoa_sieve_native::SieveAction> {
    // Check cache before hitting the database.
    if let Some(cache) = cache {
        let lock = cache.lock().await;
        if let Some(compiled) = lock.get(crate::config::GLOBAL_SCRIPT_KEY) {
            let compiled = Arc::clone(compiled);
            drop(lock);
            return stoa_sieve_native::evaluate(
                &compiled,
                raw_message,
                envelope_from,
                envelope_to,
                env,
            );
        }
    }

    let script_bytes = store::load_active_script(pool, crate::config::GLOBAL_SCRIPT_KEY).await;
    match script_bytes {
        Some(bytes) => match stoa_sieve_native::compile(&bytes) {
            Ok(compiled) => {
                let compiled = Arc::new(compiled);
                if let Some(cache) = cache {
                    cache.lock().await.insert(
                        crate::config::GLOBAL_SCRIPT_KEY.to_owned(),
                        Arc::clone(&compiled),
                    );
                }
                stoa_sieve_native::evaluate(&compiled, raw_message, envelope_from, envelope_to, env)
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    sieve.event = "compile_error",
                    "global Sieve script compile error — failing open to Keep; \
                     filter rules are NOT being applied"
                );
                vec![stoa_sieve_native::SieveAction::Keep]
            }
        },
        None => vec![stoa_sieve_native::SieveAction::Keep],
    }
}

/// Count the number of `Received:` headers in the header section of a message.
///
/// Only the header section (before the first blank line) is scanned; body
/// content is never considered.  Matching is case-insensitive.
///
/// Used for mail loop detection: RFC 5321 §6.3 recommends rejecting messages
/// with 25 or more `Received:` hops as a probable loop.
fn count_received_headers(msg: &[u8]) -> usize {
    let headers = &msg[..header_section_end(msg)];
    let prefix = b"received:";
    let mut count = 0;
    let mut i = 0;
    while i < headers.len() {
        // Find the end of this line.
        let line_end = headers[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p)
            .unwrap_or(headers.len());
        let line = &headers[i..line_end];
        // Strip trailing CR.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            count += 1;
        }
        i = line_end + 1;
    }
    count
}

/// Read the RFC 5321 DATA body: accumulate dot-unstuffed lines until a lone
/// `".\r\n"` terminator is received.
///
/// Reads byte-by-byte via the `BufReader` internal buffer so that a single
/// line longer than `max_bytes` cannot exhaust heap — it is detected early
/// and the rest of that line is drained before continuing.
///
/// Returns `(accumulated_bytes, too_large)`.  If the body exceeds
/// `max_bytes`, we continue reading and discarding until the terminator so
/// the session can continue (RFC 5321 §4.5.3.1).
async fn read_data_body<R>(reader: &mut BufReader<R>, max_bytes: u64) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut body: Vec<u8> = Vec::new();
    let mut too_large = false;
    let max_bytes_usize = max_bytes as usize;
    let mut byte = [0u8; 1];
    let mut line_buf: Vec<u8> = Vec::new();

    'outer: loop {
        // Read one line byte-by-byte, bounded to max_bytes_usize per line.
        // A single body line longer than max_bytes means the message is
        // already over the limit; drain that line and mark too_large.
        line_buf.clear();
        loop {
            match reader.read(&mut byte).await {
                Ok(0) | Err(_) => break 'outer,
                Ok(_) => {
                    line_buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break; // Full line read — process below.
                    }
                    if line_buf.len() > max_bytes_usize {
                        too_large = true;
                        body.clear();
                        // Drain rest of the overlong line without buffering.
                        loop {
                            match reader.read(&mut byte).await {
                                Ok(0) | Err(_) => break 'outer,
                                Ok(_) if byte[0] == b'\n' => break,
                                _ => {}
                            }
                        }
                        continue 'outer;
                    }
                }
            }
        }

        // Terminator: a lone dot followed by CRLF.
        if line_buf == b".\r\n" || line_buf == b".\n" {
            break;
        }

        // Dot-unstuffing: RFC 5321 §4.5.2 — a line beginning with ".." has
        // the leading dot removed.
        let unstuffed: &[u8] = if line_buf.starts_with(b"..") {
            &line_buf[1..]
        } else {
            &line_buf
        };

        if !too_large {
            body.extend_from_slice(unstuffed);
            if body.len() as u64 > max_bytes {
                too_large = true;
                // Drop the accumulated body; keep reading until terminator.
                body.clear();
            }
        }
    }

    (body, too_large)
}

/// Extract the address from an SMTP MAIL FROM or RCPT TO argument.
///
/// Handles ESMTP parameters that follow the angle-bracket pair — for example
/// `MAIL FROM:<sender@example.com> SIZE=12345` or
/// `RCPT TO:<user@example.com> ORCPT=rfc822;user@example.com`.
/// Returns only the content between `<` and the first `>` after it.
/// Returns the trimmed argument as-is when no angle brackets are present.
fn parse_angle_addr(args: &str) -> String {
    // Skip the `FROM:` / `TO:` keyword prefix (case-insensitive).
    let after_colon = if let Some(pos) = args.find(':') {
        &args[pos + 1..]
    } else {
        args
    };
    let trimmed = after_colon.trim();
    // Locate the angle-bracket pair and return only what is inside it.
    // Everything after the closing `>` (ESMTP params) is intentionally ignored.
    if let Some(open) = trimmed.find('<') {
        if let Some(rel_close) = trimmed[open + 1..].find('>') {
            return trimmed[open + 1..open + 1 + rel_close].to_string();
        }
    }
    trimmed.to_string()
}

/// Return `true` if the SMTP MAIL FROM argument string contains the standalone
/// `REQUIRETLS` parameter (RFC 8689 §2).
///
/// The parameter is case-insensitive per RFC 5321 §4.1.2.  It appears after
/// the closing `>` of the address part, separated by whitespace.  Examples:
///
/// - `FROM:<user@example.com> REQUIRETLS`          → true
/// - `FROM:<user@example.com> SIZE=1000 REQUIRETLS` → true
/// - `FROM:<user@example.com>`                      → false
fn has_requiretls_param(args: &str) -> bool {
    // Strip up to and including the first `>` to isolate ESMTP params.
    let params = match args.find('>') {
        Some(pos) => &args[pos + 1..],
        None => args,
    };
    // Split on ASCII whitespace; look for a case-insensitive "REQUIRETLS" token.
    params
        .split_ascii_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case("REQUIRETLS"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig,
        SieveAdminConfig, TlsConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── list_mailbox_id ───────────────────────────────────────────────────────
    // Oracle: Python
    //   import hashlib, base64
    //   def mid(name): return base64.b32encode(hashlib.sha256(name.encode()).digest()[:16]).decode().rstrip('=')

    #[test]
    fn list_mailbox_id_oracle() {
        // Oracle: mid('List/rust-users.lists.rust-lang.org') = 'U22LEYZSQKMQEBJK7VVRUKLURQ'
        assert_eq!(
            list_mailbox_id("List/rust-users.lists.rust-lang.org"),
            "U22LEYZSQKMQEBJK7VVRUKLURQ"
        );
    }

    #[test]
    fn list_mailbox_id_is_26_chars() {
        assert_eq!(list_mailbox_id("List/example.lists.example.com").len(), 26);
    }

    #[test]
    fn list_mailbox_id_different_names_differ() {
        assert_ne!(
            list_mailbox_id("List/a.example.com"),
            list_mailbox_id("List/b.example.com")
        );
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: crate::config::LogFormat::Json,
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        })
    }

    async fn open_test_db() -> SqlitePool {
        crate::store::open(":memory:")
            .await
            .expect("open in-memory DB")
    }

    /// Drive a session with the given config and optional pool.
    ///
    /// Returns `(server_response_string, nntp_queue_dir)`.
    /// The caller can inspect the tempdir for `.msg` files to verify NNTP injection.
    async fn drive_session_ext(
        client_script: &[u8],
        config: Arc<Config>,
        pool: Option<SqlitePool>,
    ) -> (String, tempfile::TempDir) {
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                false,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                pool,
                None,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(client_script).await.expect("write script");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .await
            .expect("read response");
        server_task.await.expect("server task");

        (response, queue_dir)
    }

    /// Convenience wrapper: no-pool session using the default test config.
    async fn drive_session(client_script: &[u8]) -> (String, tempfile::TempDir) {
        drive_session_ext(client_script, test_config(), None).await
    }

    /// Count .msg files in a queue directory.
    fn count_queued(dir: &tempfile::TempDir) -> usize {
        std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .count()
    }

    #[tokio::test]
    async fn test_basic_smtp_session() {
        // Basic end-to-end: full SMTP exchange completes successfully.
        // All RCPT TO addresses are accepted in the global delivery model.
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Hello\r\n\
            \r\n\
            Body text.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) = drive_session_ext(client, test_config(), None).await;

        assert!(
            response.starts_with("220 "),
            "expected greeting, got: {response}"
        );
        assert!(response.contains("250"), "expected 250 after EHLO");
        assert!(response.contains("354"), "expected 354 DATA prompt");
        assert!(response.contains("250 OK"), "expected 250 after DATA");
        assert!(response.contains("221"), "expected 221 QUIT");
    }

    #[tokio::test]
    async fn test_rset_clears_state() {
        // MAIL then RSET then MAIL again — both MAIL commands must succeed.
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<a@example.com>\r\n\
            RSET\r\n\
            MAIL FROM:<b@example.com>\r\n\
            QUIT\r\n";

        let (response, _) = drive_session(client).await;

        // Count "250 OK" occurrences: MAIL, RSET, MAIL = 3
        let count_250_ok = response.matches("250 OK").count();
        assert!(
            count_250_ok >= 2,
            "expected at least 2x '250 OK', got: {response}"
        );
        assert!(response.contains("221"), "expected 221 after QUIT");
    }

    #[tokio::test]
    async fn test_quit_returns_221() {
        let client = b"QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.starts_with("220 "),
            "expected greeting, got: {response}"
        );
        assert!(
            response.contains("221 Bye"),
            "expected 221 Bye, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_unknown_command_returns_500() {
        let client = b"FROBNICATE arg\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("500 Command unrecognized"),
            "expected 500, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_rcpt_before_mail_returns_503() {
        let client = b"EHLO client.example.com\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("503 Bad sequence"),
            "expected 503, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_rcpt_any_address_accepted() {
        // Global delivery model: all RCPT TO addresses are accepted (no per-user allowlist).
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<anyone@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("250 OK"),
            "all RCPT TO must be accepted in global delivery model, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_oversized_line_returns_500_and_closes() {
        // Build a line that exceeds 4096 bytes.
        let mut long_line = vec![b'A'; MAX_LINE_BYTES + 1];
        long_line.extend_from_slice(b"\r\n");

        let (response, _) = drive_session(&long_line).await;
        assert!(
            response.contains("500 Line too long"),
            "expected 500 Line too long, got: {response}"
        );
    }

    /// When `auth` is Some, a message with no DKIM / no DMARC record still
    /// gets accepted (dmarc_reject will be false) and has the
    /// Authentication-Results header prepended into the delivered message.
    #[tokio::test]
    async fn test_auth_pipeline_stamps_header() {
        let auth = Arc::new(
            mail_auth::MessageAuthenticator::new_cloudflare()
                .expect("resolver creation must not fail"),
        );

        // Message is stored in INBOX for inspection via the smtp-local store.
        let pool = open_test_db().await;
        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let auth2 = auth.clone();
        let pool2 = pool.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(
                Box::new(stream),
                false,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                Some(auth2),
                Arc::new(crate::dns_cache::DnsCache::new()),
                Some(pool2),
                None,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let script = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            From: sender@example.com\r\n\
            To: rcpt@example.com\r\n\
            Subject: Auth test\r\n\
            Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";
        client.write_all(script).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("250 OK"), "expected 250 after DATA");

        let raw_bytes =
            crate::store::get_first_message_raw(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX")
                .await
                .expect("message must be in INBOX");
        let raw = std::str::from_utf8(&raw_bytes).expect("valid UTF-8");
        assert!(
            raw.contains("Authentication-Results:"),
            "expected Authentication-Results header in message:\n{raw}"
        );
    }

    // ── Sieve delivery tests ──────────────────────────────────────────────────

    const FULL_MSG: &[u8] = b"EHLO client.example.com\r\n\
        MAIL FROM:<sender@example.com>\r\n\
        RCPT TO:<alice@example.com>\r\n\
        DATA\r\n\
        Subject: Test\r\n\
        \r\n\
        Body\r\n\
        .\r\n\
        QUIT\r\n";

    #[tokio::test]
    async fn test_sieve_default_delivers_to_inbox() {
        // No global script stored → default Keep → message in INBOX.
        let pool = open_test_db().await;
        let config = test_config();

        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        let count =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count, 1, "expected 1 message in INBOX");
    }

    #[tokio::test]
    async fn test_sieve_fileinto_delivers_to_folder() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            br#"require ["fileinto"]; fileinto "Work";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config();
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        let count_work =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "Work").await;
        let count_inbox =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count_work, 1, "expected 1 message in Work");
        assert_eq!(count_inbox, 0, "expected 0 messages in INBOX");
    }

    #[tokio::test]
    async fn test_sieve_discard_accepts_but_no_db_write() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            b"discard;",
            true,
        )
        .await
        .expect("save script");

        let config = test_config();
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK (discard still accepts), got: {response}"
        );
        let count =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count, 0, "expected 0 messages — message was discarded");
    }

    #[tokio::test]
    async fn test_sieve_reject_returns_550() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            br#"require ["reject"]; reject "Not wanted";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config();
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(response.contains("550"), "expected 550, got: {response}");
        let count =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count, 0, "expected 0 messages — message was rejected");
    }

    // ── Sieve fileinto "newsgroup:X" enqueues to NNTP queue ──────────────────

    #[tokio::test]
    async fn test_sieve_fileinto_newsgroup_enqueues_article() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            br#"require ["fileinto"]; fileinto "newsgroup:comp.test";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config();
        let pool_clone = pool.clone();
        let (response, queue_dir) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        assert_eq!(
            count_queued(&queue_dir),
            1,
            "expected 1 article in NNTP queue"
        );

        // The queued file should contain the Newsgroups: header.
        let files: Vec<_> = std::fs::read_dir(queue_dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .collect();
        let bytes = std::fs::read(files[0].path()).expect("read queue file");
        let text = std::str::from_utf8(&bytes).expect("valid UTF-8");
        assert!(
            text.contains("Newsgroups: comp.test"),
            "queued article must have Newsgroups header"
        );

        // Nothing in INBOX.
        let count =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count, 0, "newsgroup fileinto must not deliver to INBOX");
    }

    // ── Sieve fileinto "newsgroup:X" with pre-existing Newsgroups: header ────

    #[tokio::test]
    async fn test_sieve_fileinto_newsgroup_no_duplicate_header() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            br#"require ["fileinto"]; fileinto "newsgroup:comp.test";"#,
            true,
        )
        .await
        .expect("save script");

        // Message already has a Newsgroups: header.
        let msg_with_ng = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<alice@example.com>\r\n\
            DATA\r\n\
            Newsgroups: alt.test\r\n\
            Subject: Cross-posted\r\n\
            \r\n\
            Body\r\n\
            .\r\n\
            QUIT\r\n";

        let config = test_config();
        let (response, queue_dir) = drive_session_ext(msg_with_ng, config, Some(pool)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        assert_eq!(
            count_queued(&queue_dir),
            1,
            "expected 1 article in NNTP queue"
        );

        let files: Vec<_> = std::fs::read_dir(queue_dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .collect();
        let bytes = std::fs::read(files[0].path()).expect("read queue file");
        let text = std::str::from_utf8(&bytes).expect("valid UTF-8");

        // Original Newsgroups: must be present.
        assert!(
            text.contains("Newsgroups: alt.test"),
            "original Newsgroups header must be preserved"
        );
        // Must not have a duplicate.
        assert_eq!(
            text.matches("Newsgroups:").count(),
            1,
            "must not have duplicate Newsgroups: header, got:\n{text}"
        );
    }

    // ── List-Id: auto-routing ─────────────────────────────────────────────────

    const LIST_MSG: &[u8] = b"EHLO client.example.com\r\n\
        MAIL FROM:<sender@example.com>\r\n\
        RCPT TO:<alice@example.com>\r\n\
        DATA\r\n\
        List-Id: <rust-users.lists.rust-lang.org>\r\n\
        Subject: List post\r\n\
        \r\n\
        Body\r\n\
        .\r\n\
        QUIT\r\n";

    /// A message with List-Id: must be delivered to List/<list-id>, not INBOX.
    #[tokio::test]
    async fn test_list_id_routes_to_list_mailbox() {
        let pool = open_test_db().await;
        let config = test_config();
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(LIST_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );

        let count_list = crate::store::count_messages(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "List/rust-users.lists.rust-lang.org",
        )
        .await;
        let count_inbox =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;

        assert_eq!(count_list, 1, "expected 1 message in List/* mailbox");
        assert_eq!(count_inbox, 0, "expected 0 messages in INBOX");
    }

    /// A message without List-Id: must be delivered to INBOX, not a List mailbox.
    #[tokio::test]
    async fn test_no_list_id_routes_to_inbox() {
        let pool = open_test_db().await;
        let config = test_config();
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );

        let count_inbox =
            crate::store::count_messages(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX").await;
        assert_eq!(count_inbox, 1, "expected 1 message in INBOX");
    }

    // ── Received: header (RFC 5321 §4.4) ─────────────────────────────────────

    /// Every accepted message must start with a Received: trace header.
    #[tokio::test]
    async fn test_received_header_prepended() {
        let pool = open_test_db().await;
        let config = test_config();

        let client = b"EHLO mail.sender.example\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            From: sender@example.com\r\n\
            To: rcpt@example.com\r\n\
            Subject: Received header test\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) = drive_session_ext(client, config, Some(pool.clone())).await;
        assert!(
            response.contains("250 OK"),
            "expected 250 after DATA: {response}"
        );

        let raw_bytes =
            crate::store::get_first_message_raw(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX")
                .await
                .expect("message must be in INBOX");
        let raw = std::str::from_utf8(&raw_bytes).expect("valid UTF-8");

        assert!(
            raw.starts_with("Received:"),
            "stored message must start with Received: header, got:\n{raw}"
        );
        assert!(
            raw.contains("mail.sender.example"),
            "Received: header must contain EHLO domain: {raw}"
        );
        assert!(
            raw.contains("test.example.com"),
            "Received: header must contain local hostname: {raw}"
        );
    }

    // ── ryw.2: parse_angle_addr unit tests ───────────────────────────────────

    #[test]
    fn parse_angle_addr_simple() {
        assert_eq!(parse_angle_addr("FROM:<foo@bar.com>"), "foo@bar.com");
    }

    #[test]
    fn parse_angle_addr_with_size_param() {
        // Modern MTAs send SIZE on MAIL FROM; the address must not include it.
        assert_eq!(
            parse_angle_addr("FROM:<foo@bar.com> SIZE=12345"),
            "foo@bar.com"
        );
    }

    #[test]
    fn parse_angle_addr_with_orcpt_param() {
        // RFC 3461 DSN: ORCPT may follow RCPT TO.
        assert_eq!(
            parse_angle_addr("TO:<alice@example.com> ORCPT=rfc822;alice@example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn parse_angle_addr_null_sender() {
        // Null sender (<>) used for bounce messages.
        assert_eq!(parse_angle_addr("FROM:<>"), "");
    }

    #[test]
    fn parse_angle_addr_no_brackets() {
        assert_eq!(parse_angle_addr("foo@bar.com"), "foo@bar.com");
    }

    // ── stoa-2xeks.21: has_requiretls_param unit tests ────────────────────────

    // T1: REQUIRETLS alone after address returns true.
    // Oracle: RFC 8689 §2 — parameter token is case-insensitive.
    #[test]
    fn has_requiretls_param_present() {
        assert!(has_requiretls_param("FROM:<user@example.com> REQUIRETLS"));
    }

    // T2: lowercase requiretls is accepted (case-insensitive per RFC 5321 §4.1.2).
    #[test]
    fn has_requiretls_param_lowercase() {
        assert!(has_requiretls_param("FROM:<user@example.com> requiretls"));
    }

    // T3: REQUIRETLS mixed with SIZE parameter.
    #[test]
    fn has_requiretls_param_with_size() {
        assert!(has_requiretls_param(
            "FROM:<user@example.com> SIZE=1000 REQUIRETLS"
        ));
    }

    // T4: no REQUIRETLS parameter returns false.
    #[test]
    fn has_requiretls_param_absent() {
        assert!(!has_requiretls_param("FROM:<user@example.com>"));
    }

    // T5: SIZE only, no REQUIRETLS, returns false.
    #[test]
    fn has_requiretls_param_size_only() {
        assert!(!has_requiretls_param("FROM:<user@example.com> SIZE=99999"));
    }

    // T6: "REQUIRETLS" is not a prefix match — "REQUIRETLSx" must not match.
    #[test]
    fn has_requiretls_param_no_prefix_match() {
        assert!(!has_requiretls_param("FROM:<user@example.com> REQUIRETLSx"));
    }

    // ── ryw.2: integration — MAIL FROM with SIZE must not corrupt envelope ───

    #[tokio::test]
    async fn test_mail_from_with_size_param_accepted() {
        // A real MTA sends MAIL FROM:<addr> SIZE=nnn.  The session must
        // accept it and store the address without the SIZE suffix.
        let pool = open_test_db().await;
        let config = test_config();
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com> SIZE=1024\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Size test\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) = drive_session_ext(client, config, Some(pool.clone())).await;
        assert!(
            response.contains("250 OK"),
            "expected 250 after DATA: {response}"
        );

        let envelope_from =
            crate::store::get_first_envelope_from(&pool, crate::config::GLOBAL_SCRIPT_KEY, "INBOX")
                .await
                .expect("message must be in INBOX");
        assert_eq!(
            envelope_from, "sender@example.com",
            "envelope_from must not include SIZE param"
        );
    }

    // ── STARTTLS EHLO advertisement ───────────────────────────────────────────

    // STARTTLS must NOT appear in EHLO when no tls_acceptor is provided.
    #[tokio::test]
    async fn test_ehlo_no_starttls_without_tls_acceptor() {
        // config has cert/key paths set but tls_acceptor is None.
        let config = Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: Some("/etc/ssl/cert.pem".into()),
                key_path: Some("/etc/ssl/key.pem".into()),
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: crate::config::LogFormat::Json,
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        });

        let client = b"EHLO client.example.com\r\nQUIT\r\n";
        let (response, _) = drive_session_ext(client, config, None).await;

        assert!(
            !response.contains("STARTTLS"),
            "STARTTLS must not appear in EHLO when tls_acceptor is None: {response}"
        );
        assert!(
            response.contains("250"),
            "expected 250 EHLO response: {response}"
        );
    }

    // STARTTLS must appear in EHLO when tls_acceptor is Some. Oracle: RFC 3207 §3.
    #[tokio::test]
    async fn test_ehlo_includes_starttls_when_tls_acceptor_present() {
        use rcgen::generate_simple_self_signed;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stoa_tls::install_ring_provider();
        let config = test_config();
        let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("test.crt");
        let key_path = dir.path().join("test.key");
        std::fs::write(&cert_path, cert_key.cert.pem().as_bytes()).expect("write cert");
        std::fs::write(&key_path, cert_key.key_pair.serialize_pem().as_bytes()).expect("write key");
        let acceptor = Arc::new(
            crate::tls::build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("build acceptor"),
        );
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let acceptor2 = Some(Arc::clone(&acceptor));
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                false,
                false,
                peer.to_string(),
                config2,
                Arc::new(CredentialStore::empty()),
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                acceptor2,
            )
            .await;
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"EHLO client.example.com\r\nQUIT\r\n")
            .await
            .expect("write");
        client.shutdown().await.expect("shutdown");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");
        assert!(
            response.contains("STARTTLS"),
            "STARTTLS must appear in EHLO when tls_acceptor is Some: {response}"
        );
    }

    // RFC 4954 §4: AUTH MUST NOT be advertised in EHLO on a cleartext connection
    // that also offers STARTTLS, even when credentials are configured.
    // Oracle: RFC 4954 §4 "AUTH command is only available after a successful TLS
    // negotiation" (when STARTTLS is offered).
    #[tokio::test]
    async fn test_ehlo_does_not_advertise_auth_before_starttls_with_credentials() {
        use rcgen::generate_simple_self_signed;
        use stoa_auth::UserCredential;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stoa_tls::install_ring_provider();

        // Build a credential store with one user (cost 4 = minimum valid bcrypt cost).
        let hash = bcrypt::hash("secret", 4).expect("bcrypt must not fail at cost 4");
        let cred_store = Arc::new(
            CredentialStore::from_credentials(&[UserCredential {
                username: "user".to_string(),
                password: hash,
            }])
            .expect("from_credentials must succeed for valid bcrypt hash"),
        );

        let config = test_config();
        let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("test.crt");
        let key_path = dir.path().join("test.key");
        std::fs::write(&cert_path, cert_key.cert.pem().as_bytes()).expect("write cert");
        std::fs::write(&key_path, cert_key.key_pair.serialize_pem().as_bytes()).expect("write key");
        let acceptor = Arc::new(
            crate::tls::build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("build acceptor"),
        );
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let acceptor2 = Some(Arc::clone(&acceptor));
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                false, // is_tls = false: plaintext connection before STARTTLS
                false, // is_submission = false: port 25
                peer.to_string(),
                config2,
                cred_store,
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                acceptor2, // tls_acceptor present → STARTTLS will be offered
            )
            .await;
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"EHLO client.example.com\r\nQUIT\r\n")
            .await
            .expect("write");
        client.shutdown().await.expect("shutdown");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");

        // STARTTLS must be offered (connection is plaintext, acceptor is present).
        assert!(
            response.contains("STARTTLS"),
            "STARTTLS must be offered on plaintext connection: {response}"
        );
        // AUTH must NOT be advertised: RFC 4954 §4 forbids advertising AUTH
        // on a connection that has not yet completed TLS, even when STARTTLS is offered.
        assert!(
            !response.contains("AUTH"),
            "AUTH must NOT appear in EHLO before STARTTLS on port 25: {response}"
        );
    }

    // AUTH before STARTTLS returns 530. Oracle: RFC 4954 §4.
    #[tokio::test]
    async fn test_auth_before_starttls_returns_530() {
        use rcgen::generate_simple_self_signed;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stoa_tls::install_ring_provider();
        let config = test_config();
        let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("test.crt");
        let key_path = dir.path().join("test.key");
        std::fs::write(&cert_path, cert_key.cert.pem().as_bytes()).expect("write cert");
        std::fs::write(&key_path, cert_key.key_pair.serialize_pem().as_bytes()).expect("write key");
        let acceptor = Arc::new(
            crate::tls::build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("build acceptor"),
        );
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let acceptor2 = Some(Arc::clone(&acceptor));
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                false,
                false,
                peer.to_string(),
                config2,
                Arc::new(CredentialStore::empty()),
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                acceptor2,
            )
            .await;
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"EHLO client.example.com\r\nAUTH PLAIN\r\n")
            .await
            .expect("write");
        client.shutdown().await.expect("shutdown");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");
        assert!(
            response.contains("530"),
            "AUTH before STARTTLS must return 530, got: {response}"
        );
        assert!(
            response.contains("5.7.0"),
            "530 must carry 5.7.0, got: {response}"
        );
        assert!(
            !response.contains("334"),
            "No AUTH challenge before STARTTLS: {response}"
        );
    }

    // Submission port (587, is_submission=true, is_tls=false): EHLO must
    // advertise AUTH PLAIN and the AUTH handler must honour it.
    // Oracle: stoa-ik62e — AUTH PLAIN broken on submission port.
    #[tokio::test]
    async fn test_auth_plain_succeeds_on_submission_port_without_tls() {
        use base64::Engine as _;
        use stoa_auth::UserCredential;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        stoa_tls::install_ring_provider();
        let hash = bcrypt::hash("hunter2", 4).expect("bcrypt");
        let creds = vec![UserCredential {
            username: "alice".to_string(),
            password: hash,
        }];
        let cred_store = Arc::new(
            CredentialStore::from_credentials(&creds)
                .expect("from_credentials must succeed for valid bcrypt hash"),
        );

        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let store2 = Arc::clone(&cred_store);
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                false, // is_tls = false: plaintext submission connection
                true,  // is_submission = true: port 587
                peer.to_string(),
                config2,
                store2,
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                None, // no TLS acceptor
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");

        // SASL PLAIN credential: "\0alice\0hunter2"
        let plain = base64::engine::general_purpose::STANDARD.encode(b"\x00alice\x00hunter2");
        let script = format!("EHLO client.example.com\r\nAUTH PLAIN {plain}\r\nQUIT\r\n");
        client.write_all(script.as_bytes()).await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");

        // EHLO must advertise AUTH on the submission port.
        assert!(
            response.contains("AUTH PLAIN"),
            "EHLO on submission port must advertise AUTH PLAIN: {response}"
        );
        // AUTH PLAIN must succeed (235).
        assert!(
            response.contains("235"),
            "AUTH PLAIN must succeed on submission port (is_submission=true, is_tls=false): {response}"
        );
        // Must not see 530 or 534.
        assert!(
            !response.contains("530") && !response.contains("534"),
            "AUTH must not be rejected on submission port: {response}"
        );
    }

    // ── EHLO/HELO injection guard ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_ehlo_with_bare_cr_returns_501() {
        // Injection vector: a bare CR (no LF) causes read_command_line to
        // include the injected text in the EHLO argument.  The injected
        // content would otherwise be interpolated verbatim into Received:.
        // b"EHLO evil\rX-Injected: header\r\n" is read as one command line.
        let client = b"EHLO evil\rX-Injected: header\r\nQUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("501"),
            "EHLO with bare CR in domain must return 501, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_ehlo_with_nul_returns_501() {
        let mut script = b"EHLO evil".to_vec();
        script.push(0); // NUL
        script.extend_from_slice(b"\r\nQUIT\r\n");
        let (response, _) = drive_session(&script).await;
        assert!(
            response.contains("501"),
            "EHLO with NUL must return 501, got: {response}"
        );
    }

    // ── ryw.1 + ryw.4: timeout test ──────────────────────────────────────────

    #[tokio::test]
    async fn test_command_timeout_sends_421() {
        // Use tokio's simulated time so the test does not sleep for real.
        tokio::time::pause();

        let config = Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 1, // 1-second timeout for this test
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: crate::config::LogFormat::Json,
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        });

        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(
                Box::new(stream),
                false,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Advance simulated time past the 1-second command timeout.
        tokio::time::advance(Duration::from_secs(2)).await;

        // After the timeout fires, the server sends 421 and closes the write half.
        // read_to_string completes once the write half is dropped.
        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut client, &mut response)
            .await
            .unwrap();
        server_task.await.unwrap();

        assert!(
            response.starts_with("220 "),
            "expected greeting before timeout: {response:?}"
        );
        assert!(
            response.contains("421"),
            "expected 421 timeout response, got: {response:?}"
        );
    }

    // ── Sieve script cache tests ──────────────────────────────────────────

    const MINIMAL_MESSAGE: &[u8] = b"From: a@example.com\r\nTo: b@example.com\r\n\r\nHi\r\n";

    #[tokio::test]
    async fn sieve_global_populates_cache_on_first_call() {
        let pool = crate::store::open(":memory:").await.unwrap();
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            b"keep;",
            true,
        )
        .await
        .unwrap();

        let cache = new_sieve_cache();
        sieve_global(
            &pool,
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
            &stoa_sieve_native::SieveEnv::new(),
        )
        .await;

        assert!(
            cache
                .lock()
                .await
                .contains_key(crate::config::GLOBAL_SCRIPT_KEY),
            "cache should contain _global after first call"
        );
    }

    #[tokio::test]
    async fn sieve_global_uses_cached_script_after_db_removal() {
        let pool = crate::store::open(":memory:").await.unwrap();
        crate::store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "default",
            b"discard;",
            true,
        )
        .await
        .unwrap();

        let cache = new_sieve_cache();
        // First call: DB load, cache populated, script is Discard.
        let actions = sieve_global(
            &pool,
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
            &stoa_sieve_native::SieveEnv::new(),
        )
        .await;
        assert!(
            actions
                .iter()
                .any(|a| *a == stoa_sieve_native::SieveAction::Discard),
            "expected Discard from compiled script"
        );

        // Remove from DB — subsequent call must use the cache, still Discard.
        crate::store::delete_script(&pool, crate::config::GLOBAL_SCRIPT_KEY, "default")
            .await
            .unwrap();
        let actions2 = sieve_global(
            &pool,
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
            &stoa_sieve_native::SieveEnv::new(),
        )
        .await;
        assert!(
            actions2
                .iter()
                .any(|a| *a == stoa_sieve_native::SieveAction::Discard),
            "expected Discard from cache even after DB removal"
        );
    }

    #[tokio::test]
    async fn sieve_global_no_cache_falls_back_to_keep_when_no_script() {
        let pool = crate::store::open(":memory:").await.unwrap();
        let actions = sieve_global(
            &pool,
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            None,
            &stoa_sieve_native::SieveEnv::new(),
        )
        .await;
        assert_eq!(actions, vec![stoa_sieve_native::SieveAction::Keep]);
    }

    // ── count_received_headers unit tests ────────────────────────────────────

    #[test]
    fn count_received_zero_when_none() {
        let msg = b"From: a@b.com\r\nSubject: hi\r\n\r\nBody\r\n";
        assert_eq!(count_received_headers(msg), 0);
    }

    #[test]
    fn count_received_one() {
        let msg = b"Received: from x by y\r\nFrom: a@b\r\n\r\nBody\r\n";
        assert_eq!(count_received_headers(msg), 1);
    }

    #[test]
    fn count_received_many() {
        let mut headers = Vec::new();
        for _ in 0..25 {
            headers.extend_from_slice(b"Received: from x by y\r\n");
        }
        headers.extend_from_slice(b"From: a@b\r\n\r\nBody\r\n");
        assert_eq!(count_received_headers(&headers), 25);
    }

    #[test]
    fn count_received_case_insensitive() {
        let msg = b"RECEIVED: from x\r\nreceived: from y\r\n\r\nBody\r\n";
        assert_eq!(count_received_headers(msg), 2);
    }

    #[test]
    fn count_received_body_ignored() {
        // A Received: line in the body must not be counted.
        let msg = b"From: a@b\r\n\r\nReceived: from x by y\r\n";
        assert_eq!(count_received_headers(msg), 0);
    }

    /// A message with 25+ Received: headers must be rejected with 554.
    #[tokio::test]
    async fn test_mail_loop_rejection_returns_554() {
        let config = test_config();

        // Build a DATA payload with 25 Received: headers — exactly the limit.
        let mut body_lines = String::new();
        for _ in 0..25 {
            body_lines.push_str("Received: from x ([1.2.3.4]) by y with SMTP; Mon, 1 Jan 2024\r\n");
        }
        body_lines.push_str("From: sender@example.com\r\nSubject: loop\r\n\r\nBody\r\n");

        let client_script = format!(
            "EHLO client.example.com\r\n\
             MAIL FROM:<sender@example.com>\r\n\
             RCPT TO:<rcpt@example.com>\r\n\
             DATA\r\n\
             {body_lines}.\r\n\
             QUIT\r\n"
        );

        let (response, _queue_dir) =
            drive_session_ext(client_script.as_bytes(), config, None).await;

        assert!(
            response.contains("554"),
            "25 Received hops must be rejected with 554, got: {response}"
        );
        // The DATA body must be rejected: no "250 OK" may appear after "354".
        let after_354 = response
            .find("354")
            .map(|p| &response[p..])
            .unwrap_or(&response);
        assert!(
            !after_354.contains("250 OK"),
            "DATA body must not receive 250 OK after loop detection: {response}"
        );
    }

    /// A message with exactly 24 Received: headers must still be accepted.
    #[tokio::test]
    async fn test_mail_loop_24_hops_accepted() {
        let config = test_config();

        let mut body_lines = String::new();
        for _ in 0..24 {
            body_lines.push_str("Received: from x ([1.2.3.4]) by y with SMTP; Mon, 1 Jan 2024\r\n");
        }
        body_lines.push_str("From: sender@example.com\r\nSubject: ok\r\n\r\nBody\r\n");

        let client_script = format!(
            "EHLO client.example.com\r\n\
             MAIL FROM:<sender@example.com>\r\n\
             RCPT TO:<rcpt@example.com>\r\n\
             DATA\r\n\
             {body_lines}.\r\n\
             QUIT\r\n"
        );

        let (response, _queue_dir) =
            drive_session_ext(client_script.as_bytes(), config, None).await;

        assert!(
            response.contains("250 OK"),
            "24 hops must be accepted with 250 OK, got: {response}"
        );
    }

    /// Sieve Keep with pool=None must return 452 (transient), not 250 OK.
    #[tokio::test]
    async fn test_sieve_keep_no_pool_returns_452() {
        let config = test_config();
        // Pass pool=None so the Keep action cannot deliver to INBOX.
        let (response, _) = drive_session_ext(FULL_MSG, config, None).await;
        assert!(
            response.contains("452"),
            "Sieve Keep with no pool must return 452 transient, got: {response}"
        );
    }

    /// When a credential store is non-empty, MAIL FROM without prior AUTH
    /// must be rejected with 530.
    #[tokio::test]
    async fn test_mail_from_requires_auth_when_credentials_configured() {
        use stoa_auth::{CredentialStore, UserCredential};
        use tokio::io::AsyncWriteExt;

        // bcrypt cost 4 is the minimum; fast enough for tests.
        let hash = bcrypt::hash("hunter2", 4).expect("bcrypt::hash");
        let creds = vec![UserCredential {
            username: "alice".to_string(),
            password: hash,
        }];
        let credential_store = Arc::new(
            CredentialStore::from_credentials(&creds).expect("test setup: valid bcrypt hash"),
        );

        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let store2 = Arc::clone(&credential_store);
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                Box::new(stream),
                true,
                false,
                peer.to_string(),
                config2,
                store2,
                queue2,
                None,
                Arc::new(crate::dns_cache::DnsCache::new()),
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let script = b"EHLO client.example.com\r\nMAIL FROM:<sender@example.com>\r\nQUIT\r\n";
        client.write_all(script).await.expect("write");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");

        assert!(
            response.contains("530 5.7.0 Authentication required"),
            "unauthenticated MAIL FROM must be rejected with 530 when auth is configured, got: {response}"
        );
        // Verify no 354 DATA prompt was sent (i.e., we never accepted MAIL FROM).
        assert!(
            !response.contains("354"),
            "MAIL FROM must not succeed without auth: {response}"
        );
    }
    // ── stoa-2xeks.21: EHLO REQUIRETLS advertisement ─────────────────────────

    // T7: REQUIRETLS advertised in EHLO when is_tls=true.
    // Oracle: RFC 8689 §2 — REQUIRETLS MUST appear in EHLO only on TLS.
    // We use the loopback listener approach already established in test_basic_smtp_session.
    #[tokio::test]
    async fn ehlo_includes_requiretls_on_tls_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let local = listener.local_addr().expect("local_addr");
            let config2 = config.clone();
            let queue2 = Arc::clone(&nntp_queue);
            tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.expect("accept");
                run_session(
                    Box::new(stream),
                    true,
                    false,
                    peer.to_string(),
                    config2,
                    Arc::new(CredentialStore::empty()),
                    queue2,
                    None,
                    Arc::new(crate::dns_cache::DnsCache::new()),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            });
            local
        };
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"EHLO client.example.com\r\nQUIT\r\n")
            .await
            .expect("write");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");
        assert!(
            response.contains("REQUIRETLS"),
            "REQUIRETLS must appear in EHLO when is_tls=true, got: {response}"
        );
    }

    // T8: REQUIRETLS NOT advertised in EHLO when is_tls=false.
    // Oracle: RFC 8689 §2 — advertising REQUIRETLS on plaintext is forbidden.
    #[tokio::test]
    async fn ehlo_excludes_requiretls_on_plaintext_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let local = listener.local_addr().expect("local_addr");
            let config2 = config.clone();
            let queue2 = Arc::clone(&nntp_queue);
            tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.expect("accept");
                run_session(
                    Box::new(stream),
                    false,
                    false,
                    peer.to_string(),
                    config2,
                    Arc::new(CredentialStore::empty()),
                    queue2,
                    None,
                    Arc::new(crate::dns_cache::DnsCache::new()),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            });
            local
        };
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"EHLO client.example.com\r\nQUIT\r\n")
            .await
            .expect("write");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");
        assert!(
            !response.contains("REQUIRETLS"),
            "REQUIRETLS must NOT appear in EHLO when is_tls=false, got: {response}"
        );
    }

    // T9: MAIL FROM with REQUIRETLS on a non-TLS session must be rejected with
    // "530 5.7.0 REQUIRETLS requires TLS" (RFC 8689 §2).
    #[tokio::test]
    async fn requiretls_mail_from_on_plaintext_rejected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let local = listener.local_addr().expect("local_addr");
            let config2 = config.clone();
            let queue2 = Arc::clone(&nntp_queue);
            tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.expect("accept");
                run_session(
                    Box::new(stream),
                    false,
                    false,
                    peer.to_string(),
                    config2,
                    Arc::new(CredentialStore::empty()),
                    queue2,
                    None,
                    Arc::new(crate::dns_cache::DnsCache::new()),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            });
            local
        };
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let script =
            b"EHLO client.example.com\r\nMAIL FROM:<sender@example.com> REQUIRETLS\r\nQUIT\r\n";
        client.write_all(script).await.expect("write");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");
        assert!(
            response.contains("530") && response.contains("REQUIRETLS"),
            "REQUIRETLS on plaintext must be rejected with 530, got: {response}"
        );
        // EHLO ends with "250 OK" so we cannot assert its absence;
        // assert instead that no "354" DATA prompt was issued.
        assert!(
            !response.contains("354"),
            "DATA prompt must not appear after REQUIRETLS rejection: {response}"
        );
    }
}
