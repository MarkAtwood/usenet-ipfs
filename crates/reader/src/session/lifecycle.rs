use std::net::SocketAddr;
use std::sync::Arc;

use cid::Cid;
use mailparse::parse_headers;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn, Instrument};

use stoa_core::audit::AuditEvent;
use stoa_core::validation::validate_message_id;
use stoa_core::ArticleRootNode;

use crate::{
    config::Config,
    post::{
        find_header_boundary,
        injection::{
            extract_injection_source, inject_injection_date, inject_injection_info,
            inject_message_id, prepend_path_header, strip_server_synthesized_headers,
        },
        ipfs_write::{write_ipld_article_to_ipfs, IpfsBlockStore},
        log_append::append_to_groups,
        pipeline::check_duplicate_msgid,
        sign::{sign_article, verify_article_sig},
        smtp_relay::maybe_enqueue_smtp_relay,
    },
    search::{ArticleIndexRequest, SearchError},
    session::{
        command::{
            parse_command, ArticleRange, ArticleRef, Command, ListSubcommand, OverArg, SearchKey,
        },
        commands::{
            fetch::{
                article_response, body_response, head_response, xcid_response, ArticleContent,
            },
            hdr::{extract_field, hdr_response, HdrRecord},
            list::GroupInfo,
            over::over_response,
            post::{complete_post, read_dot_terminated},
        },
        context::{SessionContext, SessionFlags},
        dispatch::dispatch,
        response::Response,
        state::SessionState,
    },
    store::{
        overview::extract_overview,
        server_stores::ServerStores,
        staging_fallback::{fetch_from_staging, StagingResult},
    },
};

/// Whether this listener accepts plain NNTP or implicit-TLS (NNTPS) connections.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ListenerKind {
    /// Plain NNTP (port 119 / STARTTLS upgrade path).
    Plain,
    /// Implicit TLS / NNTPS (port 563).
    Tls,
}

/// Run a complete NNTP session on the given TCP stream.
///
/// `kind`: `ListenerKind::Tls` for NNTPS connections (implicit TLS, accepted by
/// the caller before this function is invoked). `ListenerKind::Plain` for plain
/// connections on port 119 — STARTTLS is available if `tls_acceptor` is `Some`.
/// `tls_acceptor`: pre-loaded TLS acceptor, shared across connections.
/// Must be `Some` when `kind = ListenerKind::Tls`. On plain connections, `Some`
/// enables STARTTLS; `None` disables it.
pub async fn run_session(
    stream: TcpStream,
    kind: ListenerKind,
    config: &Config,
    stores: Arc<ServerStores>,
    tls_acceptor: Option<Arc<crate::tls::TlsAcceptor>>,
) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("failed to get peer addr: {e}");
            return;
        }
    };

    if kind == ListenerKind::Tls {
        let acceptor = match tls_acceptor {
            Some(a) => a,
            None => {
                warn!(peer = %peer_addr, "TLS acceptor missing for NNTPS connection");
                return;
            }
        };
        match crate::tls::accept_tls(&acceptor, stream).await {
            Ok(tls_stream) => {
                let (client_cert_fp, client_cert_der) =
                    crate::tls::extract_client_cert_data(&tls_stream);
                run_session_io(
                    tls_stream,
                    peer_addr,
                    config,
                    true,
                    client_cert_fp,
                    client_cert_der,
                    stores,
                )
                .await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "TLS handshake failed: {e}");
            }
        }
    } else {
        run_plain_session(stream, peer_addr, config, stores, tls_acceptor).await;
    }
}

/// Populate `ctx.known_groups` from the article_numbers store.
///
/// Called once at the start of each session so that GROUP and LIST commands
/// can return 411 for newsgroups not currently carried by this server.
/// Groups that have at least one article are considered "carried".
async fn load_known_groups(stores: &ServerStores, ctx: &mut SessionContext) {
    match stores.article_numbers.list_groups().await {
        Ok(groups) => {
            ctx.known_groups = groups
                .into_iter()
                .map(|(name, low, high)| GroupInfo {
                    name,
                    low,
                    high,
                    posting_allowed: true,
                    description: String::new(),
                })
                .collect();
            ctx.known_groups
                .sort_unstable_by(|a, b| a.name.cmp(&b.name));
        }
        Err(e) => {
            warn!("load_known_groups: article_numbers.list_groups failed: {e}");
        }
    }
}

/// Run a plain-text NNTP session (port 119).
///
/// If TLS cert/key are configured, STARTTLS is advertised in CAPABILITIES.
/// When the client issues STARTTLS, a 382 response is sent and the session
/// is upgraded to TLS in-place (RFC 4642).  The post-upgrade session resets
/// auth state but does NOT re-send a greeting.
///
/// If TLS is not configured, AUTHINFO returns 483 when `auth.required = true`
/// and callers must connect to the NNTPS port (563).
async fn run_plain_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: &Config,
    stores: Arc<ServerStores>,
    tls_acceptor: Option<Arc<crate::tls::TlsAcceptor>>,
) {
    info!(peer = %peer_addr, "plain session started");
    let start = std::time::Instant::now();

    if tls_acceptor.is_some() {
        debug!(peer = %peer_addr, "STARTTLS available on plain connection");
    }

    let auth_required = config.auth.required;
    let posting_allowed = !config.read_only;
    let mut ctx = SessionContext::new(
        peer_addr,
        SessionFlags {
            auth_required,
            posting_allowed,
            tls_active: false,
        },
    );
    ctx.starttls_available = tls_acceptor.is_some();
    ctx.search_available = stores.search_index.is_some();
    load_known_groups(&stores, &mut ctx).await;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if write_half
        .write_all(greeting.to_bytes().as_slice())
        .await
        .is_err()
    {
        let elapsed = start.elapsed();
        info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
        return;
    }

    let exit = run_command_loop(
        &mut reader,
        &mut write_half,
        &mut ctx,
        peer_addr,
        config,
        &stores,
    )
    .await;

    // STARTTLS upgrade: command loop sent 382 and signalled StartTlsRequested.
    if matches!(exit, CommandLoopExit::StartTlsRequested) {
        let acceptor = match tls_acceptor {
            Some(a) => a,
            None => {
                warn!(peer = %peer_addr, "STARTTLS: no acceptor at upgrade time");
                let elapsed = start.elapsed();
                info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
                return;
            }
        };
        // Reassemble the TCP stream from the split halves.
        let stream = match reader.into_inner().reunite(write_half) {
            Ok(s) => s,
            Err(e) => {
                warn!(peer = %peer_addr, "STARTTLS: stream reunite failed: {e}");
                let elapsed = start.elapsed();
                info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
                return;
            }
        };
        info!(peer = %peer_addr, "STARTTLS: performing TLS handshake");
        match crate::tls::accept_tls(&acceptor, stream).await {
            Ok(tls_stream) => {
                let (client_cert_fp, client_cert_der) =
                    crate::tls::extract_client_cert_data(&tls_stream);
                run_session_post_starttls(
                    tls_stream,
                    peer_addr,
                    config,
                    client_cert_fp,
                    client_cert_der,
                    stores,
                )
                .await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "STARTTLS: TLS handshake failed: {e}");
            }
        }
    }

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
}

/// Run the NNTP session after a successful STARTTLS upgrade.
///
/// Per RFC 4642 §2.2, the server MUST NOT re-send the greeting after the TLS
/// handshake. Session state is reset to the post-greeting state (auth cleared).
async fn run_session_post_starttls<S>(
    stream: S,
    peer_addr: SocketAddr,
    config: &Config,
    client_cert_fingerprint: Option<String>,
    client_cert_der: Option<Vec<u8>>,
    stores: Arc<ServerStores>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    info!(peer = %peer_addr, "STARTTLS: session resumed over TLS");

    let auth_required = config.auth.required;
    let posting_allowed = !config.read_only;
    let mut ctx = SessionContext::new(
        peer_addr,
        SessionFlags {
            auth_required,
            posting_allowed,
            tls_active: true,
        },
    );
    ctx.starttls_available = false; // already TLS; no further upgrade
    ctx.search_available = stores.search_index.is_some();
    ctx.client_cert_fingerprint = client_cert_fingerprint;
    ctx.client_cert_der = client_cert_der;
    load_known_groups(&stores, &mut ctx).await;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // No greeting — RFC 4642 §2.2.
    let _exit = run_command_loop(
        &mut reader,
        &mut writer,
        &mut ctx,
        peer_addr,
        config,
        &stores,
    )
    .await;
}

/// Return value from `run_command_loop` encoding why the loop exited.
enum CommandLoopExit {
    /// Normal exit: QUIT, EOF, read/write error, or idle timeout.
    Done,
    /// The client issued STARTTLS and received a 382; the caller must
    /// perform the TLS handshake before resuming the session.
    StartTlsRequested,
}

/// Execute the NNTP command loop on a generic async read/write pair.
///
/// Runs until QUIT, EOF, read/write error, or idle timeout.
async fn run_command_loop<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    ctx: &mut SessionContext,
    peer_addr: SocketAddr,
    config: &Config,
    stores: &ServerStores,
) -> CommandLoopExit
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line_buf = String::new();
    let cmd_timeout = std::time::Duration::from_secs(config.limits.command_timeout_secs);

    // Helper: write a Response and return Done on I/O error.
    // Used in the command routing match below.
    macro_rules! send {
        ($resp:expr) => {
            if writer.write_all($resp.to_bytes().as_slice()).await.is_err() {
                return CommandLoopExit::Done;
            }
        };
    }

    loop {
        line_buf.clear();
        let n = match tokio::time::timeout(cmd_timeout, reader.read_line(&mut line_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                warn!(peer = %peer_addr, "read error: {e}");
                return CommandLoopExit::Done;
            }
            Err(_) => {
                let resp = Response::new(400, "Timeout - closing connection");
                let _ = writer.write_all(resp.to_bytes().as_slice()).await;
                return CommandLoopExit::Done;
            }
        };

        if n == 0 {
            debug!(peer = %peer_addr, "client disconnected");
            return CommandLoopExit::Done;
        }

        let line = line_buf.trim_end_matches(['\r', '\n']);
        if line.to_ascii_uppercase().starts_with("AUTHINFO PASS ") {
            debug!(peer = %peer_addr, cmd = "AUTHINFO PASS <redacted>", "received");
        } else {
            debug!(peer = %peer_addr, cmd = %line, "received");
        }

        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(_) => {
                let resp = Response::unknown_command();
                if writer.write_all(resp.to_bytes().as_slice()).await.is_err() {
                    return CommandLoopExit::Done;
                }
                continue;
            }
        };

        // Auth gate: if not yet authenticated, let dispatch() enforce the state
        // machine.  All data commands return 480 Authentication Required there.
        // Without this gate the pre-dispatch match below would execute article
        // lookups for unauthenticated clients (zmn9.23).
        if ctx.state == SessionState::Authenticating {
            let resp = dispatch(
                ctx,
                cmd,
                &config.auth,
                &stores.client_cert_store,
                &stores.trusted_issuer_store,
            );
            send!(resp);
            continue;
        }

        // Route commands that need async store access before dispatch, or that
        // require special handling (STARTTLS, AUTHINFO PASS).  All other commands
        // fall through to the synchronous `dispatch` function at the end of the loop.
        match &cmd {
            Command::Article(Some(ArticleRef::MessageId(msgid))) => {
                let resp = lookup_article_by_msgid(stores, msgid).await;
                send!(resp);
                continue;
            }
            Command::Article(Some(ArticleRef::Cid(cid_str))) => {
                let resp = lookup_article_by_cid(stores, cid_str).await;
                send!(resp);
                continue;
            }
            Command::Article(Some(ArticleRef::Number(n))) => {
                let resp = match lookup_article_content_by_number(stores, ctx, *n).await {
                    Ok(content) => article_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Article(None) => {
                let sg = match ctx.selected_group.as_ref() {
                    None => {
                        send!(Response::no_newsgroup_selected());
                        continue;
                    }
                    Some(sg) => sg,
                };
                let n = match sg.article_number {
                    None => {
                        send!(Response::new(420, "Current article number is invalid"));
                        continue;
                    }
                    Some(n) => n,
                };
                let resp = match lookup_article_content_by_number(stores, ctx, n).await {
                    Ok(content) => article_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Head(Some(ArticleRef::MessageId(msgid))) => {
                let resp = lookup_head_by_msgid(stores, msgid).await;
                send!(resp);
                continue;
            }
            Command::Head(Some(ArticleRef::Cid(cid_str))) => {
                let resp = lookup_head_by_cid(stores, cid_str).await;
                send!(resp);
                continue;
            }
            Command::Head(Some(ArticleRef::Number(n))) => {
                let resp = match lookup_article_content_by_number(stores, ctx, *n).await {
                    Ok(content) => head_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Head(None) => {
                let sg = match ctx.selected_group.as_ref() {
                    None => {
                        send!(Response::no_newsgroup_selected());
                        continue;
                    }
                    Some(sg) => sg,
                };
                let n = match sg.article_number {
                    None => {
                        send!(Response::new(420, "Current article number is invalid"));
                        continue;
                    }
                    Some(n) => n,
                };
                let resp = match lookup_article_content_by_number(stores, ctx, n).await {
                    Ok(content) => head_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Body(Some(ArticleRef::MessageId(msgid))) => {
                let resp = lookup_body_by_msgid(stores, msgid).await;
                send!(resp);
                continue;
            }
            Command::Body(Some(ArticleRef::Cid(cid_str))) => {
                let resp = lookup_body_by_cid(stores, cid_str).await;
                send!(resp);
                continue;
            }
            Command::Body(Some(ArticleRef::Number(n))) => {
                let resp = match lookup_article_content_by_number(stores, ctx, *n).await {
                    Ok(content) => body_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Body(None) => {
                let sg = match ctx.selected_group.as_ref() {
                    None => {
                        send!(Response::no_newsgroup_selected());
                        continue;
                    }
                    Some(sg) => sg,
                };
                let n = match sg.article_number {
                    None => {
                        send!(Response::new(420, "Current article number is invalid"));
                        continue;
                    }
                    Some(n) => n,
                };
                let resp = match lookup_article_content_by_number(stores, ctx, n).await {
                    Ok(content) => body_response(&content),
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Stat(Some(ArticleRef::Number(n))) => {
                let resp = match lookup_article_content_by_number(stores, ctx, *n).await {
                    Ok(content) => {
                        Response::article_exists(content.article_number, &content.message_id)
                    }
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Stat(None) => {
                let sg = match ctx.selected_group.as_ref() {
                    None => {
                        send!(Response::no_newsgroup_selected());
                        continue;
                    }
                    Some(sg) => sg,
                };
                let n = match sg.article_number {
                    None => {
                        send!(Response::new(420, "Current article number is invalid"));
                        continue;
                    }
                    Some(n) => n,
                };
                let resp = match lookup_article_content_by_number(stores, ctx, n).await {
                    Ok(content) => {
                        Response::article_exists(content.article_number, &content.message_id)
                    }
                    Err(r) => r,
                };
                send!(resp);
                continue;
            }
            Command::Stat(Some(ArticleRef::MessageId(msgid))) => {
                let resp = stat_by_msgid(stores, msgid).await;
                send!(resp);
                continue;
            }
            Command::Stat(Some(ArticleRef::Cid(cid_str))) => {
                let resp = stat_by_cid(stores, cid_str).await;
                send!(resp);
                continue;
            }
            Command::Xcid(arg) => {
                if let Some(ref msgid) = arg {
                    if validate_message_id(msgid).is_err() {
                        send!(Response::syntax_error());
                        continue;
                    }
                }
                let resp = handle_xcid(
                    stores,
                    arg.as_deref(),
                    ctx.selected_group.as_ref().map(|sg| sg.name.as_str()),
                    ctx.selected_group.as_ref().and_then(|sg| sg.article_number),
                )
                .await;
                send!(resp);
                continue;
            }
            Command::Xverify {
                message_id,
                expected_cid,
                verify_sig,
            } => {
                if validate_message_id(message_id).is_err() {
                    send!(Response::syntax_error());
                    continue;
                }
                let resp = handle_xverify(stores, message_id, expected_cid, *verify_sig).await;
                send!(resp);
                continue;
            }
            Command::Xget(cid_str) => {
                let resp = crate::session::commands::xget::handle_xget(
                    cid_str,
                    stores.ipfs_store.as_ref(),
                    stores.msgid_map.as_ref(),
                )
                .await;
                send!(resp);
                continue;
            }
            Command::Next => {
                let resp = handle_next_live(stores, ctx).await;
                send!(resp);
                continue;
            }
            Command::Last => {
                let resp = handle_last_live(stores, ctx).await;
                send!(resp);
                continue;
            }
            Command::Ihave(message_id) => {
                if validate_message_id(message_id).is_err() {
                    send!(Response::syntax_error());
                    continue;
                }
                // RFC 3977 §6.3.2: send 335, read dot-terminated body, respond 235/437.
                // Storage of transit-fed articles is not yet implemented; respond 437
                // (article rejected) after reading the body to keep the connection valid.
                if writer
                    .write_all(b"335 Send it; end with <CR-LF>.<CR-LF>\r\n")
                    .await
                    .is_err()
                {
                    return CommandLoopExit::Done;
                }
                let body_timeout =
                    std::time::Duration::from_secs(config.limits.post_body_timeout_secs);
                let read_result = tokio::time::timeout(
                    body_timeout,
                    read_dot_terminated(reader, config.limits.max_article_bytes),
                )
                .await;
                match read_result {
                    Err(_elapsed) => {
                        warn!(peer = %peer_addr, "IHAVE body upload timed out");
                        let _ = writer
                            .write_all(b"400 Timeout - closing connection\r\n")
                            .await;
                        return CommandLoopExit::Done;
                    }
                    Ok(Ok(_article_bytes)) => {
                        // Body received; storage not yet implemented — reject.
                        if writer.write_all(b"437 Article rejected\r\n").await.is_err() {
                            return CommandLoopExit::Done;
                        }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                        warn!(peer = %peer_addr, "IHAVE rejected: article too large");
                        if writer
                            .write_all(b"437 Article too large\r\n")
                            .await
                            .is_err()
                        {
                            return CommandLoopExit::Done;
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(peer = %peer_addr, "IHAVE read error: {e}");
                        return CommandLoopExit::Done;
                    }
                }
                continue;
            }
            Command::Group(name) => {
                let resp = handle_group_live(stores, ctx, name).await;
                send!(resp);
                continue;
            }
            Command::List(ListSubcommand::Active(ref wildmat)) => {
                let resp = handle_list_active_live(stores, wildmat.as_deref()).await;
                send!(resp);
                continue;
            }
            Command::Newnews {
                wildmat,
                ref date,
                ref time,
            } => {
                let resp = handle_newnews_live(stores, wildmat, date, time).await;
                send!(resp);
                continue;
            }
            Command::Over(arg) => {
                let resp = handle_over_live(stores, ctx, arg.as_ref()).await;
                send!(resp);
                continue;
            }
            Command::Hdr {
                field,
                range_or_msgid,
            } => {
                let resp = handle_hdr_live(stores, ctx, field, range_or_msgid.as_deref()).await;
                send!(resp);
                continue;
            }
            // STARTTLS: mid-session TLS upgrade (RFC 4642).
            // Send 382 + return StartTlsRequested when available; otherwise fall
            // through to dispatch (which returns 502).
            Command::StartTls => {
                if ctx.starttls_available && !ctx.tls_active {
                    // RFC 4642 §2.2: the client MUST NOT pipeline commands after
                    // STARTTLS.  This check is best-effort: it catches data that
                    // is already in the BufReader's internal buffer, but cannot
                    // detect commands that the client has sent but that have not
                    // yet been copied from the kernel TCP receive buffer into the
                    // userspace buffer.  A well-behaved client will wait for the
                    // 382 before sending further data; a malicious client may still
                    // slip a command through the gap.  Connections caught by this
                    // check are closed; connections that slip through will see
                    // garbled output once the TLS handshake starts.
                    if !reader.buffer().is_empty() {
                        warn!(peer = %peer_addr, "STARTTLS: pipelined data detected (best-effort check), closing");
                        let _ = writer.write_all(b"502 Command unavailable\r\n").await;
                        return CommandLoopExit::Done;
                    }
                    if writer
                        .write_all(Response::starttls_ready().to_bytes().as_slice())
                        .await
                        .is_err()
                    {
                        return CommandLoopExit::Done;
                    }
                    return CommandLoopExit::StartTlsRequested; // caller performs TLS handshake
                }
                // Not available or already active — fall through to dispatch (returns 502).
            }
            // AUTHINFO PASS: async bcrypt credential check via CredentialStore.
            // RFC 3977 §7.1.1 / RFC 4643: if auth.required and TLS not active, reject 483.
            Command::AuthinfoPass(password) => {
                if config.auth.required && !ctx.tls_active {
                    send!(Response::new(483, "Encryption required for authentication"));
                    continue;
                }
                let username = match ctx.pending_auth_user.take() {
                    Some(u) => u,
                    None => {
                        send!(Response::authentication_out_of_sequence());
                        continue;
                    }
                };
                let accepted = if config.auth.is_dev_mode() {
                    tracing::warn!(
                        peer = %peer_addr,
                        username = %username,
                        "AUTHINFO: dev mode active — credential check bypassed; \
                         do not use in production"
                    );
                    true
                } else {
                    stores.credential_store.check(&username, password).await
                };
                if let Some(logger) = &stores.audit_logger {
                    logger.log(AuditEvent::AuthAttempt {
                        peer_addr: peer_addr.to_string(),
                        user: username.clone(),
                        success: accepted,
                        service: "nntp".to_string(),
                        auth_method: "password".to_string(),
                    });
                }
                let peer_ip = peer_addr.ip();
                if accepted {
                    // Stable structured log field (fail2ban-compatible): event=auth_success.
                    debug!(
                        event = "auth_success",
                        service = "nntp",
                        remote_ip = %peer_ip,
                        username = %username,
                    );
                    stores
                        .auth_failure_tracker
                        .lock()
                        .await
                        .record_success(peer_ip);
                    ctx.state = SessionState::Active;
                    ctx.is_drain_session = config
                        .auth
                        .drain_username
                        .as_deref()
                        .map(|dn| dn.eq_ignore_ascii_case(&username))
                        .unwrap_or(false);
                    ctx.authenticated_user = Some(username);
                    ctx.auth_failure_count = 0;
                    send!(Response::authentication_accepted());
                } else {
                    // Stable structured log field (fail2ban-compatible): event=auth_failure.
                    warn!(
                        event = "auth_failure",
                        service = "nntp",
                        remote_ip = %peer_ip,
                        username = %username,
                        reason = "bad_password",
                    );
                    let lockout = stores
                        .auth_failure_tracker
                        .lock()
                        .await
                        .record_failure(peer_ip);
                    if lockout {
                        // Stable structured log field (fail2ban-compatible): event=auth_lockout.
                        warn!(
                            event = "auth_lockout",
                            service = "nntp",
                            remote_ip = %peer_ip,
                            "auth_lockout: failure threshold reached for IP"
                        );
                    }
                    ctx.auth_failure_count += 1;
                    if ctx.auth_failure_count >= crate::session::context::MAX_AUTH_FAILURES {
                        warn!(peer = %peer_addr, "AUTHINFO: too many failures, closing connection");
                        let resp = Response::new(400, "Too many authentication failures");
                        let _ = writer.write_all(resp.to_bytes().as_slice()).await;
                        return CommandLoopExit::Done;
                    }
                    send!(Response::authentication_failed());
                }
                continue;
            }
            Command::Search { key, value } => {
                let resp = handle_nntp_search(stores, ctx, key, value).await;
                if writer.write_all(&resp).await.is_err() {
                    return CommandLoopExit::Done;
                }
                continue;
            }
            // AUTHINFO SASL OAUTHBEARER — RFC 4643 §2.3 / RFC 7628.
            // Requires TLS (same rule as AUTHINFO USER/PASS when auth.required).
            // The initial response is a base64-encoded OAUTHBEARER client message;
            // we extract the Bearer token and validate it via the OIDC store.
            Command::AuthinfoSaslOauthbearer(initial_response) => {
                if config.auth.required && !ctx.tls_active {
                    send!(Response::new(483, "Encryption required for authentication"));
                    continue;
                }
                let oidc = match stores.oidc_store.as_ref() {
                    Some(o) => o,
                    None => {
                        send!(Response::new(
                            503,
                            "SASL OAUTHBEARER not configured on this server"
                        ));
                        continue;
                    }
                };
                if initial_response.is_empty() {
                    send!(Response::new(
                        481,
                        "Authentication failed: OAUTHBEARER initial response required"
                    ));
                    continue;
                }
                // Base64-decode and extract the Bearer token.
                let token = match extract_oauthbearer_token(initial_response) {
                    Some(t) => t,
                    None => {
                        send!(Response::new(
                            481,
                            "Authentication failed: malformed OAUTHBEARER initial response"
                        ));
                        continue;
                    }
                };
                let result = oidc.validate_jwt(&token).await;
                let peer_ip = peer_addr.ip();
                match result {
                    Ok(username) => {
                        debug!(
                            event = "auth_success",
                            service = "nntp",
                            remote_ip = %peer_ip,
                            username = %username,
                        );
                        stores
                            .auth_failure_tracker
                            .lock()
                            .await
                            .record_success(peer_ip);
                        if let Some(logger) = &stores.audit_logger {
                            logger.log(AuditEvent::AuthAttempt {
                                peer_addr: peer_addr.to_string(),
                                user: username.clone(),
                                success: true,
                                service: "nntp".to_string(),
                                auth_method: "oauthbearer".to_string(),
                            });
                        }
                        ctx.state = SessionState::Active;
                        ctx.authenticated_user = Some(username);
                        ctx.auth_failure_count = 0;
                        send!(Response::authentication_accepted());
                    }
                    Err(e) => {
                        warn!(
                            event = "auth_failure",
                            service = "nntp",
                            remote_ip = %peer_ip,
                            reason = "oauthbearer_jwt_invalid",
                            "OAUTHBEARER: {e}",
                        );
                        let lockout = stores
                            .auth_failure_tracker
                            .lock()
                            .await
                            .record_failure(peer_ip);
                        if lockout {
                            warn!(
                                event = "auth_lockout",
                                service = "nntp",
                                remote_ip = %peer_ip,
                                "auth_lockout: failure threshold reached for IP"
                            );
                        }
                        if let Some(logger) = &stores.audit_logger {
                            logger.log(AuditEvent::AuthAttempt {
                                peer_addr: peer_addr.to_string(),
                                user: String::new(),
                                success: false,
                                service: "nntp".to_string(),
                                auth_method: "oauthbearer".to_string(),
                            });
                        }
                        ctx.auth_failure_count += 1;
                        if ctx.auth_failure_count >= crate::session::context::MAX_AUTH_FAILURES {
                            warn!(peer = %peer_addr, "AUTHINFO SASL: too many failures, closing");
                            let resp = Response::new(400, "Too many authentication failures");
                            let _ = writer.write_all(resp.to_bytes().as_slice()).await;
                            return CommandLoopExit::Done;
                        }
                        send!(Response::authentication_failed());
                    }
                }
                continue;
            }
            _ => {} // fall through to dispatch
        }

        let is_quit = matches!(cmd, Command::Quit);
        let is_post = matches!(cmd, Command::Post);
        let cmd_label = line
            .split_whitespace()
            .next()
            .unwrap_or("UNKNOWN")
            .to_uppercase();
        let cmd_start = std::time::Instant::now();
        let resp = {
            let _span = tracing::info_span!(
                "nntp.command",
                "nntp.command" = %cmd_label,
                "net.peer.ip" = %peer_addr,
            )
            .entered();
            dispatch(
                ctx,
                cmd,
                &config.auth,
                &stores.client_cert_store,
                &stores.trusted_issuer_store,
            )
        };
        let elapsed = cmd_start.elapsed();
        crate::metrics::NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&[cmd_label.as_str()])
            .observe(elapsed.as_secs_f64());
        let threshold = config.limits.slow_command_threshold_ms;
        if threshold > 0 && elapsed.as_millis() as u64 >= threshold {
            warn!(
                event = "slow_command",
                command = %cmd_label,
                elapsed_ms = elapsed.as_millis() as u64,
                remote_ip = %peer_addr,
                "slow NNTP command",
            );
        }
        let resp_code = resp.code;

        if writer.write_all(resp.to_bytes().as_slice()).await.is_err() {
            return CommandLoopExit::Done;
        }

        if is_quit {
            return CommandLoopExit::Done;
        }

        // POST two-phase completion: if dispatch returned 340, read the article.
        if is_post && resp_code == 340 {
            let body_timeout = std::time::Duration::from_secs(config.limits.post_body_timeout_secs);
            let read_result = tokio::time::timeout(
                body_timeout,
                read_dot_terminated(reader, config.limits.max_article_bytes),
            )
            .await;
            let article_bytes = match read_result {
                Err(_elapsed) => {
                    warn!(peer = %peer_addr, "post body upload timed out");
                    let _ = writer
                        .write_all(b"400 Timeout - closing connection\r\n")
                        .await;
                    return CommandLoopExit::Done;
                }
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Article exceeded the size limit.  The stream was drained to
                    // the dot-terminator, so the connection is still valid.
                    warn!(peer = %peer_addr, "post rejected: article too large");
                    if writer
                        .write_all(b"441 Article too large\r\n")
                        .await
                        .is_err()
                    {
                        return CommandLoopExit::Done;
                    }
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(peer = %peer_addr, "post read error: {e}");
                    return CommandLoopExit::Done;
                }
            };

            let (final_resp, post_meta) = run_post_pipeline(
                &article_bytes,
                stores,
                config.limits.max_article_bytes,
                ctx.is_drain_session,
                &peer_addr.ip().to_string(),
                ctx.authenticated_user.as_deref(),
            )
            .await;
            if let Some(logger) = &stores.audit_logger {
                match post_meta {
                    Some(ref meta) => logger.log(AuditEvent::ArticlePosted {
                        peer_addr: peer_addr.to_string(),
                        username: ctx.authenticated_user.clone(),
                        message_id: meta.message_id.clone(),
                        newsgroups: meta.newsgroups.clone(),
                        cid: meta.cid.clone(),
                    }),
                    None => logger.log(AuditEvent::ArticleRejected {
                        peer_addr: peer_addr.to_string(),
                        username: ctx.authenticated_user.clone(),
                        message_id: None,
                        reason: final_resp.text.clone(),
                    }),
                }
            }
            if writer
                .write_all(final_resp.to_bytes().as_slice())
                .await
                .is_err()
            {
                return CommandLoopExit::Done;
            }
        }
    }
}

/// Run the NNTP protocol loop on a generic async I/O stream.
///
/// `is_tls`: true for NNTPS connections, false for plain.
/// `client_cert_fingerprint`: SHA-256 fingerprint of the client's TLS cert, if
/// one was presented during the handshake.  `None` for plain connections or
/// when the client did not send a certificate.
/// `client_cert_der`: raw DER bytes of the leaf certificate for issuer-based
/// auth.  `None` for plain connections or when the client did not send a cert.
async fn run_session_io<S>(
    stream: S,
    peer_addr: SocketAddr,
    config: &Config,
    is_tls: bool,
    client_cert_fingerprint: Option<String>,
    client_cert_der: Option<Vec<u8>>,
    stores: Arc<ServerStores>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    info!(peer = %peer_addr, "session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = !config.read_only;
    let mut ctx = SessionContext::new(
        peer_addr,
        SessionFlags {
            auth_required,
            posting_allowed,
            tls_active: is_tls,
        },
    );
    ctx.search_available = stores.search_index.is_some();
    ctx.client_cert_fingerprint = client_cert_fingerprint;
    ctx.client_cert_der = client_cert_der;
    load_known_groups(&stores, &mut ctx).await;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if writer
        .write_all(greeting.to_bytes().as_slice())
        .await
        .is_err()
    {
        return;
    }

    let _exit = run_command_loop(
        &mut reader,
        &mut writer,
        &mut ctx,
        peer_addr,
        config,
        &stores,
    )
    .await;

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "session ended");
}

/// Validate and store a POSTed article through the full pipeline.
///
/// Steps:
/// 1. Extract and remove the `X-Stoa-Injection-Source:` header (if
///    present) to determine the injection source.
/// 2. Validate headers via `complete_post` (sync).
/// 3. Check for duplicate message-id.
/// 4. Sign the article with the operator key.
/// 5. Generate HLC timestamps (one per destination group).
/// 6. Write signed bytes to IPFS as an IPLD block set (DAG-CBOR root, 0x71)
///    and record the msgid → root CID mapping.
/// 7. Append to group logs (peerable sources only) and assign local article
///    numbers (always).
/// 8. Index overview fields.
///
/// `max_article_bytes` is the operator-configured article size limit; articles
/// exceeding it are rejected with 441.
///
/// Returns 240 on success or a 441 error response on failure.
/// Metadata returned by a successful `run_post_pipeline` for audit logging.
struct PostAuditMeta {
    message_id: String,
    newsgroups: String,
    cid: String,
}

#[tracing::instrument(skip_all, fields(message_id = tracing::field::Empty))]
async fn run_post_pipeline(
    article_bytes: &[u8],
    stores: &ServerStores,
    max_article_bytes: usize,
    is_drain_session: bool,
    client_ip: &str,
    authenticated_user: Option<&str>,
) -> (Response, Option<PostAuditMeta>) {
    // Step 1: Strip the X-Stoa-Injection-Source header so it is never stored
    // in IPFS or forwarded to peers.  Classification is always NntpPost in
    // this pipeline: an NNTP POST client can forge any header value, so the
    // header value must not change whether the article is peered.  Articles
    // arriving via the SMTP drain are posted through a separate authenticated
    // path that sets its own peerability context.
    let mut article_bytes = article_bytes.to_vec();
    // Step 1: Extract and remove the X-Stoa-Injection-Source header.
    //
    // The header is always removed so it is never stored in IPFS or forwarded
    // to peers.  Whether its *value* is trusted depends on the session type:
    //
    // - Drain sessions (is_drain_session=true): trust the value so the SMTP
    //   queue drain can route SmtpListId articles as local-only (non-peerable).
    //   See usenet-ipfs-8ipr.
    //
    // - All other sessions (is_drain_session=false): discard the value and
    //   classify as NntpPost.  An NNTP client can forge any header value, so
    //   the header value MUST NOT change peerability for untrusted sessions.
    //   See closed bead usenet-ipfs-07rs.3 for full analysis.
    let injection_source = if is_drain_session {
        extract_injection_source(&mut article_bytes)
    } else {
        let _ = extract_injection_source(&mut article_bytes);
        stoa_core::InjectionSource::NntpPost
    };
    // Strip server-synthesized X-Stoa-* headers that must never be stored in
    // IPFS.  If a client includes these in a POST, they would be returned
    // verbatim before the server's own injected value, allowing the client to
    // forge integrity signals seen by readers.
    strip_server_synthesized_headers(&mut article_bytes);
    // Save pre-path bytes for DID verification.  The author signed the article
    // BEFORE the server added the Path: header; DID verification must use these
    // bytes so that strip_did_sig_header reproduces exactly what was signed.
    let article_bytes_pre_path = article_bytes.clone();
    // Step 1b: Inject the Path: header required by RFC 5536 §3.1.
    // Must happen before signing so the header is covered by the operator signature.
    let article_bytes = prepend_path_header(&article_bytes, &stores.path_hostname);
    // Step 1c: Synthesize Message-ID if absent (RFC 5536 §3.1).
    let article_bytes = inject_message_id(&article_bytes, &stores.path_hostname);
    // Step 1d: Add Injection-Info header (RFC 5536 §3.2.9).
    let article_bytes = inject_injection_info(
        &article_bytes,
        client_ip,
        authenticated_user,
        stores.mail_complaints_to.as_deref(),
    );
    // Step 1e: Add Injection-Date if Date is absent or skewed (RFC 5536 §3.2.3).
    let article_bytes = inject_injection_date(&article_bytes, stores.max_clock_skew_secs);
    let article_bytes = article_bytes.as_slice();

    // Step 2: Validate headers.
    let (message_id, newsgroups) = {
        let _span = tracing::info_span!("post.validate_headers").entered();
        if let Err(resp) = complete_post(article_bytes, max_article_bytes) {
            return (resp, None);
        }
        match extract_post_metadata(article_bytes) {
            Ok(meta) => meta,
            Err(resp) => return (resp, None),
        }
    };
    tracing::Span::current().record("message_id", message_id.as_str());

    // Step 3: Duplicate check.
    if let Err(resp) = check_duplicate_msgid(&stores.msgid_map, &message_id).await {
        return (resp, None);
    }

    // DID author signature verification (optional, non-blocking).
    // Must happen BEFORE operator signing so we verify against the original
    // article bytes (the author signed before the operator sig header existed).
    let did_sig_valid: Option<bool> = {
        use crate::post::did_passthrough::extract_did_sig;
        use crate::post::did_verify::verify_did_sig;
        // Pass full article bytes: extract_did_sig isolates the header section
        // internally.  Passing pre-sliced header bytes would call header_section
        // twice (once here, once inside extract_did_sig), which is a no-op
        // today only because header_section falls back to returning the full
        // slice when no blank line is present.
        if let Some(header_val) = extract_did_sig(&article_bytes_pre_path) {
            match verify_did_sig(&article_bytes_pre_path, &header_val) {
                Ok(valid) => {
                    tracing::debug!(
                        msgid = %message_id,
                        verified = valid,
                        "DID author signature checked"
                    );
                    Some(valid)
                }
                Err(e) => {
                    // A parse error on a header that claims to be a DID sig is
                    // treated as a bad signature (Some(false)), not as absent
                    // (None).  Downgrading to None would give a weaker signal:
                    // None means "no DID claim" while Some(false) means "bad
                    // DID claim", which is the accurate description.
                    tracing::warn!(
                        msgid = %message_id,
                        error = ?e,
                        "DID author signature verification error (treating as invalid)"
                    );
                    Some(false)
                }
            }
        } else {
            None
        }
    };

    // Step 4: Sign the article.
    // Produces signed_bytes with the X-Stoa-Sig header inserted.
    // The group log entry signature is computed separately over log entry
    // canonical bytes inside append_to_groups, where parent CIDs are known.
    let (signed_bytes, sig_bytes) = {
        let _span = tracing::info_span!("post.sign_article").entered();
        sign_article(&stores.signing_key, article_bytes)
    };

    // Step 5: Generate HLC timestamps under the clock mutex, then release
    // before any async I/O so concurrent POSTs are not serialised by it.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // infallible: system clock is always after UNIX_EPOCH on any supported platform
        .unwrap()
        .as_millis() as u64;
    let hlc_timestamps: Vec<u64> = {
        let mut clock = stores.clock.lock().await;
        newsgroups
            .iter()
            .map(|_| clock.send(now_ms).wall_ms)
            .collect()
    };
    // Use the primary HLC timestamp for the IPLD root node metadata.
    let primary_hlc = hlc_timestamps.first().copied().unwrap_or(now_ms);
    let newsgroups_str: Vec<String> = newsgroups.iter().map(|g| g.as_str().to_owned()).collect();

    // Step 6: Write to IPFS as a proper IPLD block set (root CID codec 0x71)
    // and record msgid → root CID.
    let cid = match write_ipld_article_to_ipfs(
        stores.ipfs_store.as_ref(),
        &stores.msgid_map,
        &signed_bytes,
        &message_id,
        newsgroups_str,
        primary_hlc,
        sig_bytes,
    )
    .instrument(tracing::info_span!("post.ipfs_block_put"))
    .await
    {
        Ok(cid) => cid,
        Err(resp) => return (resp, None),
    };

    // Step 6b: Verify article signatures (best-effort; never blocks acceptance).
    {
        use stoa_verify::x_sig::verify_x_sig;
        let pubkey = stores.signing_key.verifying_key();
        let x_sig_results = verify_x_sig(&[pubkey], &signed_bytes);
        let dkim_results =
            stoa_verify::dkim::verify_dkim_headers(&stores.dkim_authenticator, &signed_bytes).await;
        let all_verifications: Vec<_> = x_sig_results.into_iter().chain(dkim_results).collect();
        let verified_at_ms = now_ms as i64;
        if let Err(e) = stores
            .verification_store
            .record_verifications(&cid, &all_verifications, verified_at_ms)
            .await
        {
            warn!(message_id = %message_id, error = %e, "verification record failed");
        }
    }

    // Step 7: Append to group logs (peerable sources only) and assign article
    // numbers (always, so local readers see every article).
    let append_result = match append_to_groups(
        stores.log_storage.as_ref(),
        &stores.article_numbers,
        &hlc_timestamps,
        &cid,
        &stores.signing_key,
        &newsgroups,
        injection_source,
    )
    .instrument(tracing::info_span!("post.group_log_append"))
    .await
    {
        Ok(r) => r,
        Err(resp) => return (resp, None),
    };

    // Step 8: Index overview fields for each assigned (group, article_number).
    let (header_bytes, body_bytes) = split_article(&signed_bytes);
    let mut overview = extract_overview(&header_bytes, &body_bytes);
    overview.did_sig_valid = did_sig_valid;
    for (group, article_number) in &append_result.assignments {
        overview.article_number = *article_number;
        if let Err(e) = stores.overview_store.insert(group, &overview).await {
            warn!("overview insert failed for {group}/{article_number}: {e}");
        }
    }

    // Step 9: Best-effort full-text search indexing.
    // Failures are logged but never cause the POST to fail.
    if let Some(idx) = &stores.search_index {
        for (group, article_number) in &append_result.assignments {
            let req = ArticleIndexRequest {
                message_id: &message_id,
                newsgroup: group,
                article_num: *article_number,
                subject: &overview.subject,
                from: &overview.from,
                date_str: &overview.date,
                body_bytes: &body_bytes,
            };
            if let Err(e) = idx.index_article(&req).await {
                tracing::warn!(
                    message_id = %message_id,
                    error = %e,
                    "search index failed; article still accepted"
                );
            }
        }
        if let Err(e) = idx.commit().await {
            tracing::warn!(error = %e, "search index commit failed");
        }
    }

    // Step 10: Best-effort SMTP relay for email recipients.
    // Enqueue only when the article has email addresses in To: or Cc:.
    // Failure is non-fatal — POST already succeeded.
    maybe_enqueue_smtp_relay(stores.smtp_relay_queue.as_ref(), &signed_bytes).await;

    let newsgroups_str = newsgroups
        .iter()
        .map(|g| g.as_str())
        .collect::<Vec<_>>()
        .join(",");
    (
        Response::new(240, "Article received OK"),
        Some(PostAuditMeta {
            message_id: message_id.clone(),
            newsgroups: newsgroups_str,
            cid: cid.to_string(),
        }),
    )
}

/// Reconstruct wire-format article bytes from an IPLD DAG-CBOR root CID.
///
/// Fetches the root block (codec 0x71, DAG-CBOR `ArticleRootNode`), then
/// fetches the header and body sub-blocks referenced by the root, and
/// concatenates them as `header_bytes + "\r\n\r\n" + body_bytes`.
async fn fetch_article_wire_bytes(
    ipfs_store: &dyn IpfsBlockStore,
    root_cid: &Cid,
) -> Result<Vec<u8>, String> {
    let root_bytes = ipfs_store
        .get_raw(root_cid)
        .await
        .map_err(|e| format!("IPFS fetch root block {root_cid}: {e:?}"))?;
    let root: ArticleRootNode = serde_ipld_dagcbor::from_slice(&root_bytes)
        .map_err(|e| format!("DAG-CBOR decode ArticleRootNode from {root_cid}: {e}"))?;
    let header_bytes = ipfs_store
        .get_raw(&root.header_cid)
        .await
        .map_err(|e| format!("IPFS fetch header block {}: {e:?}", root.header_cid))?;
    let body_bytes = ipfs_store
        .get_raw(&root.body_cid)
        .await
        .map_err(|e| format!("IPFS fetch body block {}: {e:?}", root.body_cid))?;
    let mut wire = Vec::with_capacity(header_bytes.len() + 4 + body_bytes.len());
    wire.extend_from_slice(&header_bytes);
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(&body_bytes);
    Ok(wire)
}

/// Look up an article by Message-ID from stores and return a 220/430 response.
async fn lookup_article_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    let (cid_opt, header_bytes, body_bytes) = match resolve_msgid_to_wire(stores, msgid).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    // Look up DID signature verification result from the overview index.
    // Silently omit the header on lookup error — do not fail the ARTICLE command.
    let did_sig_valid = stores
        .overview_store
        .query_by_msgid(msgid)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.did_sig_valid);
    let verifications = if let Some(ref cid) = cid_opt {
        stores
            .verification_store
            .get_verifications(cid)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };
    article_response(&ArticleContent {
        article_number: 0,
        message_id: msgid.to_string(),
        header_bytes,
        body_bytes,
        cid: cid_opt,
        did_sig_valid,
        verifications,
    })
}

/// Resolve a local article number to its `ArticleContent`.
///
/// Looks up the CID via `article_numbers`, fetches wire bytes from IPFS,
/// builds an `ArticleContent` record, and updates `ctx.current_article_number`.
///
/// Returns `Err(Response)` with 412, 423, or 500 on any failure.
async fn lookup_article_content_by_number(
    stores: &ServerStores,
    ctx: &mut SessionContext,
    number: u64,
) -> Result<ArticleContent, Response> {
    let group = match ctx.selected_group.as_ref() {
        Some(sg) => sg.name.as_str().to_string(),
        None => return Err(Response::no_newsgroup_selected()),
    };
    let cid = match stores.article_numbers.lookup_cid(&group, number).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(Response::new(423, "No article with that number")),
        Err(e) => {
            warn!("article_numbers lookup error {group}/{number}: {e}");
            return Err(Response::program_fault());
        }
    };
    let wire_bytes = match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid).await {
        Ok(b) => b,
        Err(e) => {
            warn!("fetch_article_wire_bytes error for cid {cid}: {e}");
            return Err(Response::program_fault());
        }
    };
    let (header_bytes, body_bytes) = split_article(&wire_bytes);
    // Use query_by_number (1 DB query) instead of header-scan + query_by_msgid
    // (header parse + 1 DB query).  Fall back to the header parse only if the
    // overview record is missing (article indexed before overview was written).
    let overview = stores
        .overview_store
        .query_by_number(&group, number)
        .await
        .ok()
        .flatten();
    let message_id = overview
        .as_ref()
        .map(|r| r.message_id.clone())
        .unwrap_or_else(|| {
            let headers_str = String::from_utf8_lossy(&header_bytes);
            extract_header_value(&headers_str, "Message-ID").unwrap_or_default()
        });
    let did_sig_valid = overview.and_then(|r| r.did_sig_valid);
    let verifications = stores
        .verification_store
        .get_verifications(&cid)
        .await
        .unwrap_or_default();
    if let Some(sg) = ctx.selected_group.as_mut() {
        sg.article_number = Some(number);
    }
    Ok(ArticleContent {
        article_number: number,
        message_id,
        header_bytes,
        body_bytes,
        cid: Some(cid),
        did_sig_valid,
        verifications,
    })
}

/// STAT <msgid>: check article existence by message-id without fetching content.
///
/// Returns 223 with `0 <msgid>` if the article is known, 430 if not found.
/// RFC 3977 §6.2.4: STAT <msgid> does not require a currently selected group.
///
/// When the block store has no record and a staging pool is configured, the
/// staging table is consulted as a fallback (stoa-psd6m).
async fn stat_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    match stores.msgid_map.lookup_by_msgid(msgid).await {
        Ok(Some(_)) => Response::article_exists(0, msgid),
        Ok(None) => {
            // Not in block store — check transit staging.
            if let Some(ref pool) = stores.staging_pool {
                match fetch_from_staging(pool, msgid).await {
                    StagingResult::Found(_) => {
                        debug!(msgid, "STAT: article found in transit staging (pre-IPFS)");
                        return Response::article_exists(0, msgid);
                    }
                    StagingResult::NotStaged | StagingResult::Error => {}
                }
            }
            Response::no_article_with_message_id()
        }
        Err(e) => {
            warn!("msgid_map lookup error for STAT {msgid}: {e}");
            Response::program_fault()
        }
    }
}

/// HEAD <msgid>: look up an article by Message-ID and return headers only.
async fn lookup_head_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    let (cid_opt, header_bytes, body_bytes) = match resolve_msgid_to_wire(stores, msgid).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let did_sig_valid = stores
        .overview_store
        .query_by_msgid(msgid)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.did_sig_valid);
    let verifications = if let Some(ref cid) = cid_opt {
        stores
            .verification_store
            .get_verifications(cid)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };
    head_response(&ArticleContent {
        article_number: 0,
        message_id: msgid.to_string(),
        header_bytes,
        body_bytes,
        cid: cid_opt,
        did_sig_valid,
        verifications,
    })
}

/// BODY <msgid>: look up an article by Message-ID and return body only.
async fn lookup_body_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    let (cid_opt, header_bytes, body_bytes) = match resolve_msgid_to_wire(stores, msgid).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let verifications = if let Some(ref cid) = cid_opt {
        stores
            .verification_store
            .get_verifications(cid)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };
    body_response(&ArticleContent {
        article_number: 0,
        message_id: msgid.to_string(),
        header_bytes,
        body_bytes,
        cid: cid_opt,
        did_sig_valid: None,
        verifications,
    })
}

/// Resolve a Message-ID to an optional CID and split wire bytes `(cid_opt, header, body)`.
///
/// Shared scaffold for `lookup_article_by_msgid`, `lookup_head_by_msgid`, and
/// `lookup_body_by_msgid`: performs the msgid-map lookup, IPFS fetch, and
/// header/body split that all three commands require.
///
/// When the block store has no record for `msgid` and a staging pool is
/// configured, the function falls back to reading the raw article bytes from
/// the transit staging table (stoa-psd6m).  The staging path returns
/// `cid_opt = None` because the article has not yet been committed to IPFS;
/// callers must propagate this `None` to `ArticleContent.cid` so that
/// `X-Stoa-CID` is omitted from the response.
///
/// Returns `Err(Response)` with 430 (not found) or 500 (storage error) so the
/// caller can return early via `match … { Err(r) => return r, Ok(t) => t }`.
async fn resolve_msgid_to_wire(
    stores: &ServerStores,
    msgid: &str,
) -> Result<(Option<cid::Cid>, Vec<u8>, Vec<u8>), Response> {
    match stores.msgid_map.lookup_by_msgid(msgid).await {
        Ok(Some(cid)) => {
            let wire_bytes = match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid).await
            {
                Ok(b) => b,
                Err(e) => {
                    warn!("fetch_article_wire_bytes error for cid {cid}: {e}");
                    return Err(Response::program_fault());
                }
            };
            let (header_bytes, body_bytes) = split_article(&wire_bytes);
            Ok((Some(cid), header_bytes, body_bytes))
        }
        Ok(None) => {
            // Article not in block store — check the transit staging area.
            if let Some(ref pool) = stores.staging_pool {
                match fetch_from_staging(pool, msgid).await {
                    StagingResult::Found(wire_bytes) => {
                        let (header_bytes, body_bytes) = split_article(&wire_bytes);
                        // No CID yet: article is staged but not committed to IPFS.
                        // cid: None causes callers to omit X-Stoa-CID from the response,
                        // which is correct — there is no content address to report yet.
                        debug!(msgid, "serving article from transit staging (pre-IPFS)");
                        return Ok((None, header_bytes, body_bytes));
                    }
                    StagingResult::NotStaged => {}
                    StagingResult::Error => {
                        // Staging lookup failed; fall through to 430.
                    }
                }
            }
            Err(Response::no_article_with_message_id())
        }
        Err(e) => {
            warn!("msgid_map lookup error for {msgid}: {e}");
            Err(Response::program_fault())
        }
    }
}

/// Decode a SASL OAUTHBEARER initial response (RFC 7628 §3.1) and extract
/// the Bearer token.
///
/// The initial response is a base64-encoded string of the form:
/// `n,,[a=ruser,]\x01auth=Bearer <token>\x01[key=value\x01]*\x01`
///
/// Returns `Some(token)` on success, `None` on malformed input.
fn extract_oauthbearer_token(b64: &str) -> Option<String> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    // Find "auth=Bearer " and extract the value up to the next \x01.
    let prefix = "auth=Bearer ";
    let start = text.find(prefix)? + prefix.len();
    let end = text[start..]
        .find('\x01')
        .map(|i| start + i)
        .unwrap_or(text.len());
    if end <= start {
        return None;
    }
    Some(text[start..end].to_string())
}

/// Split raw article bytes at the blank-line separator.
///
/// Returns `(header_bytes, body_bytes)`. Both slices exclude the blank line
/// itself. If no separator is found, the entire input is treated as headers.
fn split_article(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match find_header_boundary(bytes) {
        Some(body_start) => {
            // Determine separator length: 4 for \r\n\r\n, 2 for \n\n.
            let sep_len = if body_start >= 4 && bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                4
            } else {
                2
            };
            let header_end = body_start - sep_len;
            (bytes[..header_end].to_vec(), bytes[body_start..].to_vec())
        }
        None => (bytes.to_vec(), vec![]),
    }
}

/// Extract `Message-ID` and `Newsgroups` from article header bytes.
///
/// Uses `mailparse::parse_headers` so that RFC 5322 folded header values
/// (continuation lines starting with whitespace) are unfolded correctly.
///
/// Returns `Err(441 response)` if either field is missing or invalid.
fn extract_post_metadata(
    article_bytes: &[u8],
) -> Result<(String, Vec<stoa_core::article::GroupName>), Response> {
    // Pass the bytes up to and including the blank line (or the full slice if
    // none is found); mailparse::parse_headers stops at the blank line anyway.
    let parse_end = find_header_boundary(article_bytes).unwrap_or(article_bytes.len());
    let header_section = &article_bytes[..parse_end];

    let (parsed, _) = parse_headers(header_section)
        .map_err(|_| Response::new(441, "Could not parse article headers"))?;

    let mut message_id: Option<String> = None;
    let mut newsgroups_val: Option<String> = None;
    for hdr in &parsed {
        let key = hdr.get_key().to_ascii_lowercase();
        if key == "message-id" && message_id.is_none() {
            message_id = Some(hdr.get_value());
        } else if key == "newsgroups" && newsgroups_val.is_none() {
            newsgroups_val = Some(hdr.get_value());
        }
    }

    let message_id = message_id.ok_or_else(|| Response::new(441, "Missing Message-ID header"))?;
    let newsgroups_val =
        newsgroups_val.ok_or_else(|| Response::new(441, "Missing Newsgroups header"))?;

    let newsgroups: Vec<stoa_core::article::GroupName> = newsgroups_val
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            stoa_core::article::GroupName::new(s)
                .map_err(|_| Response::new(441, format!("Invalid group name: {s}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if newsgroups.is_empty() {
        return Err(Response::new(441, "Newsgroups header is empty"));
    }

    Ok((message_id, newsgroups))
}

/// Extract the trimmed value of the first matching header field, or `None`.
///
/// Implements RFC 5322 §2.2.3 header unfolding: continuation lines that begin
/// with a single SP (0x20) or HTAB (0x09) are appended to the field value
/// (after replacing the leading whitespace with a single space) until a line
/// that does not start with whitespace is encountered.
fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    let prefix_colon = format!("{}:", name.to_ascii_lowercase());
    let lines: Vec<&str> = headers.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let lower = lines[i].to_ascii_lowercase();
        if lower.starts_with(&prefix_colon) {
            // Capture the value from the first line (after "Name:").
            let mut value = lines[i][prefix_colon.len()..].trim_start().to_string();
            i += 1;
            // Collect continuation lines (RFC 5322 §2.2.3).
            while i < lines.len() {
                let next = lines[i];
                if next.starts_with(' ') || next.starts_with('\t') {
                    value.push(' ');
                    value.push_str(next.trim());
                    i += 1;
                } else {
                    break;
                }
            }
            return Some(value.trim_end().to_string());
        }
        i += 1;
    }
    None
}

// ── CID extension handlers (ADR-0007) ─────────────────────────────────────

/// XCID [<message-id>]: return the CID for the current or named article.
///
/// If a message-id argument is supplied, look it up directly.
/// If no argument, use the current (group, article_number) from session state.
async fn handle_xcid(
    stores: &ServerStores,
    arg: Option<&str>,
    current_group: Option<&str>,
    current_number: Option<u64>,
) -> Response {
    let cid = if let Some(msgid) = arg {
        match stores.msgid_map.lookup_by_msgid(msgid).await {
            Ok(Some(c)) => c,
            Ok(None) => return Response::no_article_with_message_id(),
            Err(e) => {
                warn!("XCID msgid lookup error: {e}");
                return Response::program_fault();
            }
        }
    } else {
        let group = match current_group {
            Some(g) => g,
            None => return Response::no_newsgroup_selected(),
        };
        let number = match current_number {
            Some(n) => n,
            None => return Response::current_article_invalid(),
        };
        match stores.article_numbers.lookup_cid(group, number).await {
            Ok(Some(c)) => c,
            Ok(None) => return Response::current_article_invalid(),
            Err(e) => {
                warn!("XCID article_numbers lookup error: {e}");
                return Response::program_fault();
            }
        }
    };
    xcid_response(&cid)
}

/// XVERIFY <message-id> <expected-cid> [SIG]: verify CID match, optionally
/// also re-verify the operator ed25519 signature.
///
/// Response codes:
/// - 291: verified OK
/// - 430: message-id not found
/// - 541: CID mismatch
/// - 542: signature verification failed
async fn handle_xverify(
    stores: &ServerStores,
    message_id: &str,
    expected_cid: &str,
    verify_sig: bool,
) -> Response {
    let actual_cid = match stores.msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Response::no_article_with_message_id(),
        Err(e) => {
            warn!("XVERIFY msgid lookup error: {e}");
            return Response::program_fault();
        }
    };

    if actual_cid.to_string() != expected_cid {
        return Response::new(541, "CID mismatch");
    }

    if verify_sig {
        let wire_bytes =
            match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &actual_cid).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("XVERIFY fetch wire bytes error: {e}");
                    return Response::program_fault();
                }
            };
        let pubkey = stores.signing_key.verifying_key();
        if verify_article_sig(&pubkey, &wire_bytes).is_err() {
            return Response::new(542, "Signature verification failed");
        }
    }

    Response::new(291, "Verified OK")
}

// ── Live GROUP / LIST ACTIVE / OVER handlers ──────────────────────────────

/// GROUP groupname: select a group and return live article count and range.
///
/// Returns 411 for an invalid group name or for a group not carried by this
/// server (RFC 3977 §6.1.1). A group is considered carried if it has at least
/// one article in the article_numbers store. Returns 211 with live (low, high,
/// count) for carried groups.
async fn handle_group_live(
    stores: &ServerStores,
    ctx: &mut SessionContext,
    name: &str,
) -> Response {
    let group_name = match stoa_core::article::GroupName::new(name) {
        Ok(g) => g,
        Err(_) => return Response::no_such_newsgroup(),
    };
    // RFC 3977 §6.1.1: return 411 if the group is not served by this server.
    // group_range() issues a targeted single-group query; (low > high) means
    // no articles exist for this group (the RFC 3977 empty sentinel is (1, 0)).
    // This avoids the O(n-groups) list_groups() scan followed by a linear
    // contains() search.
    let (low, high) = match stores.article_numbers.group_range(name).await {
        Ok(r) => r,
        Err(e) => {
            warn!("group_range error for {name}: {e}");
            return Response::program_fault();
        }
    };
    if low > high {
        return Response::no_such_newsgroup();
    }
    let count = if low <= high { high - low + 1 } else { 0 };
    ctx.selected_group = Some(crate::session::context::SelectedGroup {
        name: group_name,
        article_number: if count > 0 { Some(low) } else { None },
    });
    ctx.state = SessionState::GroupSelected;
    Response::group_selected(name, count, low, high)
}

/// NEXT: advance the article pointer to the next article in the current group.
///
/// RFC 3977 §6.1.3:
/// - 412 if no group is selected.
/// - 420 if no current article number (pointer not set).
/// - 421 if already at the last article.
/// - 223 n message-id on success; updates the article pointer.
async fn handle_next_live(stores: &ServerStores, ctx: &mut SessionContext) -> Response {
    let (group, current) = match ctx.selected_group.as_ref() {
        None => return Response::no_newsgroup_selected(),
        Some(sg) => match sg.article_number {
            None => return Response::current_article_invalid(),
            Some(n) => (sg.name.as_str().to_string(), n),
        },
    };
    match stores.article_numbers.next_after(&group, current).await {
        Ok(None) => Response::no_next_article(),
        Ok(Some((next_n, _cid))) => {
            let msgid = stores
                .overview_store
                .query_by_number(&group, next_n)
                .await
                .ok()
                .flatten()
                .map(|r| r.message_id)
                .unwrap_or_default();
            if let Some(sg) = ctx.selected_group.as_mut() {
                sg.article_number = Some(next_n);
            }
            Response::article_exists(next_n, &msgid)
        }
        Err(e) => {
            warn!("NEXT article_numbers error: {e}");
            Response::program_fault()
        }
    }
}

/// LAST: retreat the article pointer to the previous article in the current group.
///
/// RFC 3977 §6.1.4:
/// - 412 if no group is selected.
/// - 420 if no current article number (pointer not set).
/// - 422 if already at the first article.
/// - 223 n message-id on success; updates the article pointer.
async fn handle_last_live(stores: &ServerStores, ctx: &mut SessionContext) -> Response {
    let (group, current) = match ctx.selected_group.as_ref() {
        None => return Response::no_newsgroup_selected(),
        Some(sg) => match sg.article_number {
            None => return Response::current_article_invalid(),
            Some(n) => (sg.name.as_str().to_string(), n),
        },
    };
    match stores.article_numbers.prev_before(&group, current).await {
        Ok(None) => Response::no_previous_article(),
        Ok(Some((prev_n, _cid))) => {
            let msgid = stores
                .overview_store
                .query_by_number(&group, prev_n)
                .await
                .ok()
                .flatten()
                .map(|r| r.message_id)
                .unwrap_or_default();
            if let Some(sg) = ctx.selected_group.as_mut() {
                sg.article_number = Some(prev_n);
            }
            Response::article_exists(prev_n, &msgid)
        }
        Err(e) => {
            warn!("LAST article_numbers error: {e}");
            Response::program_fault()
        }
    }
}

/// LIST ACTIVE [wildmat]: return live article ranges for groups that have articles.
///
/// If `wildmat` is `Some`, only groups whose names match the pattern are included.
async fn handle_list_active_live(stores: &ServerStores, wildmat: Option<&str>) -> Response {
    let groups = match stores.article_numbers.list_groups().await {
        Ok(g) => g,
        Err(e) => {
            warn!("list_groups error: {e}");
            return Response::program_fault();
        }
    };
    let body: Vec<String> = groups
        .into_iter()
        .filter(|(name, _, _)| {
            wildmat
                .map(|pat| stoa_core::wildmat::matches_wildmat(name, pat))
                .unwrap_or(true)
        })
        .map(|(name, low, high)| format!("{} {} {} y", name, high, low))
        .collect();
    Response::list_active(body)
}

/// NEWNEWS wildmat date time: return Message-IDs of articles newer than timestamp.
///
/// Queries the overview index for message IDs in groups matching `wildmat`
/// whose Date header is strictly after the parsed NNTP timestamp. Articles
/// with unparseable Date headers are excluded (conservative).
async fn handle_newnews_live(
    stores: &ServerStores,
    wildmat: &str,
    date: &str,
    time: &str,
) -> Response {
    use crate::session::commands::list::parse_nntp_datetime;
    let since_ts = parse_nntp_datetime(date, time);
    match stores
        .overview_store
        .message_ids_since(wildmat, since_ts)
        .await
    {
        Ok(ids) => Response::newnews(ids),
        Err(e) => {
            warn!("NEWNEWS store query error: {e}");
            Response::program_fault()
        }
    }
}

/// OVER/XOVER [range]: serve overview records from the SQLite overview index.
async fn handle_over_live(
    stores: &ServerStores,
    ctx: &SessionContext,
    arg: Option<&OverArg>,
) -> Response {
    // RFC 3977 §8.3.2: message-id form does not require a currently selected newsgroup.
    if let Some(OverArg::MessageId(msgid)) = arg {
        return match stores.overview_store.query_by_msgid(msgid).await {
            Ok(Some(record)) => over_response(std::iter::once(record)),
            Ok(None) => Response::no_article_with_message_id(),
            Err(e) => {
                warn!("OVER msgid lookup error: {e}");
                Response::program_fault()
            }
        };
    }

    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let group = match ctx.selected_group.as_ref() {
        Some(sg) => sg.name.as_str().to_string(),
        None => return Response::no_newsgroup_selected(),
    };

    let (low, high) = match arg {
        None => {
            let n = match ctx.selected_group.as_ref().and_then(|sg| sg.article_number) {
                Some(n) => n,
                None => return Response::current_article_invalid(),
            };
            (n, n)
        }
        Some(OverArg::Range(r)) => match r {
            ArticleRange::Single(n) => (*n, *n),
            ArticleRange::From(n) => {
                let (_, g_high) = match stores.article_numbers.group_range(&group).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("OVER group_range error: {e}");
                        return Response::program_fault();
                    }
                };
                (*n, g_high)
            }
            ArticleRange::Range(lo, hi) => (*lo, *hi),
        },
        Some(OverArg::MessageId(_)) => unreachable!("MessageId handled above"),
    };

    let records = match stores.overview_store.query_range(&group, low, high).await {
        Ok(r) => r,
        Err(e) => {
            warn!("OVER query_range error: {e}");
            return Response::program_fault();
        }
    };
    over_response(records)
}

/// HDR field-name [range|message-id]: return one header field per article
/// from the overview index (RFC 3977 §8.5).
///
/// Supported fields are those stored in the overview index: `Subject`, `From`,
/// `Date`, `Message-ID`, `References`, `:bytes`, `:lines`.  Unknown fields
/// return 501 per RFC 3977 §8.5.2.
async fn handle_hdr_live(
    stores: &ServerStores,
    ctx: &SessionContext,
    field: &str,
    range_or_msgid: Option<&str>,
) -> Response {
    // Reject unsupported fields early.
    let field_lower = field.to_ascii_lowercase();
    let supported = matches!(
        field_lower.as_str(),
        "subject" | "from" | "date" | "message-id" | "references" | ":bytes" | ":lines"
    );
    if !supported {
        return Response::new(501, "Field not supported");
    }

    // Message-ID form: does not require a currently selected newsgroup.
    if let Some(arg) = range_or_msgid {
        if arg.starts_with('<') {
            return match stores.overview_store.query_by_msgid(arg).await {
                Ok(Some(record)) => {
                    let value = extract_field(&record, field).unwrap_or_default();
                    hdr_response(&[HdrRecord {
                        article_number: record.article_number,
                        value,
                    }])
                }
                Ok(None) => Response::no_article_with_message_id(),
                Err(e) => {
                    warn!("HDR msgid lookup error: {e}");
                    Response::program_fault()
                }
            };
        }
    }

    // Range form: requires a currently selected newsgroup.
    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let group = match ctx.selected_group.as_ref() {
        Some(sg) => sg.name.as_str().to_string(),
        None => return Response::no_newsgroup_selected(),
    };

    let (low, high) = match range_or_msgid {
        None => {
            let n = match ctx.selected_group.as_ref().and_then(|sg| sg.article_number) {
                Some(n) => n,
                None => return Response::current_article_invalid(),
            };
            (n, n)
        }
        Some(arg) => {
            let range = crate::session::command::parse_range_pub(arg);
            match range {
                ArticleRange::Single(n) => (n, n),
                ArticleRange::From(n) => {
                    let (_, g_high) = match stores.article_numbers.group_range(&group).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("HDR group_range error: {e}");
                            return Response::program_fault();
                        }
                    };
                    (n, g_high)
                }
                ArticleRange::Range(lo, hi) => (lo, hi),
            }
        }
    };

    let records = match stores.overview_store.query_range(&group, low, high).await {
        Ok(r) => r,
        Err(e) => {
            warn!("HDR query_range error: {e}");
            return Response::program_fault();
        }
    };

    let hdr_records: Vec<HdrRecord> = records
        .into_iter()
        .map(|r| {
            let value = extract_field(&r, field).unwrap_or_default();
            HdrRecord {
                article_number: r.article_number,
                value,
            }
        })
        .collect();

    hdr_response(&hdr_records)
}

/// Fetch article content by CID, returning `Err(Response)` on failure.
///
/// Shared scaffold for ARTICLE/HEAD/BODY/STAT cid: variants.
/// Returns 501 for an unparseable CID, 430 if the block is not found.
async fn fetch_article_content_by_cid(
    stores: &ServerStores,
    cid_str: &str,
) -> Result<ArticleContent, Response> {
    let cid: Cid = match cid_str.parse() {
        Ok(c) => c,
        Err(_) => return Err(Response::syntax_error()),
    };
    let wire_bytes = match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid).await {
        Ok(b) => b,
        Err(_) => return Err(Response::no_article_with_message_id()),
    };
    let (header_bytes, body_bytes) = split_article(&wire_bytes);
    let headers_str = String::from_utf8_lossy(&header_bytes);
    let message_id = extract_header_value(&headers_str, "Message-ID").unwrap_or_default();

    // Look up DID signature verification result from the overview index.
    // Silently omit the header on lookup error — do not fail the command.
    let did_sig_valid = stores
        .overview_store
        .query_by_msgid(&message_id)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.did_sig_valid);

    // Look up cryptographic verification results from the verify store.
    let verifications = stores
        .verification_store
        .get_verifications(&cid)
        .await
        .unwrap_or_default();

    Ok(ArticleContent {
        article_number: 0,
        message_id,
        header_bytes,
        body_bytes,
        cid: Some(cid),
        did_sig_valid,
        verifications,
    })
}

/// ARTICLE cid:<cid>: fetch an article directly by its IPFS CID.
///
/// Returns 501 for an unparseable CID, 430 if the block is not found,
/// or 220 with the article on success.
async fn lookup_article_by_cid(stores: &ServerStores, cid_str: &str) -> Response {
    match fetch_article_content_by_cid(stores, cid_str).await {
        Ok(content) => article_response(&content),
        Err(r) => r,
    }
}

/// HEAD cid:<cid>: return headers only for the article at the given CID.
async fn lookup_head_by_cid(stores: &ServerStores, cid_str: &str) -> Response {
    match fetch_article_content_by_cid(stores, cid_str).await {
        Ok(content) => head_response(&content),
        Err(r) => r,
    }
}

/// BODY cid:<cid>: return body only for the article at the given CID.
async fn lookup_body_by_cid(stores: &ServerStores, cid_str: &str) -> Response {
    match fetch_article_content_by_cid(stores, cid_str).await {
        Ok(content) => body_response(&content),
        Err(r) => r,
    }
}

/// STAT cid:<cid>: check article existence by CID, returning 223 or 430.
async fn stat_by_cid(stores: &ServerStores, cid_str: &str) -> Response {
    match fetch_article_content_by_cid(stores, cid_str).await {
        Ok(content) => Response::article_exists(0, &content.message_id),
        Err(r) => r,
    }
}

/// Escape characters that have special meaning in Tantivy's query parser.
/// This allows literal user input to be used in field:value queries safely.
fn escape_tantivy_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '+' | '-' | '&' | '|' | '!' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '"' | '~'
            | '*' | '?' | ':' | '\\' | '/' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// SEARCH key value: execute a full-text search within the current newsgroup.
///
/// Requires a selected newsgroup (412 otherwise). Returns 503 if the search
/// index is not available. On success, returns 100 followed by a list of
/// matching article numbers, dot-terminated.
async fn handle_nntp_search(
    stores: &ServerStores,
    ctx: &SessionContext,
    key: &SearchKey,
    value: &str,
) -> Vec<u8> {
    let group = match &ctx.selected_group {
        Some(sg) => sg.name.as_str().to_owned(),
        None => return b"412 No newsgroup selected\r\n".to_vec(),
    };

    let idx = match &stores.search_index {
        Some(i) => i,
        None => return b"503 Search not available\r\n".to_vec(),
    };

    let query_str = match key {
        SearchKey::Subject => format!("subject:\"{}\"", escape_tantivy_query(value)),
        SearchKey::From => format!("from_header:\"{}\"", escape_tantivy_query(value)),
        SearchKey::Since | SearchKey::Before => {
            return b"501 Date range search not yet implemented\r\n".to_vec();
        }
        // Body targets the article body only; Text searches all indexed fields.
        SearchKey::Body => format!("body_text:\"{}\"", escape_tantivy_query(value)),
        SearchKey::Text => escape_tantivy_query(value),
    };

    match idx.search_in_group(&group, &query_str, 10_000).await {
        Ok(nums) => {
            if nums.is_empty() {
                return b"100 Article list follows\r\n.\r\n".to_vec();
            }
            let mut resp = b"100 Article list follows\r\n".to_vec();
            for n in nums {
                resp.extend_from_slice(format!("{n}\r\n").as_bytes());
            }
            resp.extend_from_slice(b".\r\n");
            resp
        }
        Err(SearchError::QueryTooLong { len, max }) => {
            format!("501 Query too long ({len} bytes, max {max})\r\n").into_bytes()
        }
        Err(e) => {
            tracing::warn!(error = %e, "SEARCH failed");
            b"451 Program error\r\n".to_vec()
        }
    }
}

#[cfg(test)]
mod oauthbearer_tests {
    use super::extract_oauthbearer_token;
    use base64::Engine as _;

    fn encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn extracts_token_from_well_formed_response() {
        // RFC 7628 §3.1: n,,\x01auth=Bearer <token>\x01\x01
        let initial = encode("n,,\x01auth=Bearer mytoken123\x01\x01");
        assert_eq!(
            extract_oauthbearer_token(&initial),
            Some("mytoken123".to_string())
        );
    }

    #[test]
    fn extracts_token_with_a_field() {
        let initial = encode("n,a=user@example.com,\x01auth=Bearer tok.ens\x01\x01");
        assert_eq!(
            extract_oauthbearer_token(&initial),
            Some("tok.ens".to_string())
        );
    }

    #[test]
    fn returns_none_for_empty_input() {
        assert_eq!(extract_oauthbearer_token(""), None);
    }

    #[test]
    fn returns_none_for_non_base64() {
        assert_eq!(extract_oauthbearer_token("!!!not-b64!!!"), None);
    }

    #[test]
    fn returns_none_when_auth_field_missing() {
        let initial = encode("n,,\x01host=nntp.example.com\x01\x01");
        assert_eq!(extract_oauthbearer_token(&initial), None);
    }

    #[test]
    fn handles_token_without_trailing_ctrl_a() {
        // Some clients may omit the trailing \x01.
        let initial = encode("n,,\x01auth=Bearer onlytoken");
        assert_eq!(
            extract_oauthbearer_token(&initial),
            Some("onlytoken".to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::commands::post::DEFAULT_MAX_ARTICLE_BYTES;
    use crate::store::server_stores::ServerStores;
    use std::time::{SystemTime, UNIX_EPOCH};
    use stoa_core::group_log::LogStorage;

    /// Return the current time formatted as RFC 2822 (e.g. `Mon, 20 Apr 2026 12:00:00 +0000`).
    fn now_rfc2822() -> String {
        let s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64;
        stoa_core::util::epoch_to_rfc2822(s)
    }

    fn minimal_article(newsgroups: &str, subject: &str, msgid: &str) -> Vec<u8> {
        let date = now_rfc2822();
        format!(
            "Newsgroups: {newsgroups}\r\n\
             From: poster@example.com\r\n\
             Subject: {subject}\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             Article body.\r\n"
        )
        .into_bytes()
    }

    /// Regression test for rbe3.50: run_post_pipeline must honour the
    /// operator-configured max_article_bytes, not a hardcoded constant.
    ///
    /// Before the fix, `complete_post` was always called with
    /// `DEFAULT_MAX_ARTICLE_BYTES` regardless of the operator's config value.
    #[tokio::test]
    async fn post_pipeline_rejects_article_over_operator_limit() {
        let stores = ServerStores::new_mem().await;
        // Build a minimal article that is valid but large enough to exceed a
        // tiny operator-imposed limit.
        let article = minimal_article("comp.test", "Too Large", "<toolarge@test.example>");

        // Limit of 1 byte — any real article will exceed it.
        let (resp, _) = run_post_pipeline(&article, &stores, 1, false, "127.0.0.1", None).await;
        assert_eq!(
            resp.code, 441,
            "POST pipeline must return 441 when article exceeds operator limit; got: {}",
            resp.text
        );
        assert!(
            resp.text.to_ascii_lowercase().contains("too large"),
            "error text must mention 'too large': {}",
            resp.text
        );
    }

    /// Regression test for o0r.2: verify that the group log entry produced by
    /// run_post_pipeline carries a valid operator Ed25519 signature.
    ///
    /// The fix has two parts:
    /// (1) append_to_groups now accepts a SigningKey and computes the log entry
    ///     signature over canonical bytes (hlc_timestamp || article_cid ||
    ///     sorted parent_cids) internally, where parent CIDs are known.
    /// (2) The article signature from sign_article (over raw article bytes) is
    ///     correctly used only for the X-Stoa-Sig header, not the log.
    ///
    /// This test will fail if operator_signature in the log entry is ever left
    /// empty or set to a signature over the wrong bytes.
    #[tokio::test]
    async fn post_pipeline_log_entry_signature_verifies() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Signature Verify", "<sigverify@test.example>");

        let (resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(
            resp.code, 240,
            "POST pipeline must succeed; got: {}",
            resp.text
        );

        let group = stoa_core::article::GroupName::new("comp.test").unwrap();
        let tips = stores.log_storage.list_tips(&group).await.unwrap();
        assert_eq!(tips.len(), 1, "must have exactly one tip after one POST");

        let entry = stores
            .log_storage
            .get_entry(&tips[0])
            .await
            .unwrap()
            .expect("tip entry must exist in storage");

        assert_eq!(
            entry.operator_signature.len(),
            64,
            "operator_signature must be 64 bytes (Ed25519); got {} — sign_article return value may not be threaded through",
            entry.operator_signature.len()
        );

        let pubkey = stores.signing_key.verifying_key();
        let result = stoa_core::group_log::verify::verify_entry(
            &entry,
            &tips[0],
            stores.log_storage.as_ref(),
            &pubkey,
        )
        .await;

        assert!(
            result.is_ok(),
            "group log entry must carry a valid operator signature; got: {result:?}"
        );
    }

    #[tokio::test]
    async fn post_then_over_returns_article() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Integration Test", "<integ@test.example>");

        let (resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(
            resp.code, 240,
            "POST pipeline must return 240; got: {}",
            resp.text
        );

        let records = stores
            .overview_store
            .query_range("comp.test", 1, 10)
            .await
            .unwrap();
        assert_eq!(
            records.len(),
            1,
            "overview index must have exactly one record"
        );
        assert_eq!(records[0].article_number, 1);
        assert_eq!(records[0].subject, "Integration Test");
        assert_eq!(records[0].message_id, "<integ@test.example>");
    }

    /// Article stored via POST must contain a Path: header (RFC 5536 §3.1).
    #[tokio::test]
    async fn post_pipeline_stored_article_has_path_header() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Path Test", "<pathtest@test.example>");

        let (resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(resp.code, 240, "POST must succeed; got: {}", resp.text);

        let cid = stores
            .msgid_map
            .lookup_by_msgid("<pathtest@test.example>")
            .await
            .expect("msgid lookup must not fail")
            .expect("msgid must be in map after POST");
        let wire = fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid)
            .await
            .expect("fetch_article_wire_bytes must succeed");
        let text = String::from_utf8_lossy(&wire);
        assert!(
            text.to_ascii_lowercase().contains("path:"),
            "stored article must contain a Path: header (RFC 5536 §3.1): {text:.200}"
        );
        // The path_hostname for new_mem() is "localhost".
        assert!(
            text.contains("Path: localhost"),
            "Path header must contain the configured hostname: {text:.200}"
        );
    }

    // ── ARTICLE/HEAD/BODY by number (usenet-ipfs-1jr7) ───────────────────

    /// After posting an article, ARTICLE N must return 220 with the article.
    #[tokio::test]
    async fn article_by_number_returns_220() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "By Number Test", "<bynumber@test.example>");
        let (post_resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(post_resp.code, 240, "POST must succeed");

        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("comp.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let content = lookup_article_content_by_number(&stores, &mut ctx, 1)
            .await
            .expect("article 1 must be found");
        assert_eq!(content.article_number, 1);
        assert_eq!(content.message_id, "<bynumber@test.example>");
        assert_eq!(
            ctx.selected_group.as_ref().and_then(|sg| sg.article_number),
            Some(1)
        );
    }

    /// After posting, HEAD <msgid> must return 221.
    #[tokio::test]
    async fn head_by_msgid_returns_221() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Head By Msgid", "<headmsgid@test.example>");
        let (post_resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(post_resp.code, 240, "POST must succeed");

        let resp = lookup_head_by_msgid(&stores, "<headmsgid@test.example>").await;
        assert_eq!(
            resp.code, 221,
            "HEAD <msgid> must return 221; got: {}",
            resp.text
        );
        assert!(
            resp.body.iter().any(|l| l.contains("Head By Msgid")),
            "headers must contain Subject"
        );
        assert!(
            !resp.body.iter().any(|l| l == "Article body."),
            "body must not appear in HEAD"
        );
    }

    /// After posting, BODY <msgid> must return 222 and contain the body.
    #[tokio::test]
    async fn body_by_msgid_returns_222() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Body By Msgid", "<bodymsgid@test.example>");
        let (post_resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(post_resp.code, 240, "POST must succeed");

        let resp = lookup_body_by_msgid(&stores, "<bodymsgid@test.example>").await;
        assert_eq!(
            resp.code, 222,
            "BODY <msgid> must return 222; got: {}",
            resp.text
        );
        assert!(
            resp.body.iter().any(|l| l.contains("Article body.")),
            "body content must appear"
        );
        assert!(
            !resp.body.iter().any(|l| l.contains("Subject:")),
            "headers must not appear in BODY"
        );
    }

    /// Regression test for 3vye.12: STAT <msgid> must return 223 for a known
    /// article and 430 for an unknown message-id.
    ///
    /// Before the fix, `stat_article` in group.rs always returned 430 for the
    /// message-id form without consulting the msgid_map store.
    #[tokio::test]
    async fn stat_by_msgid_known_returns_223() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Stat Test", "<stattest@test.example>");
        let (post_resp, _) = run_post_pipeline(
            &article,
            &stores,
            DEFAULT_MAX_ARTICLE_BYTES,
            false,
            "127.0.0.1",
            None,
        )
        .await;
        assert_eq!(post_resp.code, 240, "POST must succeed");

        let resp = stat_by_msgid(&stores, "<stattest@test.example>").await;
        assert_eq!(
            resp.code, 223,
            "STAT <known-msgid> must return 223; got: {}",
            resp.text
        );
    }

    #[tokio::test]
    async fn stat_by_msgid_unknown_returns_430() {
        let stores = ServerStores::new_mem().await;
        let resp = stat_by_msgid(&stores, "<unknown@test.example>").await;
        assert_eq!(
            resp.code, 430,
            "STAT <unknown-msgid> must return 430; got: {}",
            resp.text
        );
    }

    /// ARTICLE N with unknown number must return 423.
    #[tokio::test]
    async fn article_by_number_unknown_returns_423() {
        let stores = ServerStores::new_mem().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("comp.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        match lookup_article_content_by_number(&stores, &mut ctx, 999).await {
            Err(r) => assert_eq!(r.code, 423, "must return 423 for unknown article number"),
            Ok(_) => panic!("expected Err but got Ok for unknown article number"),
        }
    }

    // ── SEARCH lifecycle tests ────────────────────────────────────────────

    /// SEARCH without a selected group must return 412.
    #[tokio::test]
    async fn nntp_search_no_group_returns_412() {
        let stores = ServerStores::new_mem().await;
        let ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        let resp = handle_nntp_search(&stores, &ctx, &SearchKey::Subject, "hello").await;
        assert!(
            resp.starts_with(b"412"),
            "must return 412 when no group is selected; got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    #[test]
    fn escape_tantivy_query_escapes_parens_and_colons() {
        let input = "foo(bar):baz";
        let escaped = escape_tantivy_query(input);
        assert!(escaped.contains("\\("), "( must be escaped");
        assert!(escaped.contains("\\:"), ": must be escaped");
        assert!(!escaped.contains("foo("), "unescaped ( must not remain");
    }

    /// SEARCH TEXT must escape Tantivy query syntax characters so a hostile
    /// client cannot inject boolean operators or field queries to break out of
    /// the newsgroup-scoped filter.
    ///
    /// Oracle: escape_tantivy_query is tested independently above.  This test
    /// confirms that handle_nntp_search calls it for SearchKey::Text by
    /// verifying that the escaping function produces the expected output for a
    /// hostile input, and that the handler reaches the index lookup (returning
    /// 503 because new_mem_no_search omits the index).
    #[tokio::test]
    async fn nntp_search_text_escapes_tantivy_syntax() {
        let stores = ServerStores::new_mem_no_search().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("misc.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        // A value containing Tantivy query syntax.  If passed raw, the colon
        // would introduce a field query that could escape the newsgroup filter.
        let hostile_value = "field:injection AND (secret OR private)";
        let escaped = escape_tantivy_query(hostile_value);
        assert!(
            escaped.contains("\\:"),
            "colon must be escaped in TEXT search value; got: {escaped:?}"
        );
        assert!(
            escaped.contains("\\("),
            "( must be escaped in TEXT search value; got: {escaped:?}"
        );

        // Confirm the handler returns 503 (no index), proving the code path
        // reaches the index lookup with an escaped query rather than panicking
        // or short-circuiting.
        let resp = handle_nntp_search(&stores, &ctx, &SearchKey::Text, hostile_value).await;
        assert!(
            resp.starts_with(b"503"),
            "must return 503 (no index) for TEXT search; got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// SEARCH with search_index = None must return 503.
    #[tokio::test]
    async fn nntp_search_no_index_returns_503() {
        let stores = ServerStores::new_mem_no_search().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("misc.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(&stores, &ctx, &SearchKey::Subject, "hello").await;
        assert!(
            resp.starts_with(b"503"),
            "must return 503 when search index is None; got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    // ── ld7.12: Since/Before return 501, not a free-text date query ───────

    /// SEARCH SINCE must return 501, not silently pass the date string as a
    /// free-text query.  Oracle: the 501 response is the only correct answer
    /// for a key whose semantics require a dedicated date-range implementation.
    #[tokio::test]
    async fn nntp_search_since_returns_501() {
        let stores = ServerStores::new_mem().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("misc.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(
            &stores,
            &ctx,
            &SearchKey::Since,
            "Mon, 01 Jan 2024 00:00:00 +0000",
        )
        .await;
        assert!(
            resp.starts_with(b"501"),
            "SEARCH SINCE must return 501 (not implemented), got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// SEARCH BEFORE must also return 501.
    #[tokio::test]
    async fn nntp_search_before_returns_501() {
        let stores = ServerStores::new_mem().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        ctx.selected_group = Some(crate::session::context::SelectedGroup {
            name: stoa_core::article::GroupName::new("misc.test").unwrap(),
            article_number: None,
        });
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(
            &stores,
            &ctx,
            &SearchKey::Before,
            "Mon, 01 Jan 2024 00:00:00 +0000",
        )
        .await;
        assert!(
            resp.starts_with(b"501"),
            "SEARCH BEFORE must return 501 (not implemented), got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    // ── usenet-ipfs-07rs.8: RFC 5322 §2.2.3 folded header unfolding ──────

    /// extract_header_value must unfold a Message-ID header folded across two
    /// lines per RFC 5322 §2.2.3.  The continuation line starts with a single
    /// SP or HTAB; the result must be the unfolded value with internal
    /// whitespace collapsed to a single space.
    ///
    /// Oracle: RFC 5322 §2.2.3 specifies the exact unfolding algorithm.
    /// The expected result is the concatenation of the first-line value and the
    /// continuation-line value, separated by exactly one space.
    #[test]
    fn extract_header_value_unfolds_folded_header() {
        // Folded Message-ID: value split across two lines.
        // The continuation line begins with a single space followed by content.
        let headers = "From: sender@example.com\r\nMessage-ID: <part1\r\n part2@example.com>\r\nSubject: Test\r\n";
        let result = extract_header_value(headers, "Message-ID");
        assert_eq!(
            result.as_deref(),
            Some("<part1 part2@example.com>"),
            "folded Message-ID must be unfolded to a single value; got: {result:?}"
        );
    }

    /// extract_header_value must unfold a header folded with HTAB as the
    /// continuation leader (RFC 5322 §2.2.3 permits both SP and HTAB).
    #[test]
    fn extract_header_value_unfolds_htab_continuation() {
        let headers = "Message-ID: <abc\r\n\tdef@example.com>\r\n";
        let result = extract_header_value(headers, "Message-ID");
        assert_eq!(
            result.as_deref(),
            Some("<abc def@example.com>"),
            "HTAB continuation must be unfolded; got: {result:?}"
        );
    }

    /// extract_header_value must not include lines after the first
    /// non-continuation line in the value.
    #[test]
    fn extract_header_value_stops_at_non_continuation() {
        let headers = "Message-ID: <abc@example.com>\r\nSubject: not part of msgid\r\n";
        let result = extract_header_value(headers, "Message-ID");
        assert_eq!(
            result.as_deref(),
            Some("<abc@example.com>"),
            "value must not bleed into the next header; got: {result:?}"
        );
    }

    // ── zmn9.23 / zmn9.25: auth gate and 412 vs 420 regression tests ─────────

    /// Build a minimal Config for use in command-loop tests.
    fn minimal_config() -> crate::config::Config {
        let toml = r#"
[listen]
addr = "127.0.0.1:11990"

[limits]
command_timeout_secs = 5

[auth]
required = true

[tls]

[ipfs]
api_url = "http://127.0.0.1:5001"
"#;
        toml::from_str(toml).expect("minimal_config: TOML must parse")
    }

    /// Run the command loop on a byte-slice input, returning the collected output.
    async fn run_loop_bytes(
        input: &[u8],
        ctx: &mut crate::session::context::SessionContext,
    ) -> Vec<u8> {
        use std::sync::Arc;
        use tokio::io::BufReader;
        let stores = Arc::new(ServerStores::new_mem().await);
        let config = minimal_config();
        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut output: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(std::io::Cursor::new(input.to_vec()));
        run_command_loop(&mut reader, &mut output, ctx, peer, &config, &stores).await;
        output
    }

    /// RFC 3977 §7.1.1 / zmn9.23: an unauthenticated client that issues ARTICLE
    /// with a MessageId must receive 480 (Authentication Required), not 430.
    ///
    /// Before the fix, the pre-dispatch match in run_command_loop would call
    /// lookup_article_by_msgid and return 430 without checking auth state.
    #[tokio::test]
    async fn article_msgid_while_authenticating_returns_480() {
        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // auth_required=true → SessionState::Authenticating
        let mut ctx = crate::session::context::SessionContext::new(
            peer,
            crate::session::context::SessionFlags {
                auth_required: true,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert_eq!(
            ctx.state,
            crate::session::state::SessionState::Authenticating
        );

        let input = b"ARTICLE <test@example.com>\r\nQUIT\r\n";
        let out = run_loop_bytes(input, &mut ctx).await;
        let output_str = String::from_utf8_lossy(&out);
        let code: u16 = output_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("must produce a numeric response code");
        assert_eq!(
            code, 480,
            "unauthenticated ARTICLE <msgid> must return 480, got {code}; output: {output_str}"
        );
    }

    /// RFC 3977 §8.1 / zmn9.25: ARTICLE with no argument when no group is
    /// selected must return 412 (No newsgroup selected), not 420.
    ///
    /// 420 means "current article number is invalid" (group selected but NEXT/LAST
    /// exhausted the list).  412 is the correct code when no group was ever selected.
    #[tokio::test]
    async fn article_no_arg_without_group_returns_412() {
        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // auth_required=false → SessionState::Active, no group selected
        let mut ctx = crate::session::context::SessionContext::new(
            peer,
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert_eq!(ctx.state, crate::session::state::SessionState::Active);
        assert!(ctx.selected_group.is_none());

        let input = b"ARTICLE\r\nQUIT\r\n";
        let out = run_loop_bytes(input, &mut ctx).await;
        let output_str = String::from_utf8_lossy(&out);
        let code: u16 = output_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("must produce a numeric response code");
        assert_eq!(
            code, 412,
            "ARTICLE with no arg and no group must return 412, got {code}; output: {output_str}"
        );
    }

    /// RFC 3977 §8.2 / zmn9.25: HEAD with no argument when no group is selected
    /// must return 412 (No newsgroup selected), not 420.
    #[tokio::test]
    async fn head_no_arg_without_group_returns_412() {
        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // auth_required=false → SessionState::Active, no group selected
        let mut ctx = crate::session::context::SessionContext::new(
            peer,
            crate::session::context::SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert_eq!(ctx.state, crate::session::state::SessionState::Active);
        assert!(ctx.selected_group.is_none());

        let input = b"HEAD\r\nQUIT\r\n";
        let out = run_loop_bytes(input, &mut ctx).await;
        let output_str = String::from_utf8_lossy(&out);
        let code: u16 = output_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("must produce a numeric response code");
        assert_eq!(
            code, 412,
            "HEAD with no arg and no group must return 412, got {code}; output: {output_str}"
        );
    }
}
