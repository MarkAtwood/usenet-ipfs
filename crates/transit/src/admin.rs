//! Admin HTTP server for the transit daemon.
//!
//! Listens on a configurable address and serves a small set of JSON endpoints
//! for operator inspection. Optionally requires a bearer token; bind to
//! loopback only in production (see [`crate::config::AdminConfig`]).
//!
//! Endpoints:
//! - `GET /healthz/live`     — liveness probe: always 200 if process is running
//! - `GET /healthz/ready`    — readiness probe: 200 when SQLite and IPFS are up; 503 otherwise
//! - `GET /health`           — backward-compatible alias for `/healthz/ready`
//! - `GET /stats`            — article, pin, group, and peer counts from SQLite
//! - `GET /log-tip?group=X`  — tip CID and entry count for a group log
//! - `GET /peers`            — extended health info for active (non-blacklisted) peers
//! - `GET /peers/<addr>/ping` — TCP liveness probe for a peer address (returns latency_ms)
//! - `GET /metrics`          — Prometheus text format (delegates to [`crate::metrics`])
//! - `GET /pinning/remote`   — per-service job counts from the remote pin jobs table
//! - `GET /ipns`             — IPNS address and latest article CID per group
//! - `GET /version`          — binary name and semver version
//! - `GET /groups`           — distinct group names known to this node
//! - `GET /gc/last-run`      — last GC run report as JSON (null if no run yet)
//! - `POST /reload`          — re-reads config and applies live-reloadable fields; returns diff
//!
//! ## Authorization model (v1 limitation)
//!
//! A single bearer token controls access to all endpoints, including
//! `/export/car` which can export complete article archives.  Any bearer token
//! holder has full read access to all data.  Do not share the admin token with
//! read-only monitoring systems in a production deployment; use network-level
//! access controls (firewall, loopback binding) to restrict `/export/car`
//! access until per-endpoint authorization is implemented in a future release.

use sqlx::AnyPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stoa_core::audit::{AuditEvent, AuditLogger};
use stoa_core::rate_limiter::RateLimiter;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Check TLS certificate expiry, update the Prometheus gauge, log
/// warnings/errors, and return a JSON summary for API responses.
///
/// - ≤ 30 days remaining: WARN log (`event=cert_expiry_warning`)
/// - ≤  7 days remaining: ERROR log (`event=cert_expiry_critical`)
///
/// Parse failures are logged at WARN and return an object with an `"error"` key.
pub fn check_cert_expiry(cert_path: &str) -> serde_json::Value {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    match stoa_tls::cert_not_after(cert_path) {
        Ok(expiry_unix) => {
            let days_remaining = (expiry_unix - now_secs) / 86400;
            let expires_at = chrono::DateTime::from_timestamp(expiry_unix, 0)
                .map(|t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| expiry_unix.to_string());
            crate::metrics::TLS_CERT_EXPIRY_SECONDS
                .with_label_values(&[cert_path])
                .set(expiry_unix as f64);
            if days_remaining <= 7 {
                tracing::error!(
                    event = "cert_expiry_critical",
                    path = cert_path,
                    days_remaining,
                    expires_at = %expires_at,
                    "TLS certificate expires very soon"
                );
            } else if days_remaining <= 30 {
                tracing::warn!(
                    event = "cert_expiry_warning",
                    path = cert_path,
                    days_remaining,
                    expires_at = %expires_at,
                    "TLS certificate expiring soon"
                );
            }
            serde_json::json!({
                "path": cert_path,
                "expires_at": expires_at,
                "days_remaining": days_remaining,
            })
        }
        Err(e) => {
            tracing::warn!(path = cert_path, "TLS cert expiry check failed: {e}");
            serde_json::json!({ "path": cert_path, "error": e.to_string() })
        }
    }
}

#[derive(Debug)]
pub(crate) enum AdminError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Sqlx(sqlx::Error),
    Other(String),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Io(e) => write!(f, "I/O error: {e}"),
            AdminError::Serde(e) => write!(f, "JSON error: {e}"),
            AdminError::Sqlx(e) => write!(f, "database error: {e}"),
            AdminError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<std::io::Error> for AdminError {
    fn from(e: std::io::Error) -> Self {
        AdminError::Io(e)
    }
}

impl From<serde_json::Error> for AdminError {
    fn from(e: serde_json::Error) -> Self {
        AdminError::Serde(e)
    }
}

impl From<sqlx::Error> for AdminError {
    fn from(e: sqlx::Error) -> Self {
        AdminError::Sqlx(e)
    }
}

impl From<String> for AdminError {
    fn from(e: String) -> Self {
        AdminError::Other(e)
    }
}

use crate::peering::pipeline::IpfsStore;

/// SQLite pool pair for the admin server.
///
/// `transit_pool` is the transit schema (transit.db); `core_pool` is the core
/// schema (transit_core.db).  Grouped here to keep `start_admin_server` under
/// clippy's 7-argument limit.
pub struct AdminPools {
    pub transit_pool: Arc<AnyPool>,
    pub core_pool: Arc<AnyPool>,
    pub audit_logger: Option<Arc<dyn AuditLogger>>,
    /// Directory for SQLite backups.  `None` disables `POST /admin/backup`.
    pub backup_dest_dir: Option<String>,
    /// Shared live-reloadable config state.  `None` disables `POST /admin/reload`
    /// (returns 200 with `{"reloaded":false}` stub instead).
    pub reload_state: Option<Arc<crate::reload::ReloadableState>>,
    /// IPFS API base URL (e.g. `"http://127.0.0.1:5001"`).  When present,
    /// `/healthz/ready` will call `node_id` to verify Kubo reachability.
    /// When `None` (e.g. in tests using `MemIpfsStore`) the IPFS check is skipped.
    pub ipfs_api_url: Option<String>,
    /// Last GC run report for `GET /gc/last-run`.  Obtain via
    /// `GcRunner::last_report_handle()` before starting the scheduler.
    /// `None` when GC is not configured (returns `{"report":null}`).
    pub last_gc_report:
        Option<Arc<tokio::sync::RwLock<Option<crate::retention::gc_report::GcReport>>>>,
}

/// Start the admin HTTP server on the given address.
///
/// Accepts `AnyPool` for live stats queries, an optional bearer token for
/// authentication, and a per-IP rate limit in requests per minute (0 = unlimited).
/// Spawns a background tokio task. Returns immediately.
///
/// `core_pool` is the SQLite pool for the core schema (transit_core.db); it is
/// used by `build_stats_json` to query `msgid_map`. `pool` is the transit schema
/// pool (transit.db) used for all other queries.
///
/// # Fail-closed: non-loopback without bearer token
///
/// Returns `Err` if `addr` is non-loopback and `bearer_token` is `None`.
/// An unauthenticated admin endpoint on a reachable interface is a security
/// footgun in production; the server must not start in that configuration.
#[allow(clippy::too_many_arguments)]
pub fn start_admin_server(
    listener: tokio::net::TcpListener,
    pools: AdminPools,
    start_time: Instant,
    bearer_token: Option<String>,
    rate_limit_rpm: u32,
    ipfs: Arc<dyn IpfsStore>,
    ipns_path: Option<String>,
    cert_paths: Arc<Vec<String>>,
) -> Result<(), String> {
    let addr = listener
        .local_addr()
        .map_err(|e| format!("admin listener has no local address: {e}"))?;
    if !addr.ip().is_loopback() && bearer_token.is_none() {
        return Err(format!(
            "admin endpoint at {addr} is on a non-loopback interface but no bearer_token \
             is configured — refusing to start an unauthenticated admin server"
        ));
    }
    let bearer_token = Arc::new(bearer_token);
    let rate_limiter = Arc::new(RateLimiter::new(rate_limit_rpm));
    let ipns_path = Arc::new(ipns_path);
    let transit_pool = pools.transit_pool;
    let core_pool = pools.core_pool;
    let audit_logger = pools.audit_logger;
    let backup_dest_dir = Arc::new(pools.backup_dest_dir);
    let reload_state: Option<Arc<crate::reload::ReloadableState>> = pools.reload_state;
    let ipfs_api_url = Arc::new(pools.ipfs_api_url);
    let last_gc_report = pools.last_gc_report;
    tokio::spawn(async move {
        tracing::info!("admin server listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let transit_pool = Arc::clone(&transit_pool);
                    let core_pool = Arc::clone(&core_pool);
                    let bearer_token = Arc::clone(&bearer_token);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let ipfs = Arc::clone(&ipfs);
                    let ipns_path = Arc::clone(&ipns_path);
                    let audit_logger = audit_logger.clone();
                    let backup_dest_dir = Arc::clone(&backup_dest_dir);
                    let cert_paths = Arc::clone(&cert_paths);
                    let reload_state = reload_state.clone();
                    let ipfs_api_url = Arc::clone(&ipfs_api_url);
                    let last_gc_report = last_gc_report.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_admin_connection(
                            stream,
                            (&*transit_pool, &*core_pool),
                            start_time,
                            bearer_token.as_deref(),
                            &rate_limiter,
                            &*ipfs,
                            ipns_path.as_deref(),
                            audit_logger.as_deref(),
                            backup_dest_dir.as_deref(),
                            &cert_paths,
                            reload_state.as_deref(),
                            ipfs_api_url.as_deref(),
                            last_gc_report.as_ref(),
                        )
                        .await
                        {
                            tracing::warn!("admin connection error from {peer}: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("admin server accept error: {e}");
                }
            }
        }
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_admin_connection(
    stream: tokio::net::TcpStream,
    pools: (&AnyPool, &AnyPool),
    start_time: Instant,
    bearer_token: Option<&str>,
    rate_limiter: &RateLimiter,
    ipfs: &dyn IpfsStore,
    ipns_path: Option<&str>,
    audit_logger: Option<&dyn AuditLogger>,
    backup_dest_dir: Option<&str>,
    cert_paths: &[String],
    reload_state: Option<&crate::reload::ReloadableState>,
    ipfs_api_url: Option<&str>,
    last_gc_report: Option<
        &Arc<tokio::sync::RwLock<Option<crate::retention::gc_report::GcReport>>>,
    >,
) -> Result<(), AdminError> {
    let (pool, core_pool) = pools;
    let peer_ip = stream.peer_addr()?.ip();
    let mut reader = BufReader::new(stream);

    // Hard deadline for receiving the full request line + headers.  A client
    // that drips bytes one at a time (slowloris) will be dropped after this.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    // Cap on header lines: prevents an infinite loop of valid lines with no
    // blank terminator.
    const MAX_HEADER_LINES: usize = 64;

    let (method_owned, path_and_query_owned, auth_header) =
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            // Read request line.
            let mut request_line = String::new();
            reader.read_line(&mut request_line).await?;
            let rl = request_line.trim_end_matches(['\r', '\n']).to_string();
            let mut parts = rl.splitn(3, ' ');
            let method = parts.next().unwrap_or("").to_string();
            let path_and_query = parts.next().unwrap_or("").to_string();

            // Read headers until blank line.
            let mut auth_header: Option<String> = None;
            for _ in 0..MAX_HEADER_LINES {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let line = line.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    break;
                }
                if let Some(val) = line.strip_prefix("Authorization: ") {
                    auth_header = Some(val.to_string());
                }
            }

            Ok::<_, std::io::Error>((method, path_and_query, auth_header))
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "admin request read timeout")
        })??;

    let method = method_owned.as_str();
    let path_and_query = path_and_query_owned.as_str();

    // Split path from query string (needed before rate-limit check for /metrics exemption).
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };

    // Extract the underlying stream for writing responses.
    let mut writer = reader.into_inner();

    // Check bearer token if configured. This runs before rate limiting so that
    // unauthenticated requests are rejected with 401 without consuming a
    // rate-limit slot (rbe3.22).
    // Bearer token comparison uses subtle::ConstantTimeEq (see check_bearer_token
    // below) to prevent timing-oracle attacks even on loopback.
    if !check_bearer_token(auth_header.as_deref(), bearer_token) {
        tracing::debug!("admin request rejected: missing or invalid bearer token");
        write_json(
            &mut writer,
            401,
            "Unauthorized",
            r#"{"error":"unauthorized"}"#,
        )
        .await?;
        return Ok(());
    }

    if bearer_token.is_none() {
        tracing::debug!("admin request accepted: no bearer token configured");
    }

    // Apply per-IP rate limiting. /metrics is exempt (polled frequently by Prometheus).
    if path != "/metrics" && !rate_limiter.check_and_consume(peer_ip) {
        tracing::debug!("admin request rate-limited from {peer_ip}");
        let rpm = rate_limiter.rpm();
        // clamp to [1, 60]: prevents Retry-After: 0 for high rpm (e.g. rpm=120 → 60/120=0 → 1s).
        let retry_after = if rpm > 0 {
            (60u32 / rpm).clamp(1, 60)
        } else {
            60
        };
        let body = r#"{"error":"rate limit exceeded"}"#;
        let content_length = body.len();
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: {retry_after}\r\n{SECURITY_HEADERS}Content-Length: {content_length}\r\n\r\n{body}"
        );
        writer.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let method_ok = match path {
        "/reload" | "/backup" => method == "POST",
        _ => method == "GET",
    };
    if !method_ok {
        write_json(
            &mut writer,
            405,
            "Method Not Allowed",
            r#"{"error":"method not allowed"}"#,
        )
        .await?;
        return Ok(());
    }

    // Audit: log authenticated, non-rate-limited, method-valid requests at dispatch
    // time (before the handler runs). status_code 0 is a pre-response sentinel;
    // the key audit information is who accessed what path.
    if let Some(logger) = audit_logger {
        logger.log(AuditEvent::AdminAccess {
            peer_addr: peer_ip.to_string(),
            path: path.to_string(),
            method: method.to_string(),
            status_code: 0,
        });
    }

    match path {
        "/healthz/live" => {
            let body = build_liveness_json(start_time);
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        "/healthz/ready" | "/health" => {
            let (status, body) =
                build_readiness_json(pool, core_pool, ipfs_api_url, start_time).await;
            let reason = if status == 200 {
                "OK"
            } else {
                "Service Unavailable"
            };
            write_json(&mut writer, status, reason, &body).await?;
        }
        "/stats" => match build_stats_json(pool, core_pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /stats error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/log-tip" => {
            let group = extract_query_param(query, "group");
            match group {
                None => {
                    write_json(
                        &mut writer,
                        400,
                        "Bad Request",
                        r#"{"error":"missing group parameter"}"#,
                    )
                    .await?;
                }
                Some(g) => match build_log_tip_json(pool, &g).await {
                    Some(body) => write_json(&mut writer, 200, "OK", &body).await?,
                    None => {
                        write_json(
                            &mut writer,
                            404,
                            "Not Found",
                            r#"{"error":"group not found"}"#,
                        )
                        .await?
                    }
                },
            }
        }
        "/peers" => {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            match build_peers_json(pool, now_ms).await {
                Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
                Err(e) => {
                    tracing::warn!("admin /peers error: {e}");
                    write_json(
                        &mut writer,
                        500,
                        "Internal Server Error",
                        r#"{"error":"internal server error"}"#,
                    )
                    .await?;
                }
            }
        }
        "/metrics" => {
            let body = crate::metrics::gather_metrics();
            let content_length = body.len();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n{SECURITY_HEADERS}Content-Length: {content_length}\r\n\r\n{body}"
            );
            writer.write_all(response.as_bytes()).await?;
        }
        "/pinning/remote" => match build_pinning_remote_json(pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /pinning/remote error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/export/car" => {
            let group = extract_query_param(query, "group").filter(|g| !g.is_empty());
            if let Some(group) = group {
                let limit: i64 = extract_query_param(query, "limit")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1000)
                    .clamp(1, 10000);
                match crate::export::build_export_car(pool, ipfs, &group, limit).await {
                    Ok(car_bytes) => {
                        write_binary_car(&mut writer, &car_bytes).await?;
                    }
                    Err(e) => {
                        tracing::warn!("admin /export/car error: {e}");
                        write_json(
                            &mut writer,
                            500,
                            "Internal Server Error",
                            r#"{"error":"internal server error"}"#,
                        )
                        .await?;
                    }
                }
            } else {
                write_json(
                    &mut writer,
                    400,
                    "Bad Request",
                    r#"{"error":"missing group parameter"}"#,
                )
                .await?;
            }
        }
        "/ipns" => match build_ipns_json(pool, ipns_path).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /ipns error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/version" => {
            write_json(&mut writer, 200, "OK", &build_version_json()).await?;
        }
        "/groups" => match build_groups_json(pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /groups error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/backup" => match backup_dest_dir {
            None => {
                write_json(
                    &mut writer,
                    503,
                    "Service Unavailable",
                    r#"{"error":"backup.dest_dir is not configured"}"#,
                )
                .await?;
            }
            Some(dest_dir) => match backup_databases(pool, core_pool, dest_dir).await {
                Ok(paths) => {
                    let files_json = paths
                        .iter()
                        .map(|p| format!("\"{}\"", p.replace('\\', "\\\\").replace('"', "\\\"")))
                        .collect::<Vec<_>>()
                        .join(",");
                    let body = format!("{{\"backups\":[{files_json}]}}");
                    write_json(&mut writer, 200, "OK", &body).await?;
                }
                Err(e) => {
                    tracing::warn!("admin /backup error: {e}");
                    write_json(
                        &mut writer,
                        500,
                        "Internal Server Error",
                        r#"{"error":"backup failed"}"#,
                    )
                    .await?;
                }
            },
        },
        "/reload" => {
            // Live config reload: re-read the config file and apply reloadable
            // fields (groups.names, peering.trusted_peers).  Also re-checks
            // TLS certificate expiry so operators can confirm cert rotation
            // succeeded without restarting.
            let mut cert_results: Vec<serde_json::Value> = Vec::new();
            for path in cert_paths.iter() {
                cert_results.push(check_cert_expiry(path));
            }
            // Apply live reload (if available) and collect the diff.
            let (reload_changed, reload_errors, did_reload) = if let Some(rs) = reload_state {
                let result = rs.do_reload().await;
                let changed = result.changed.clone();
                let errors = result.errors.clone();
                (changed, errors, true)
            } else {
                (vec![], vec![], false)
            };

            let body = serde_json::json!({
                "reloaded": did_reload,
                "changed": reload_changed,
                "errors": reload_errors,
                "tls_certs_checked": cert_results.len(),
                "tls_certs": cert_results,
            })
            .to_string();
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        "/gc/last-run" => {
            let body = match last_gc_report {
                Some(report_lock) => {
                    let guard = report_lock.read().await;
                    match &*guard {
                        Some(report) => serde_json::to_string(report)
                            .map(|s| format!("{{\"report\":{s}}}"))
                            .unwrap_or_else(|_| r#"{"error":"serialize error"}"#.to_string()),
                        None => r#"{"report":null}"#.to_string(),
                    }
                }
                None => r#"{"report":null}"#.to_string(),
            };
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        path if path.starts_with("/peers/") && path.ends_with("/ping") => {
            let encoded_addr = &path["/peers/".len()..path.len() - "/ping".len()];
            let address = percent_decode(encoded_addr);
            if address.is_empty() {
                write_json(
                    &mut writer,
                    400,
                    "Bad Request",
                    r#"{"error":"missing peer address"}"#,
                )
                .await?;
            } else {
                let (reachable, latency_ms) = ping_peer(&address).await;
                let body = serde_json::json!({
                    "address": address,
                    "reachable": reachable,
                    "latency_ms": latency_ms,
                })
                .to_string();
                write_json(&mut writer, 200, "OK", &body).await?;
            }
        }
        _ => {
            write_json(&mut writer, 404, "Not Found", r#"{"error":"not found"}"#).await?;
        }
    }

    Ok(())
}

/// Backup `transit_pool` and `core_pool` to timestamped files in `dest_dir`.
///
/// Uses SQLite's `VACUUM INTO` statement, which copies the live database to a
/// new file atomically and is safe to run while the database is open.  The
/// destination directory is created if it does not exist.
///
/// Returns the list of backup file paths on success.
pub(crate) async fn backup_databases(
    transit_pool: &AnyPool,
    core_pool: &AnyPool,
    dest_dir: &str,
) -> Result<Vec<String>, AdminError> {
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    tokio::fs::create_dir_all(dest_dir).await?;

    let mut paths = Vec::new();
    for (name, pool) in [("transit", transit_pool), ("core", core_pool)] {
        let filename = format!("{name}-{timestamp}.db");
        let dest = format!("{dest_dir}/{filename}");
        // VACUUM INTO requires a literal path; dest_dir is operator-controlled config.
        // Reject paths containing single-quote to prevent SQL syntax errors.
        if dest.contains('\'') {
            return Err(format!("backup path must not contain single quotes: {dest}").into());
        }
        sqlx::query(&format!("VACUUM INTO '{dest}'"))
            .execute(pool)
            .await?;
        paths.push(dest);
    }
    Ok(paths)
}

/// Check whether an Authorization header satisfies the configured bearer token.
///
/// Returns `true` if:
/// - No token is configured (`bearer_token` is `None`), or
/// - The header is present and exactly matches `"Bearer <token>"`.
///
/// Returns `false` if a token is configured and the header is missing or incorrect.
///
/// The comparison is constant-time (via `subtle::ConstantTimeEq`) to prevent
/// timing oracles that could leak the token one character at a time.
pub(crate) fn check_bearer_token(auth_header: Option<&str>, bearer_token: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    match bearer_token {
        None => true,
        Some(token) => {
            let expected = format!("Bearer {token}");
            match auth_header {
                None => false,
                Some(header) => {
                    // ct_eq returns Choice (0 or 1); lengths must match first.
                    // Comparing different-length slices returns 0 (not equal).
                    expected.as_bytes().ct_eq(header.as_bytes()).into()
                }
            }
        }
    }
}

/// Extract the value of a named query parameter from a URL query string.
///
/// Handles simple `key=value` pairs and percent-decodes the value so that
/// clients using `percent_encode` (e.g. `stoa-ctl`) get back the original
/// string regardless of whether any characters were encoded.
fn extract_query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

/// Decode a percent-encoded string (e.g. `%20` → space, `%2F` → `/`).
///
/// Invalid `%XX` sequences (non-hex digits or truncated) are left as-is.
/// If the decoded bytes are not valid UTF-8, replacement characters are
/// substituted (defensive: well-formed inputs are always valid UTF-8).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (
                i.checked_add(2)
                    .filter(|&end| end < bytes.len())
                    .and_then(|_| hex_nibble(bytes[i + 1])),
                i.checked_add(2)
                    .filter(|&end| end < bytes.len())
                    .and_then(|_| hex_nibble(bytes[i + 2])),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Convert a single ASCII hex digit byte to its numeric value, or `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Standard security response headers injected into every admin HTTP response.
///
/// HSTS is intentionally absent: the admin server runs over plain TCP (no TLS),
/// so sending HSTS would be incorrect and misleading.
const SECURITY_HEADERS: &str = "\
    X-Content-Type-Options: nosniff\r\n\
    X-Frame-Options: DENY\r\n\
    Referrer-Policy: strict-origin-when-cross-origin\r\n\
    Content-Security-Policy: default-src 'none'\r\n\
    Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n";

async fn write_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    status_text: &str,
    body: &str,
) -> std::io::Result<()> {
    let content_length = body.len();
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\n{SECURITY_HEADERS}Content-Length: {content_length}\r\n\r\n{body}"
    );
    writer.write_all(response.as_bytes()).await
}

/// Write a CARv1 binary response with the standard IPLD CAR content-type.
async fn write_binary_car<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    let content_length = body.len();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.ipld.car; version=1\r\n{SECURITY_HEADERS}Content-Length: {content_length}\r\n\r\n"
    );
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body).await
}

/// Build the liveness JSON body (always succeeds; no external deps).
///
/// Used by `GET /healthz/live`.
pub(crate) fn build_liveness_json(start_time: Instant) -> String {
    let uptime_secs = start_time.elapsed().as_secs();
    serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
    })
    .to_string()
}

/// A single dependency check result.
#[derive(Debug)]
struct HealthCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// Build the readiness JSON body and the HTTP status code (200 or 503).
///
/// Checks:
/// - `sqlite_transit`: can we `SELECT 1` from the transit schema?
/// - `sqlite_core`: can we `SELECT 1` from the core schema?
/// - `kubo_reachable`: if `ipfs_api_url` is set, is Kubo's `/api/v0/id` reachable?
///
/// Returns `(status_code, json_body)`.
pub(crate) async fn build_readiness_json(
    pool: &AnyPool,
    core_pool: &AnyPool,
    ipfs_api_url: Option<&str>,
    start_time: Instant,
) -> (u16, String) {
    const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

    let mut checks: Vec<HealthCheck> = Vec::new();

    // ── sqlite_transit ────────────────────────────────────────────────────────
    checks.push(
        match tokio::time::timeout(
            CHECK_TIMEOUT,
            sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(pool),
        )
        .await
        {
            Ok(Ok(_)) => HealthCheck {
                name: "sqlite_transit",
                ok: true,
                detail: String::new(),
            },
            Ok(Err(e)) => HealthCheck {
                name: "sqlite_transit",
                ok: false,
                detail: e.to_string(),
            },
            Err(_) => HealthCheck {
                name: "sqlite_transit",
                ok: false,
                detail: "timeout".to_string(),
            },
        },
    );

    // ── sqlite_core ───────────────────────────────────────────────────────────
    checks.push(
        match tokio::time::timeout(
            CHECK_TIMEOUT,
            sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(core_pool),
        )
        .await
        {
            Ok(Ok(_)) => HealthCheck {
                name: "sqlite_core",
                ok: true,
                detail: String::new(),
            },
            Ok(Err(e)) => HealthCheck {
                name: "sqlite_core",
                ok: false,
                detail: e.to_string(),
            },
            Err(_) => HealthCheck {
                name: "sqlite_core",
                ok: false,
                detail: "timeout".to_string(),
            },
        },
    );

    // ── kubo_reachable ────────────────────────────────────────────────────────
    if let Some(url) = ipfs_api_url {
        let client = stoa_core::ipfs::KuboHttpClient::new(url);
        checks.push(
            match tokio::time::timeout(CHECK_TIMEOUT, client.node_id()).await {
                Ok(Ok(peer_id)) => HealthCheck {
                    name: "kubo_reachable",
                    ok: true,
                    detail: format!("peer ID: {peer_id}"),
                },
                Ok(Err(e)) => HealthCheck {
                    name: "kubo_reachable",
                    ok: false,
                    detail: format!("Kubo error: {e}"),
                },
                Err(_) => HealthCheck {
                    name: "kubo_reachable",
                    ok: false,
                    detail: "timeout connecting to Kubo".to_string(),
                },
            },
        );
    }

    let all_ok = checks.iter().all(|c| c.ok);
    let status_str = if all_ok { "ok" } else { "degraded" };
    let status_code: u16 = if all_ok { 200 } else { 503 };

    let checks_json: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "ok": c.ok,
                "detail": c.detail,
            })
        })
        .collect();

    let uptime_secs = start_time.elapsed().as_secs();
    let body = serde_json::json!({
        "status": status_str,
        "uptime_secs": uptime_secs,
        "checks": checks_json,
    })
    .to_string();

    (status_code, body)
}

pub(crate) async fn build_stats_json(
    pool: &AnyPool,
    core_pool: &AnyPool,
) -> Result<String, sqlx::Error> {
    // msgid_map lives in the core schema (transit_core.db), not the transit
    // schema (transit.db) — use core_pool here (rbe3.12).
    let articles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(core_pool)
        .await
        .unwrap_or(0);

    let pinned_cids: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pinned_cids")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let groups: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT group_name) FROM articles")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let now_ms_peers = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let peers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM peers WHERE blacklisted_until IS NULL OR blacklisted_until <= ?",
    )
    .bind(now_ms_peers)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(serde_json::json!({
        "articles": articles,
        "pinned_cids": pinned_cids,
        "groups": groups,
        "peers": peers,
    })
    .to_string())
}

pub(crate) async fn build_log_tip_json(pool: &AnyPool, group: &str) -> Option<String> {
    // Fetch the row with the highest sequence_number explicitly.
    // SELECT MAX(sequence_number), cid is wrong: SQLite returns an arbitrary
    // row's cid when mixing a bare aggregate (MAX) with a non-aggregated column.
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT sequence_number, cid FROM group_log WHERE group_name = ? \
         ORDER BY sequence_number DESC LIMIT 1",
    )
    .bind(group)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    row.map(|(seq, cid)| {
        serde_json::json!({
            "group": group,
            "tip_cid": cid,
            "entry_count": seq,
        })
        .to_string()
    })
}

/// Build JSON stats for `GET /pinning/remote`.
///
/// Returns a JSON array with one object per service name found in the
/// `remote_pin_jobs` table, showing counts by status.
///
/// Example response:
/// ```json
/// [{"service":"pinata","pending":2,"queued":1,"pinning":0,"pinned":10,"failed":0}]
/// ```
pub async fn build_pinning_remote_json(pool: &AnyPool) -> Result<String, sqlx::Error> {
    // Aggregate counts per (service_name, status) in one query.
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT service_name, status, COUNT(*) as cnt \
         FROM remote_pin_jobs \
         GROUP BY service_name, status \
         ORDER BY service_name, status",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Pivot into per-service objects.
    let mut by_service: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();

    for (svc, status, count) in rows {
        let entry = by_service.entry(svc.clone()).or_insert_with(|| {
            serde_json::json!({
                "service": svc,
                "pending": 0i64,
                "queued": 0i64,
                "pinning": 0i64,
                "pinned": 0i64,
                "failed": 0i64,
            })
        });
        if let Some(v) = entry.get_mut(status.as_str()) {
            *v = serde_json::json!(count);
        }
    }

    let result: Vec<serde_json::Value> = by_service.into_values().collect();
    Ok(serde_json::to_string(&result).unwrap_or_else(|_| "[]".to_string()))
}

/// Returns JSON array of active (non-blacklisted) peers with extended health fields.
///
/// Fields per peer:
/// - `peer_id` — unique identifier
/// - `address` — configured host:port
/// - `connected` — true when `last_seen_ms` is within the last 5 minutes (liveness proxy)
/// - `last_seen` — ISO8601 UTC timestamp of last successful article exchange
/// - `articles_received` — articles accepted from this peer since daemon start
/// - `articles_rejected` — articles rejected from this peer since daemon start
/// - `consecutive_failures` — current run of consecutive rejection events
/// - `health_score` — composite score in [0.0, 1.0] (see `peer_score`)
/// - `configured` — true when this peer appears in operator config
pub(crate) async fn build_peers_json(pool: &AnyPool, now_ms: i64) -> Result<String, sqlx::Error> {
    use crate::peering::peer_registry::{peer_score, PeerRegistry};

    let registry = PeerRegistry::new(pool.clone());
    let records = registry
        .list_active(now_ms)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    const CONNECTED_WINDOW_MS: i64 = 300_000; // 5 minutes

    let peers: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            let connected = r.last_seen_ms > now_ms - CONNECTED_WINDOW_MS;
            let last_seen = chrono::DateTime::from_timestamp(r.last_seen_ms / 1000, 0)
                .map(|t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| r.last_seen_ms.to_string());
            serde_json::json!({
                "peer_id": r.peer_id,
                "address": r.address,
                "connected": connected,
                "last_seen": last_seen,
                "articles_received": r.articles_accepted,
                "articles_rejected": r.articles_rejected,
                "consecutive_failures": r.consecutive_failures,
                "health_score": peer_score(r),
                "configured": r.configured,
            })
        })
        .collect();

    Ok(serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string()))
}

/// Returns `true` if `ip` falls within any address range that must not be
/// reachable from the admin ping endpoint.
///
/// Blocked ranges:
/// - Loopback: 127.0.0.0/8, ::1
/// - Unspecified: 0.0.0.0, ::
/// - Link-local: 169.254.0.0/16, fe80::/10
/// - Private (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - Private (RFC 4193): fc00::/7
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()          // 127.0.0.0/8
            || v4.is_unspecified()    // 0.0.0.0
            || v4.is_link_local()     // 169.254.0.0/16
            || o[0] == 10             // 10.0.0.0/8
            || (o[0] == 172 && (o[1] & 0xf0) == 16)  // 172.16.0.0/12
            || (o[0] == 192 && o[1] == 168)           // 192.168.0.0/16
            || v4 == Ipv4Addr::BROADCAST // 255.255.255.255
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()          // ::1
            || v6.is_unspecified()    // ::
            // Link-local: fe80::/10
            || (s[0] & 0xffc0) == 0xfe80
            // Unique local: fc00::/7 (includes fd00::/8)
            || (s[0] & 0xfe00) == 0xfc00
            // IPv4-mapped: ::ffff:0:0/96 — check the embedded IPv4 address.
            || matches!(v6.to_ipv4_mapped(), Some(v4) if is_blocked_ip(IpAddr::V4(v4)))
        }
    }
}

/// Attempt a TCP connection to `address` and measure round-trip latency.
///
/// Returns `(reachable, latency_ms)`.  A 5-second timeout applies; on timeout
/// or connection refused, `reachable` is `false` and `latency_ms` is `None`.
///
/// Rejects addresses that resolve to loopback, link-local, private, or
/// unspecified ranges to prevent SSRF from the admin endpoint.
async fn ping_peer(address: &str) -> (bool, Option<u64>) {
    use std::net::ToSocketAddrs;
    use std::time::Instant;

    const PING_TIMEOUT: Duration = Duration::from_secs(5);

    // Resolve the address synchronously (DNS) before connecting.  We must
    // validate the resolved IPs rather than the raw string because a hostname
    // could resolve to a private address.
    //
    // `ToSocketAddrs` is blocking; run it on a blocking thread so we don't
    // stall the async runtime.
    let address_owned = address.to_string();
    let addrs = match tokio::task::spawn_blocking(move || {
        address_owned
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
    })
    .await
    {
        Ok(Ok(addrs)) => addrs,
        _ => return (false, None),
    };

    // All resolved addresses must pass the blocklist check.
    for socket_addr in &addrs {
        if is_blocked_ip(socket_addr.ip()) {
            tracing::warn!(
                address = %address,
                ip = %socket_addr.ip(),
                "admin /ping: blocked SSRF attempt to private/loopback address"
            );
            return (false, None);
        }
    }

    // Connect to the first resolved address (standard behavior).
    let start = Instant::now();
    match tokio::time::timeout(PING_TIMEOUT, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            (true, Some(latency_ms))
        }
        Ok(Err(_)) | Err(_) => (false, None),
    }
}

/// Build JSON for `GET /ipns`.
///
/// Returns the stable IPNS address for this node and the latest article CID
/// per group, alphabetically sorted.
///
/// Format:
/// ```json
/// {"ipns_path":"/ipns/<peer_id>","groups":{"comp.lang.rust":"<cid>",...}}
/// ```
///
/// `ipns_path` is `null` when IPNS is disabled.
pub(crate) async fn build_ipns_json(
    pool: &AnyPool,
    ipns_path: Option<&str>,
) -> Result<String, sqlx::Error> {
    // One row per group: the CID with the highest ingested_at_ms.
    // Correlated subquery is supported in SQLite and avoids a GROUP BY/JOIN.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT group_name, cid FROM articles \
         WHERE ingested_at_ms = (\
           SELECT MAX(ingested_at_ms) FROM articles a2 \
           WHERE a2.group_name = articles.group_name\
         ) \
         ORDER BY group_name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Build a JSON object (serde_json::Map preserves insertion order, which is
    // alphabetical here because the SQL result is ORDER BY group_name).
    let mut groups = serde_json::Map::new();
    for (group, cid) in rows {
        groups.insert(group, serde_json::Value::String(cid));
    }

    let obj = serde_json::json!({
        "ipns_path": ipns_path,
        "groups": groups,
    });
    Ok(obj.to_string())
}

pub(crate) fn build_version_json() -> String {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "binary": env!("CARGO_PKG_NAME"),
        "git_sha": env!("GIT_SHA"),
        "build_date": env!("BUILD_DATE"),
        "rust_version": env!("RUST_VERSION_STR"),
    })
    .to_string()
}

pub(crate) async fn build_groups_json(pool: &AnyPool) -> Result<String, sqlx::Error> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT group_name FROM articles ORDER BY group_name")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let groups: Vec<&str> = rows.iter().map(|(g,)| g.as_str()).collect();
    Ok(serde_json::to_string(&groups).unwrap_or_else(|_| "[]".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Returns `(transit_pool, core_pool)` — each backed by a distinct temp-file SQLite
    /// database with the appropriate schema migrations applied.
    async fn make_pools() -> (Arc<AnyPool>, Arc<AnyPool>) {
        let n = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let transit_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let _ = n; // silence unused warning; tempfile provides uniqueness
        let transit_url = format!("sqlite://{}", transit_tmp.to_str().unwrap());
        crate::migrations::run_migrations(&transit_url)
            .await
            .unwrap();
        let transit_pool = stoa_core::db_pool::try_open_any_pool(&transit_url, 1)
            .await
            .unwrap();

        let core_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let core_url = format!("sqlite://{}", core_tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&core_url)
            .await
            .unwrap();
        let core_pool = stoa_core::db_pool::try_open_any_pool(&core_url, 1)
            .await
            .unwrap();

        // Keep temp paths alive for test duration by leaking into a Box.
        std::mem::forget(transit_tmp);
        std::mem::forget(core_tmp);

        (Arc::new(transit_pool), Arc::new(core_pool))
    }

    /// Convenience wrapper: returns only the transit pool for tests that don't
    /// exercise `build_stats_json` and don't need the core pool.
    async fn make_pool() -> Arc<AnyPool> {
        make_pools().await.0
    }

    #[tokio::test]
    async fn liveness_handler_returns_ok_json() {
        let start_time = Instant::now();
        let json = build_liveness_json(start_time);
        assert!(json.contains("\"status\""), "missing status key: {json}");
        assert!(json.contains("\"ok\""), "missing ok value: {json}");
        assert!(
            json.contains("\"uptime_secs\""),
            "missing uptime_secs: {json}"
        );
    }

    #[tokio::test]
    async fn stats_handler_returns_zero_counts_on_empty_db() {
        let (pool, core_pool) = make_pools().await;
        let json = build_stats_json(&pool, &core_pool).await.unwrap();
        assert!(json.contains("\"articles\""), "missing articles: {json}");
        assert!(
            json.contains("\"pinned_cids\""),
            "missing pinned_cids: {json}"
        );
        assert!(json.contains("\"groups\""), "missing groups: {json}");
        assert!(json.contains("\"peers\""), "missing peers: {json}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["articles"], 0);
        assert_eq!(v["pinned_cids"], 0);
        assert_eq!(v["groups"], 0);
        assert_eq!(v["peers"], 0);
    }

    #[tokio::test]
    async fn log_tip_returns_none_for_missing_group() {
        let pool = make_pool().await;
        let result = build_log_tip_json(&pool, "comp.lang.rust").await;
        assert!(
            result.is_none(),
            "expected None for unknown group, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn peers_returns_empty_array_on_empty_db() {
        let pool = make_pool().await;
        let now_ms = 1700000000000i64;
        let json = build_peers_json(&pool, now_ms).await.unwrap();
        assert_eq!(json, "[]", "expected empty array: {json}");
    }

    #[tokio::test]
    async fn peers_returns_extended_fields_for_known_peer() {
        use crate::peering::peer_registry::{PeerRecord, PeerRegistry};

        let pool = make_pool().await;
        let now_ms = 1700000000000i64;

        // Insert a peer seen 60 seconds ago (within the 5-minute connected window).
        let registry = PeerRegistry::new((*pool).clone());
        registry
            .upsert(&PeerRecord {
                peer_id: "test-peer-id".to_string(),
                address: "192.0.2.1:119".to_string(),
                last_seen_ms: now_ms - 60_000,
                articles_accepted: 42,
                articles_rejected: 3,
                consecutive_failures: 0,
                blacklisted_until_ms: None,
                configured: true,
            })
            .await
            .unwrap();

        let json = build_peers_json(&pool, now_ms).await.unwrap();
        let arr: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1);
        let peer = &arr[0];
        assert_eq!(peer["peer_id"], "test-peer-id");
        assert_eq!(peer["address"], "192.0.2.1:119");
        assert_eq!(peer["connected"], true, "seen 60s ago should be connected");
        assert!(peer["last_seen"].is_string(), "last_seen must be a string");
        assert_eq!(peer["articles_received"], 42);
        assert_eq!(peer["articles_rejected"], 3);
        assert_eq!(peer["consecutive_failures"], 0);
        assert!(
            peer["health_score"].as_f64().is_some(),
            "health_score must be a float"
        );
        assert_eq!(peer["configured"], true);
    }

    #[tokio::test]
    async fn peers_connected_false_when_stale() {
        use crate::peering::peer_registry::{PeerRecord, PeerRegistry};

        let pool = make_pool().await;
        let now_ms = 1700000000000i64;

        // Insert a peer last seen 10 minutes ago (outside the 5-minute window).
        let registry = PeerRegistry::new((*pool).clone());
        registry
            .upsert(&PeerRecord {
                peer_id: "stale-peer".to_string(),
                address: "192.0.2.2:119".to_string(),
                last_seen_ms: now_ms - 600_000,
                articles_accepted: 0,
                articles_rejected: 0,
                consecutive_failures: 0,
                blacklisted_until_ms: None,
                configured: false,
            })
            .await
            .unwrap();

        let json = build_peers_json(&pool, now_ms).await.unwrap();
        let arr: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            arr[0]["connected"], false,
            "stale peer must not be connected"
        );
    }

    #[test]
    fn percent_decode_passthrough() {
        assert_eq!(percent_decode("192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn percent_decode_colon() {
        assert_eq!(percent_decode("192.0.2.1%3A119"), "192.0.2.1:119");
    }

    #[test]
    fn percent_decode_mixed() {
        assert_eq!(
            percent_decode("peer.example.com%3A119"),
            "peer.example.com:119"
        );
    }

    #[tokio::test]
    async fn liveness_uptime_is_non_negative() {
        let start_time = Instant::now();
        let json = build_liveness_json(start_time);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["uptime_secs"].as_u64().is_some(),
            "uptime_secs must be a non-negative integer"
        );
    }

    #[tokio::test]
    async fn readiness_ok_when_sqlite_up_and_no_kubo_url() {
        let (pool, core_pool) = make_pools().await;
        let (status, body) = build_readiness_json(&pool, &core_pool, None, Instant::now()).await;
        assert_eq!(status, 200, "status must be 200 when checks pass: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ok");
        let checks = v["checks"].as_array().expect("checks must be array");
        assert_eq!(checks.len(), 2, "two checks (sqlite_transit, sqlite_core)");
        for c in checks {
            assert_eq!(c["ok"], true, "check {:?} must be ok", c["name"]);
        }
    }

    #[tokio::test]
    async fn readiness_503_when_kubo_unreachable() {
        let (pool, core_pool) = make_pools().await;
        // Port 1 is closed/unreachable on loopback.
        let (status, body) = build_readiness_json(
            &pool,
            &core_pool,
            Some("http://127.0.0.1:1"),
            Instant::now(),
        )
        .await;
        assert_eq!(
            status, 503,
            "status must be 503 when Kubo unreachable: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "degraded");
        let checks = v["checks"].as_array().expect("checks must be array");
        let kubo = checks
            .iter()
            .find(|c| c["name"] == "kubo_reachable")
            .expect("kubo_reachable check must exist");
        assert_eq!(kubo["ok"], false, "kubo check must be false");
    }

    #[test]
    fn bearer_token_correct_returns_true() {
        assert!(check_bearer_token(
            Some("Bearer secret123"),
            Some("secret123")
        ));
    }

    #[test]
    fn bearer_token_wrong_returns_false() {
        assert!(!check_bearer_token(Some("Bearer wrong"), Some("secret123")));
    }

    #[test]
    fn bearer_token_missing_returns_false() {
        assert!(!check_bearer_token(None, Some("secret123")));
    }

    #[test]
    fn no_token_configured_always_passes() {
        assert!(check_bearer_token(None, None));
        assert!(check_bearer_token(Some("anything"), None));
    }

    // ── /pinning/remote endpoint tests ────────────────────────────────────────

    /// Empty table returns an empty array.
    #[tokio::test]
    async fn pinning_remote_empty_table_returns_empty_array() {
        let pool = make_pool().await;
        let json = build_pinning_remote_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array(), "expected JSON array, got: {json}");
        assert_eq!(
            v.as_array().unwrap().len(),
            0,
            "expected empty array: {json}"
        );
    }

    // ── /ipns endpoint tests ───────────────────────────────────────────────────

    /// Empty articles table returns correct JSON with null ipns_path and empty groups.
    #[tokio::test]
    async fn build_ipns_json_empty_db_no_path() {
        let pool = make_pool().await;
        let json = build_ipns_json(&pool, None).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["ipns_path"].is_null(),
            "ipns_path must be null when disabled: {json}"
        );
        assert!(v["groups"].is_object(), "groups must be object: {json}");
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            0,
            "groups must be empty: {json}"
        );
    }

    /// With an IPNS path and no articles, groups is empty but ipns_path is populated.
    #[tokio::test]
    async fn build_ipns_json_with_path_no_articles() {
        let pool = make_pool().await;
        let json = build_ipns_json(&pool, Some("/ipns/12D3KooW..."))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["ipns_path"], "/ipns/12D3KooW...",
            "ipns_path must match supplied value: {json}"
        );
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            0,
            "no articles → empty groups: {json}"
        );
    }

    /// Latest CID per group is returned; older articles are not included.
    #[tokio::test]
    async fn build_ipns_json_returns_latest_cid_per_group() {
        let pool = make_pool().await;

        // Insert two articles for comp.lang.rust: older then newer.
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms) \
             VALUES ('cid-old', 'comp.lang.rust', 1000), \
                    ('cid-new', 'comp.lang.rust', 2000)",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_ipns_json(&pool, Some("/ipns/abc")).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let groups = v["groups"].as_object().unwrap();
        assert_eq!(
            groups.get("comp.lang.rust").and_then(|v| v.as_str()),
            Some("cid-new"),
            "must return newest CID, not older: {json}"
        );
        assert_eq!(groups.len(), 1, "one group in output: {json}");
    }

    /// `build_version_json` returns an object with required string fields.
    #[test]
    fn version_json_has_required_fields() {
        let json = build_version_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["version"].is_string(), "version must be a string: {json}");
        assert!(v["binary"].is_string(), "binary must be a string: {json}");
        assert!(v["git_sha"].is_string(), "git_sha must be a string: {json}");
        assert!(
            v["build_date"].is_string(),
            "build_date must be a string: {json}"
        );
        assert!(
            v["rust_version"].is_string(),
            "rust_version must be a string: {json}"
        );
    }

    /// `build_groups_json` returns an empty array when the articles table is empty.
    #[tokio::test]
    async fn groups_returns_empty_array_on_empty_db() {
        let pool = make_pool().await;
        let json = build_groups_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array(), "expected JSON array: {json}");
        assert_eq!(
            v.as_array().unwrap().len(),
            0,
            "expected empty array: {json}"
        );
    }

    // ── percent_decode tests ───────────────────────────────────────────────────

    #[test]
    fn percent_decode_plain_string_unchanged() {
        assert_eq!(percent_decode("comp.lang.rust"), "comp.lang.rust");
    }

    #[test]
    fn percent_decode_space_encoded() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn percent_decode_slash_encoded() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
    }

    #[test]
    fn percent_decode_uppercase_hex() {
        assert_eq!(percent_decode("%2F"), "/");
    }

    #[test]
    fn percent_decode_invalid_sequence_passed_through() {
        // %GG is not valid hex — leave it as-is.
        assert_eq!(percent_decode("%GG"), "%GG");
    }

    #[test]
    fn percent_decode_truncated_sequence_passed_through() {
        // % at end of string — leave it as-is.
        assert_eq!(percent_decode("foo%"), "foo%");
    }

    #[test]
    fn extract_query_param_decodes_percent_encoding() {
        let query = "group=alt.test%2Bfoo&limit=10";
        assert_eq!(
            extract_query_param(query, "group").as_deref(),
            Some("alt.test+foo")
        );
    }

    /// Groups appear in alphabetical order in the JSON output.
    #[tokio::test]
    async fn build_ipns_json_groups_alphabetical() {
        let pool = make_pool().await;

        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms) \
             VALUES ('cid-z', 'sci.math', 1000), \
                    ('cid-a', 'alt.test', 1000), \
                    ('cid-c', 'comp.lang.rust', 1000)",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_ipns_json(&pool, None).await.unwrap();
        let alt_pos = json.find("alt.test").expect("alt.test must appear");
        let comp_pos = json
            .find("comp.lang.rust")
            .expect("comp.lang.rust must appear");
        let sci_pos = json.find("sci.math").expect("sci.math must appear");
        assert!(alt_pos < comp_pos, "alt.test must precede comp.lang.rust");
        assert!(comp_pos < sci_pos, "comp.lang.rust must precede sci.math");
    }

    /// Inserting jobs for two services returns one object per service with correct counts.
    #[tokio::test]
    async fn pinning_remote_counts_by_service_and_status() {
        let pool = make_pool().await;

        // Seed three rows for "pinata": 2 pending, 1 pinned.
        sqlx::query(
            "INSERT INTO remote_pin_jobs (cid, service_name, status) \
             VALUES ('Qm1', 'pinata', 'pending'), \
                    ('Qm2', 'pinata', 'pending'), \
                    ('Qm3', 'pinata', 'pinned')",
        )
        .execute(&*pool)
        .await
        .unwrap();

        // Seed one row for "web3": 1 queued.
        sqlx::query(
            "INSERT INTO remote_pin_jobs (cid, service_name, status) VALUES ('Qm4', 'web3', 'queued')",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_pinning_remote_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().expect("expected array");
        assert_eq!(arr.len(), 2, "expected 2 service entries: {json}");

        // BTreeMap ordering: "pinata" < "web3"
        let pinata = &arr[0];
        assert_eq!(pinata["service"], "pinata");
        assert_eq!(pinata["pending"], 2);
        assert_eq!(pinata["pinned"], 1);
        assert_eq!(pinata["queued"], 0);

        let web3 = &arr[1];
        assert_eq!(web3["service"], "web3");
        assert_eq!(web3["queued"], 1);
        assert_eq!(web3["pending"], 0);
    }

    /// `backup_databases` creates valid SQLite files that can be opened.
    #[tokio::test]
    async fn backup_creates_sqlite_files() {
        let (transit_pool, core_pool) = make_pools().await;
        let dest_dir = tempfile::TempDir::new().expect("tempdir");
        let dest_str = dest_dir.path().to_str().expect("utf8 path");

        let paths = backup_databases(&transit_pool, &core_pool, dest_str)
            .await
            .expect("backup must succeed");

        assert_eq!(paths.len(), 2, "must produce 2 backup files");

        for path in &paths {
            // Verify the file exists and is non-empty.
            let meta = std::fs::metadata(path)
                .unwrap_or_else(|e| panic!("backup file missing {path}: {e}"));
            assert!(meta.len() > 0, "backup file must be non-empty: {path}");

            // Verify the file is a valid SQLite database (header magic bytes).
            let header = std::fs::read(path)
                .unwrap_or_else(|e| panic!("cannot read backup file {path}: {e}"));
            assert_eq!(
                &header[..16],
                b"SQLite format 3\0",
                "backup file must have SQLite magic header: {path}"
            );
        }
    }

    /// `backup_databases` filenames include a UTC timestamp component.
    #[tokio::test]
    async fn backup_filenames_contain_timestamp() {
        let (transit_pool, core_pool) = make_pools().await;
        let dest_dir = tempfile::TempDir::new().expect("tempdir");
        let dest_str = dest_dir.path().to_str().expect("utf8 path");

        let paths = backup_databases(&transit_pool, &core_pool, dest_str)
            .await
            .expect("backup must succeed");

        // Both filenames must contain a UTC timestamp (e.g. "20260427T030000Z").
        for path in &paths {
            let filename = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path);
            assert!(
                filename.contains('T') && filename.ends_with("Z.db"),
                "backup filename must contain UTC timestamp: {filename}"
            );
        }
    }

    /// `backup_databases` rejects dest paths containing single quotes.
    #[tokio::test]
    async fn backup_rejects_path_with_single_quote() {
        let (transit_pool, core_pool) = make_pools().await;
        let result = backup_databases(&transit_pool, &core_pool, "/tmp/bad'path").await;
        assert!(result.is_err(), "single-quote path must be rejected");
    }
}
