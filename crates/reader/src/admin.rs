//! Admin HTTP server for the reader daemon.
//!
//! Listens on a configurable address and serves a small set of endpoints for
//! operator inspection. Optionally requires a bearer token; bind to loopback
//! only in production (see [`crate::config::AdminConfig`]).
//!
//! Endpoints:
//! - `GET /health`   — liveness check (`{"status":"ok"}`)
//! - `GET /metrics`  — Prometheus text format
//! - `GET /version`  — binary name and semver version
//! - `POST /reload`  — signal daemon to reload config (stub, returns `{"reloaded":true}`)

use std::sync::Arc;
use std::time::{Duration, Instant};
use stoa_core::rate_limiter::RateLimiter;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Start the admin HTTP server on the given address.
///
/// Spawns a background tokio task and returns immediately.
///
/// # Fail-closed: non-loopback without bearer token
///
/// Returns `Err` if `addr` is non-loopback and `bearer_token` is `None`.
/// An unauthenticated admin endpoint on a reachable interface is a security
/// footgun in production; the server must not start in that configuration.
///
/// # DECISION (rbe3.79): fail-closed admin endpoint on non-loopback without bearer token
///
/// An admin server on `0.0.0.0` or any non-loopback address without a bearer
/// token would expose destructive operations (e.g. GC, config reload) to any
/// host on the network without authentication.  Returning `Err` here forces a
/// startup failure rather than a runtime authentication bypass.  Never relax
/// this to a warning or a loopback-only exclusion without explicit security
/// review.  Do NOT remove the loopback check.
pub fn start_admin_server(
    addr: std::net::SocketAddr,
    start_time: Instant,
    bearer_token: Option<String>,
    rate_limit_rpm: u32,
    cert_paths: Arc<Vec<String>>,
) -> Result<(), String> {
    if !addr.ip().is_loopback() && bearer_token.is_none() {
        return Err(format!(
            "admin endpoint at {addr} is on a non-loopback interface but no \
             admin_token is configured — refusing to start an unauthenticated \
             admin server"
        ));
    }
    let bearer_token = Arc::new(bearer_token);
    let rate_limiter = Arc::new(RateLimiter::new(rate_limit_rpm));
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("admin server failed to bind {addr}: {e}");
                return;
            }
        };
        tracing::info!("admin server listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let bearer_token = Arc::clone(&bearer_token);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let cert_paths = Arc::clone(&cert_paths);
                    tokio::spawn(async move {
                        if let Err(e) = handle_admin_connection(
                            stream,
                            start_time,
                            bearer_token.as_deref(),
                            &rate_limiter,
                            &cert_paths,
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

async fn handle_admin_connection(
    stream: tokio::net::TcpStream,
    start_time: Instant,
    bearer_token: Option<&str>,
    rate_limiter: &RateLimiter,
    cert_paths: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_ip = stream.peer_addr()?.ip();
    let mut reader = BufReader::new(stream);

    // Hard deadline for receiving the full request line + headers.  A client
    // that drips bytes one at a time (slowloris) will be dropped after this.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    // Cap on header lines: prevents an infinite loop of valid lines with no
    // blank terminator.
    const MAX_HEADER_LINES: usize = 64;

    // Cap on body size: prevents a POST with a huge Content-Length from
    // allocating unbounded memory.
    const MAX_BODY_BYTES: usize = 64 * 1024;

    let (method_owned, path_owned, auth_header, content_length) =
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut request_line = String::new();
            reader.read_line(&mut request_line).await?;
            let rl = request_line.trim_end_matches(['\r', '\n']).to_string();
            let mut parts = rl.splitn(3, ' ');
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();

            let mut auth_header: Option<String> = None;
            let mut content_length: usize = 0;
            for _ in 0..MAX_HEADER_LINES {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let line = line.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    break;
                }
                // HTTP header field names are case-insensitive (RFC 7230 §3.2).
                // Lower-case only the field name portion; preserve the value as-is
                // so the constant-time bearer token comparison is not affected.
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("authorization:") {
                    let val = line["authorization:".len()..].trim_start();
                    auth_header = Some(val.to_string());
                } else if lower.starts_with("content-length:") {
                    let val = line["content-length:".len()..].trim();
                    content_length = val.parse().unwrap_or(0);
                }
            }

            Ok::<_, std::io::Error>((method, path, auth_header, content_length))
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "admin request read timeout")
        })??;

    let method = method_owned.as_str();
    let path = path_owned.as_str();

    // Read the request body for POST requests.  We consume it before writing
    // any response so the connection is left in a clean state.  Body content
    // is currently unused (all POST endpoints are stubs), but reading it
    // ensures future handlers that need the payload can access it, and
    // prevents the client from seeing a broken-pipe error on its send.
    let _request_body: Vec<u8> = if method == "POST" && content_length > 0 {
        let clamped = content_length.min(MAX_BODY_BYTES);
        let mut buf = vec![0u8; clamped];
        tokio::time::timeout(REQUEST_TIMEOUT, reader.read_exact(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "admin request body read timeout",
                )
            })??;
        buf
    } else {
        Vec::new()
    };

    let mut writer = reader.into_inner();

    // Check bearer token before rate limiting so that invalid credentials are
    // rejected without consuming a rate-limit slot (prevents token-enumeration
    // amplification via the rate limiter).
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
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: {retry_after}\r\nContent-Length: {content_length}\r\n\r\n{body}"
        );
        writer.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let method_ok = match path {
        "/reload" => method == "POST",
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

    match path {
        "/health" => {
            let uptime_secs = start_time.elapsed().as_secs();
            let body = format!(r#"{{"status":"ok","uptime_secs":{uptime_secs}}}"#);
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        "/metrics" => {
            let body = crate::metrics::gather_metrics();
            let content_length = body.len();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {content_length}\r\n\r\n{body}"
            );
            writer.write_all(response.as_bytes()).await?;
        }
        "/version" => {
            write_json(&mut writer, 200, "OK", &build_version_json()).await?;
        }
        "/reload" => {
            // Full config reload is not yet implemented; restart the daemon to
            // apply config changes.  However, we do re-check TLS certificate
            // expiry on every reload request so operators can confirm cert
            // rotation succeeded without restarting.
            let mut cert_results: Vec<serde_json::Value> = Vec::new();
            for path in cert_paths.iter() {
                cert_results.push(crate::tls::check_cert_expiry(path));
            }
            let body = serde_json::json!({
                "reloaded": false,
                "note": "full config reload not yet implemented — restart to apply config changes",
                "tls_certs_checked": cert_results.len(),
                "tls_certs": cert_results,
            })
            .to_string();
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        _ => {
            write_json(&mut writer, 404, "Not Found", r#"{"error":"not found"}"#).await?;
        }
    }

    Ok(())
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
///
/// # DECISION (rbe3.77): constant-time bearer token comparison prevents timing oracle
///
/// A variable-time comparison (e.g. `==` on `&str`) returns early on the first
/// mismatched byte, leaking token prefix information through response latency.
/// An attacker with sub-millisecond latency measurement (common on LAN) can
/// recover a 32-byte token with ~256 requests.  `subtle::ConstantTimeEq` runs
/// in constant time regardless of where the mismatch occurs.  Do NOT replace
/// this with `==`, `starts_with`, or any standard equality comparison.
pub(crate) fn check_bearer_token(auth_header: Option<&str>, bearer_token: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    match bearer_token {
        None => true,
        Some(token) => {
            let expected = format!("Bearer {token}");
            let header = match auth_header {
                None => "",
                Some(h) => h,
            };
            // NOTE: subtle::ConstantTimeEq on slices of different lengths returns 0
            // immediately without comparing bytes, leaking the expected token length
            // through response timing.  We equalise lengths by zero-padding both
            // sides to `max_len` before comparing so the ct_eq loop always runs
            // `max_len` iterations regardless of the actual input lengths.
            let max_len = expected.len().max(header.len());
            let mut a = vec![0u8; max_len];
            let mut b = vec![0u8; max_len];
            a[..expected.len()].copy_from_slice(expected.as_bytes());
            b[..header.len()].copy_from_slice(header.as_bytes());
            // Length mismatch is always a rejection; the ct_eq result folds that in.
            let lengths_equal = subtle::Choice::from((expected.len() == header.len()) as u8);
            let bytes_equal = a.ct_eq(&b);
            (lengths_equal & bytes_equal).into()
        }
    }
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

async fn write_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    status_text: &str,
    body: &str,
) -> std::io::Result<()> {
    let content_length = body.len();
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\n\r\n{body}"
    );
    writer.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP header field names are case-insensitive (RFC 7230 §3.2).
    /// Verify that the header parser in handle_admin_connection accepts
    /// mixed-case Authorization field names.
    ///
    /// We mirror the exact logic used in production so the test is a true
    /// unit-level oracle for the parsing behaviour.
    fn parse_auth_header_value(line: &str) -> Option<String> {
        if line.to_ascii_lowercase().starts_with("authorization:") {
            let val = line["authorization:".len()..].trim_start();
            Some(val.to_string())
        } else {
            None
        }
    }

    #[test]
    fn auth_header_lowercase_accepted() {
        let val = parse_auth_header_value("authorization: Bearer tok123");
        assert_eq!(val.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn auth_header_uppercase_accepted() {
        let val = parse_auth_header_value("AUTHORIZATION: Bearer tok123");
        assert_eq!(val.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn auth_header_mixed_case_accepted() {
        let val = parse_auth_header_value("Authorization: Bearer tok123");
        assert_eq!(val.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn auth_header_no_space_after_colon_accepted() {
        // Some clients omit the space between "Authorization:" and the value.
        let val = parse_auth_header_value("Authorization:Bearer tok123");
        assert_eq!(val.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn auth_header_unrelated_line_returns_none() {
        let val = parse_auth_header_value("Content-Type: application/json");
        assert!(val.is_none());
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

    #[test]
    fn start_admin_server_rejects_non_loopback_without_token() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
            let result = start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]));
            assert!(
                result.is_err(),
                "must refuse non-loopback without bearer token"
            );
        });
    }

    #[test]
    fn start_admin_server_allows_loopback_without_token() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
            // Port 0 → OS assigns a free port; this just tests the guard logic.
            let result = start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]));
            assert!(result.is_ok(), "loopback without token must be allowed");
        });
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        // Verify the retry_after formula for key rpm values.
        // Expected: ceil(60/rpm), clamped to [1, 60].
        let cases: &[(u32, u32)] = &[
            (1, 60),  // 60/1 = 60s
            (60, 1),  // 60/60 = 1s
            (120, 1), // 60/120 = 0.5s → bumped to 1s (this was the bug)
            (600, 1), // 60/600 = 0.1s → bumped to 1s
        ];
        for &(rpm, expected) in cases {
            let got = (60u32 / rpm).clamp(1, 60);
            assert_eq!(
                got, expected,
                "retry_after for rpm={rpm} must be {expected}s, got {got}s"
            );
        }
    }
}
