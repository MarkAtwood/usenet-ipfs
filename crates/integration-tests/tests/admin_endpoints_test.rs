//! Integration tests for admin HTTP endpoints.
//!
//! Starts a reader admin server in-process and verifies that /health,
//! /version, /reload, and error cases all return the expected responses.
//! Uses raw TCP so the test has no dependency on stoa-ctl.

use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use std::sync::Arc;
use stoa_reader::admin::start_admin_server;

/// Send a raw GET request and return `(status_line, body)`.
async fn http_get(addr: &str, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    read_response(stream).await
}

/// Send a raw POST request with an empty body and return `(status_line, body)`.
async fn http_post(addr: &str, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    read_response(stream).await
}

async fn read_response(stream: TcpStream) -> (String, String) {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .expect("read status line");
    // Drain headers.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read header");
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }
    let mut body = String::new();
    reader.read_to_string(&mut body).await.expect("read body");
    (status_line.trim_end_matches(['\r', '\n']).to_string(), body)
}

/// Bind a free loopback port; drop the listener to release it, then return
/// the port number. There is a tiny TOCTOU window, but this is acceptable
/// for loopback-only tests.
fn free_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    listener.local_addr().expect("local_addr").port()
}

/// Send a raw GET request and return `(status_line, headers, body)`.
async fn http_get_with_headers(addr: &str, path: &str) -> (String, Vec<String>, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .expect("read status line");
    let mut headers: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read header");
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            break;
        }
        headers.push(trimmed);
    }
    let mut body = String::new();
    reader.read_to_string(&mut body).await.expect("read body");
    (
        status_line.trim_end_matches(['\r', '\n']).to_string(),
        headers,
        body,
    )
}

/// Assert the five security headers are present with correct values.
fn assert_security_headers(headers: &[String], context: &str) {
    let expected: &[(&str, &str)] = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("content-security-policy", "default-src 'none'"),
        (
            "permissions-policy",
            "geolocation=(), microphone=(), camera=()",
        ),
    ];
    for (name, value) in expected {
        let found = headers.iter().any(|h| {
            let lower = h.to_ascii_lowercase();
            lower.starts_with(name) && h.contains(value)
        });
        assert!(
            found,
            "{context}: missing header {name}: {value}\nGot: {headers:#?}"
        );
    }
}

// ── /health ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_health_returns_ok_json() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, body) = http_get(&format!("127.0.0.1:{port}"), "/health").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["status"], "ok", "expected status=ok: {body}");
    assert!(
        v["uptime_secs"].as_u64().is_some(),
        "uptime_secs must be a non-negative integer: {body}"
    );
}

// ── /version ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_version_returns_binary_and_version_fields() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, body) = http_get(&format!("127.0.0.1:{port}"), "/version").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(v["version"].is_string(), "version must be a string: {body}");
    assert!(v["binary"].is_string(), "binary must be a string: {body}");
}

// ── POST /reload ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_reload_post_returns_200_with_cert_check() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, body) = http_post(&format!("127.0.0.1:{port}"), "/reload").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["reloaded"], false, "reloaded must be false: {body}");
    assert!(
        v["tls_certs_checked"].as_u64().is_some(),
        "tls_certs_checked field must be present: {body}"
    );
}

#[tokio::test]
async fn admin_get_reload_returns_405() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, _body) = http_get(&format!("127.0.0.1:{port}"), "/reload").await;
    assert!(
        status.contains("405"),
        "GET /reload must return 405, got: {status}"
    );
}

// ── /metrics ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_metrics_returns_text_plain() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let request =
        format!("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.expect("read");
    assert!(
        status_line.contains("200"),
        "expected 200, got: {status_line}"
    );

    // Verify Content-Type header contains text/plain.
    let mut found_content_type = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read header");
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("content-type:") {
            assert!(
                line.contains("text/plain"),
                "metrics must be text/plain: {line}"
            );
            found_content_type = true;
        }
    }
    assert!(found_content_type, "response must have Content-Type header");
}

// ── 404 for unknown paths ─────────────────────────────────────────────────────

#[tokio::test]
async fn admin_unknown_path_returns_404() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, _body) = http_get(&format!("127.0.0.1:{port}"), "/nonexistent").await;
    assert!(
        status.contains("404"),
        "unknown path must return 404, got: {status}"
    );
}

// ── Security response headers ─────────────────────────────────────────────────

#[tokio::test]
async fn admin_health_has_security_headers() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, headers, _body) =
        http_get_with_headers(&format!("127.0.0.1:{port}"), "/health").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    assert_security_headers(&headers, "GET /health");
}

#[tokio::test]
async fn admin_version_has_security_headers() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, headers, _body) =
        http_get_with_headers(&format!("127.0.0.1:{port}"), "/version").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    assert_security_headers(&headers, "GET /version");
}

#[tokio::test]
async fn admin_metrics_has_security_headers() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, headers, _body) =
        http_get_with_headers(&format!("127.0.0.1:{port}"), "/metrics").await;
    assert!(status.contains("200"), "expected 200, got: {status}");
    assert_security_headers(&headers, "GET /metrics");
}

#[tokio::test]
async fn admin_hsts_absent_on_plain_http() {
    let port = free_loopback_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    start_admin_server(addr, Instant::now(), None, 60, Arc::new(vec![]))
        .expect("start admin server");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (_status, headers, _body) =
        http_get_with_headers(&format!("127.0.0.1:{port}"), "/health").await;
    let has_hsts = headers.iter().any(|h| {
        h.to_ascii_lowercase()
            .starts_with("strict-transport-security")
    });
    assert!(
        !has_hsts,
        "admin server must NOT emit HSTS on plain TCP; got: {headers:#?}"
    );
}
