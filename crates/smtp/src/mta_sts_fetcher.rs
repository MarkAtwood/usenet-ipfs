use std::time::Duration;

use crate::MtaStsError;

/// Fetch the MTA-STS policy file for `domain` from HTTPS.
///
/// URL: `https://mta-sts.<domain>/.well-known/mta-sts.txt`
///
/// # Security invariants (RFC 8461 §3.3)
///
/// - **No HTTP redirects** — `reqwest::redirect::Policy::none()` is mandatory.
///   Allowing redirects would let an attacker redirect the policy fetch to a
///   controlled server, defeating the HTTPS trust anchor.
/// - **WebPKI certificate required** — no custom CA; system roots only.
///   The HTTPS channel is what makes the policy trustworthy.
/// - **Response body capped** at `max_body_bytes` (RFC 8461 §3.2 recommends ≤64 KiB).
/// - **Connect+read timeout** applied via `timeout_ms`.
///
/// # SSRF note
///
/// Full SSRF mitigation (resolve hostname → check for RFC 1918 / loopback IPs
/// before connecting) would require a custom DNS resolver wired into the reqwest
/// connector.  This is disproportionate for this implementation.  Production
/// deployments MUST use network-level egress filtering to prevent access to
/// internal services.  The no-redirect and WebPKI invariants are still enforced.
pub async fn fetch_mta_sts_policy_body(
    client: &reqwest::Client,
    domain: &str,
    timeout_ms: u64,
    max_body_bytes: usize,
) -> Result<String, MtaStsError> {
    // Reject characters that are invalid in a bare hostname or that could
    // corrupt the constructed URL.  RFC 8461 §3.3 requires the domain to be a
    // valid DNS name; the additional chars below are URL meta-characters that
    // would allow SSRF if smuggled into https://mta-sts.<domain>/...
    if domain.is_empty()
        || domain.contains("://")
        || domain.contains(':')
        || domain.contains('/')
        || domain.contains('@')
        || domain.contains('#')
        || domain.contains('?')
        || domain.contains('[')
        || domain.contains(']')
    {
        return Err(MtaStsError::PolicyFetchFailed { message: "invalid domain".into() });
    }

    let url = format!(
        "https://mta-sts.{}/.well-known/mta-sts.txt",
        domain.trim_end_matches('.')
    );

    fetch_url(client, &url, timeout_ms, max_body_bytes).await
}

/// Inner HTTP fetch used by `fetch_mta_sts_policy_body`.
/// Separated so tests can call it with an `http://` URL pointing at a local
/// mock server without needing a real TLS certificate.
async fn fetch_url(
    client: &reqwest::Client,
    url: &str,
    timeout_ms: u64,
    max_body_bytes: usize,
) -> Result<String, MtaStsError> {
    let mut response = client
        .get(url)
        .timeout(Duration::from_millis(timeout_ms))
        .send()
        .await
        .map_err(|e| MtaStsError::PolicyFetchFailed { message: format!("request failed: {e}") })?;

    let status = response.status();
    if status.is_redirection() {
        return Err(MtaStsError::PolicyFetchRedirectForbidden);
    }
    if !status.is_success() {
        return Err(MtaStsError::PolicyFetchHttpError {
            status: status.as_u16(),
        });
    }

    // Read body in chunks, enforcing the size cap as each chunk arrives.
    // Using chunk() instead of bytes() prevents an adversarial server from
    // consuming unbounded memory before the limit check fires.
    let mut buf = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| MtaStsError::PolicyFetchFailed { message: format!("body read failed: {e}") })?;
        match chunk {
            None => break,
            Some(bytes) => {
                if buf.len() + bytes.len() > max_body_bytes {
                    return Err(MtaStsError::PolicyFetchTooLarge);
                }
                buf.extend_from_slice(&bytes);
            }
        }
    }

    let body = String::from_utf8(buf)
        .map_err(|_| MtaStsError::PolicyFetchFailed { message: "invalid UTF-8 in response".into() })?;

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client")
    }

    // T1: empty domain is rejected before making a network connection.
    // Oracle: RFC 8461 §3.3 — the domain MUST be a valid hostname; empty string
    // is not valid.
    #[tokio::test]
    async fn empty_domain_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "", 5_000, 65_536)
            .await
            .expect_err("empty domain must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T2: domain containing "://" is rejected (SSRF guard — prevents constructing
    // a URL like "https://mta-sts.https://evil.com/...").
    // Oracle: RFC 8461 §3.3 — domain must be a bare label, not a URL.
    #[tokio::test]
    async fn domain_with_scheme_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "https://evil.com", 5_000, 65_536)
            .await
            .expect_err("domain with scheme must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T3: domain containing "/" is rejected.
    // Oracle: RFC 8461 §3.3 — path separators are not valid in a domain label.
    #[tokio::test]
    async fn domain_with_path_separator_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "example.com/evil", 5_000, 65_536)
            .await
            .expect_err("domain with path separator must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T4 (domain guard): domain containing "@" is rejected.
    // Oracle: RFC 3986 treats "@" as the userinfo separator in the authority
    // component; "evil.com@target.com" would connect to target.com, not evil.com.
    #[tokio::test]
    async fn domain_with_at_sign_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "evil.com@target.com", 5_000, 65_536)
            .await
            .expect_err("domain with @ must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T4b: domain containing "#" is rejected.
    // Oracle: RFC 3986 treats "#" as the fragment delimiter; "example.com#evil"
    // would construct "https://mta-sts.example.com#evil/..." and the fragment
    // could be used to confuse proxies or caches.
    #[tokio::test]
    async fn domain_with_fragment_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "example.com#evil", 5_000, 65_536)
            .await
            .expect_err("domain with # must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T4c: domain containing "?" is rejected.
    // Oracle: RFC 3986 treats "?" as the query delimiter; could corrupt the URL.
    #[tokio::test]
    async fn domain_with_query_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "example.com?q=evil", 5_000, 65_536)
            .await
            .expect_err("domain with ? must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T4d: domain containing "[" is rejected.
    // Oracle: RFC 3986 §3.2.2 uses "[" and "]" to delimit IPv6 literals;
    // a domain containing "[" could be used to inject an IPv6 address.
    #[tokio::test]
    async fn domain_with_bracket_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "example.com[evil]", 5_000, 65_536)
            .await
            .expect_err("domain with [ must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // T4e: domain containing ":" is rejected.
    // Oracle: RFC 3986 §3.2.3 treats ":" as the port delimiter in the authority
    // component; "evil.com:8080" would construct
    // "https://mta-sts.evil.com:8080/.well-known/mta-sts.txt", connecting to a
    // non-standard HTTPS port which may bypass network-level MTA-STS filtering.
    // A valid DNS hostname label must not contain ":".
    #[tokio::test]
    async fn domain_with_port_rejected() {
        let err = fetch_mta_sts_policy_body(&test_client(), "evil.com:8080", 5_000, 65_536)
            .await
            .expect_err("domain with : must fail");
        assert!(matches!(err, MtaStsError::PolicyFetchFailed { .. }));
    }

    // ── Mock-server tests (T5–T9) ────────────────────────────────────────────
    //
    // These tests call `fetch_url` directly with an `http://` URL pointing at
    // a local axum server.  This avoids the need for a real TLS certificate
    // while still exercising every HTTP response-handling path.

    /// Spawn an axum router on a random loopback port and return the base URL.
    async fn start_mock_server(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    // T4: server returns 200 with a valid policy body → body is returned unchanged.
    // Oracle: RFC 8461 §3.3 — a 200 response with a valid UTF-8 body must be
    // returned as-is.
    #[tokio::test]
    async fn successful_fetch_returns_body() {
        use axum::response::IntoResponse;
        let body = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n";
        let body_str = body.to_string();
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let b = body_str.clone();
                async move { (axum::http::StatusCode::OK, b).into_response() }
            }),
        );
        let base = start_mock_server(router).await;
        let result = fetch_url(&test_client(), &format!("{base}/"), 5_000, 65_536)
            .await
            .expect("should succeed");
        assert_eq!(result, body);
    }

    // T5: server returns 301 redirect → PolicyFetchRedirectForbidden.
    // Oracle: RFC 8461 §3.3 — redirects MUST NOT be followed; an attacker could
    // redirect the policy fetch to a server they control.
    #[tokio::test]
    async fn redirect_returns_error() {
        use axum::response::IntoResponse;
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, "/other")],
                    "",
                )
                    .into_response()
            }),
        );
        let base = start_mock_server(router).await;
        let err = fetch_url(&test_client(), &format!("{base}/"), 5_000, 65_536)
            .await
            .expect_err("redirect must fail");
        assert!(
            matches!(err, MtaStsError::PolicyFetchRedirectForbidden),
            "unexpected error: {err}"
        );
    }

    // T6: server returns 200 with a body > max_body_bytes → PolicyFetchTooLarge.
    // Oracle: RFC 8461 §3.2 — policy body MUST NOT exceed the configured limit.
    #[tokio::test]
    async fn oversized_body_returns_error() {
        use axum::response::IntoResponse;
        let large = "x".repeat(65_537);
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let b = large.clone();
                async move { (axum::http::StatusCode::OK, b).into_response() }
            }),
        );
        let base = start_mock_server(router).await;
        let err = fetch_url(&test_client(), &format!("{base}/"), 5_000, 65_536)
            .await
            .expect_err("oversized body must fail");
        assert!(
            matches!(err, MtaStsError::PolicyFetchTooLarge),
            "unexpected error: {err}"
        );
    }

    // T7: server returns 404 → PolicyFetchHttpError { status: 404 }.
    // Oracle: RFC 8461 §3.3 — only 2xx is a valid policy response.
    #[tokio::test]
    async fn not_found_returns_error() {
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
        let base = start_mock_server(router).await;
        let err = fetch_url(&test_client(), &format!("{base}/"), 5_000, 65_536)
            .await
            .expect_err("404 must fail");
        assert!(
            matches!(err, MtaStsError::PolicyFetchHttpError { status: 404 }),
            "unexpected error: {err}"
        );
    }

    // T8: connection refused (no server) → PolicyFetchFailed("request failed").
    // Oracle: unreachable server must not hang; reqwest surfaces the error via
    // the connect timeout and wraps it as PolicyFetchFailed.
    #[tokio::test]
    async fn connection_refused_returns_error() {
        // Bind a listener just to get a free port, then drop it so the port
        // is closed before we try to connect.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);

        let err = fetch_url(
            &test_client(),
            &format!("http://127.0.0.1:{port}/"),
            5_000,
            65_536,
        )
        .await
        .expect_err("connection refused must fail");
        assert!(
            matches!(err, MtaStsError::PolicyFetchFailed { .. }),
            "unexpected error: {err}"
        );
    }
}
