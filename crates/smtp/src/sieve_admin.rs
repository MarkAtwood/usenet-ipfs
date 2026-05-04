/// HTTP admin API for per-user Sieve script management.
///
/// ManageSieve (RFC 5804) requires TLS before PLAIN auth, which is out of scope
/// for v1.  This HTTP API provides the same functionality over loopback TCP,
/// with access control enforced by the bind address (default 127.0.0.1:4190).
///
/// # Endpoints
///
/// | Method | Path                                        | Description       |
/// |--------|---------------------------------------------|-------------------|
/// | GET    | /admin/sieve/{username}                     | List scripts      |
/// | GET    | /admin/sieve/{username}/{name}              | Get script bytes  |
/// | PUT    | /admin/sieve/{username}/{name}              | Upload script     |
/// | DELETE | /admin/sieve/{username}/{name}              | Delete script     |
/// | POST   | /admin/sieve/{username}/{name}/activate     | Set active script |
/// | POST   | /admin/sieve/check                          | Validate (no save)|
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use prometheus::{Encoder, TextEncoder};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tracing::info;

use stoa_core::util::is_loopback_addr;

use crate::config::{Config, MtaStsMode};
use crate::session::SieveCache;
use crate::store;

#[derive(Clone)]
struct AdminState {
    config: Arc<Config>,
    pool: SqlitePool,
    sieve_cache: SieveCache,
}

/// JSON payload for a single entry in the `GET /admin/sieve/{username}` response.
#[derive(serde::Serialize)]
struct ListScriptEntry {
    name: String,
    active: bool,
}

/// Validate a script name: must be non-empty, no path separators, no null bytes.
fn valid_script_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
}

/// Axum middleware that enforces the bearer token configured in
/// `sieve_admin.bearer_token`.
///
/// If no token is configured, all requests pass through (backward compatible).
/// If a token is configured, requests must include `Authorization: Bearer <token>`;
/// missing or incorrect tokens receive `401 Unauthorized`.
async fn require_bearer_token(
    State(s): State<AdminState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(expected) = &s.config.sieve_admin.bearer_token {
        use subtle::ConstantTimeEq as _;
        let auth = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let expected_header = format!("Bearer {expected}");
        let ok: bool = match auth {
            None => false,
            Some(header) => expected_header.as_bytes().ct_eq(header.as_bytes()).into(),
        };
        if !ok {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }
    next.run(request).await
}

/// Performs the fail-closed startup check and, if the configuration is safe,
/// spawns the Sieve admin HTTP server task.
///
/// Returns `Err` immediately when the endpoint is bound to a non-loopback
/// address without a bearer token and without `allow_non_loopback = true`.
/// The caller must treat this as a fatal startup error.
pub fn start_sieve_admin_server(
    config: Arc<Config>,
    pool: SqlitePool,
    sieve_cache: SieveCache,
) -> Result<(), String> {
    let bind = &config.sieve_admin.bind;
    let has_token = config.sieve_admin.bearer_token.is_some();
    if !is_loopback_addr(bind) && !config.sieve_admin.allow_non_loopback && !has_token {
        return Err(format!(
            "sieve admin endpoint at {bind} is on a non-loopback interface but no \
             bearer_token is configured — refusing to start an unauthenticated admin server"
        ));
    }
    tokio::spawn(run_admin_server(config, pool, sieve_cache));
    Ok(())
}

/// Inner async loop: bind and serve.  Called only after the fail-closed check
/// in `start_sieve_admin_server` has passed.
async fn run_admin_server(config: Arc<Config>, pool: SqlitePool, sieve_cache: SieveCache) {
    let bind = &config.sieve_admin.bind;

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => {
            info!(%bind, "Sieve admin API listening");
            l
        }
        Err(e) => {
            tracing::error!(%bind, "failed to bind Sieve admin API: {e}");
            return;
        }
    };

    let state = AdminState {
        config,
        pool,
        sieve_cache,
    };

    // /.well-known/mta-sts.txt is public — no bearer token required.
    // RFC 8461 §3.3: the policy must be reachable without authentication
    // so that sending MTAs can fetch it.  In production this endpoint MUST
    // be served over HTTPS; operators should terminate TLS at a reverse
    // proxy (nginx/Caddy) and forward plain HTTP to this listener.
    //
    // All /admin/* and /metrics routes are protected by the bearer-token
    // middleware.  This includes /metrics: even though metrics expose no
    // user data, they reveal internal counters that could aid targeted
    // attacks, and the admin API already requires a token for all other
    // endpoints.
    let protected = Router::new()
        .route("/admin/sieve/{username}", get(list_scripts))
        .route("/admin/sieve/{username}/{name}", get(get_script))
        .route("/admin/sieve/{username}/{name}", put(put_script))
        .route("/admin/sieve/{username}/{name}", delete(delete_script))
        .route(
            "/admin/sieve/{username}/{name}/activate",
            post(activate_script),
        )
        .route("/admin/sieve/check", post(check_script))
        .route("/metrics", get(get_metrics))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ));

    let app = Router::new()
        .route("/.well-known/mta-sts.txt", get(serve_mta_sts_policy))
        .merge(protected)
        .with_state(state);

    if let Err(e) = axum::serve(listener, app).await {
        // Log the error but do not panic — a panic in a spawned task is caught
        // by the tokio runtime and silently aborts only that task, so the
        // operator would have no indication the admin API has stopped.
        tracing::error!("Sieve admin server stopped with error: {e}");
    }
}

/// GET /admin/sieve/{username}
/// Returns a JSON array of `{"name": "...", "active": true|false}` objects.
async fn list_scripts(State(s): State<AdminState>, Path(username): Path<String>) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    let username = normalize_username(&username);
    match store::list_scripts(&s.pool, username).await {
        Ok(scripts) => {
            let entries: Vec<ListScriptEntry> = scripts
                .into_iter()
                .map(|(name, active)| ListScriptEntry { name, active })
                .collect();
            (StatusCode::OK, Json(entries)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /admin/sieve/{username}/{name}
/// Returns the raw Sieve script bytes (text/plain).
async fn get_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    let username = normalize_username(&username);
    match store::get_script(&s.pool, username, &name).await {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [("Content-Type", "text/plain; charset=utf-8")],
            bytes,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// PUT /admin/sieve/{username}/{name}
/// Body: raw Sieve script bytes.
/// Returns 201 on success, 413 if too large, 422 if script fails to parse.
async fn put_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    if body.len() as u64 > s.config.sieve_admin.max_script_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "script exceeds size limit").into_response();
    }
    if let Err(e) = stoa_sieve_native::compile(&body) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Sieve parse error: {e}"),
        )
            .into_response();
    }
    let username = normalize_username(&username);
    match store::save_script(&s.pool, username, &name, &body, false).await {
        Ok(()) => {
            s.sieve_cache.lock().await.remove(username);
            (StatusCode::CREATED, "").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// DELETE /admin/sieve/{username}/{name}
async fn delete_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    let username = normalize_username(&username);
    match store::delete_script(&s.pool, username, &name).await {
        Ok(true) => {
            s.sieve_cache.lock().await.remove(username);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /admin/sieve/{username}/{name}/activate
async fn activate_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    let username = normalize_username(&username);
    match store::set_active(&s.pool, username, &name).await {
        Ok(true) => {
            s.sieve_cache.lock().await.remove(username);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /admin/sieve/check
/// Validates the body as a Sieve script without storing it.
/// Returns 200 on success, 422 with error text on failure.
async fn check_script(State(s): State<AdminState>, body: Bytes) -> Response {
    if body.len() as u64 > s.config.sieve_admin.max_script_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "script exceeds size limit").into_response();
    }
    match stoa_sieve_native::compile(&body) {
        Ok(_) => (StatusCode::OK, "OK").into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Sieve parse error: {e}"),
        )
            .into_response(),
    }
}

/// GET /metrics
///
/// Returns all registered Prometheus metrics in the standard text exposition
/// format (Content-Type: text/plain; version=0.0.4).  This route is protected
/// by the bearer-token middleware (same as all other admin endpoints) when a
/// token is configured; unauthenticated when no token is set.
async fn get_metrics() -> Response {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encode error: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [("Content-Type", encoder.format_type())],
        buf,
    )
        .into_response()
}

/// GET /.well-known/mta-sts.txt
///
/// Serves the MTA-STS policy file (RFC 8461 §3.2) for the domain named in
/// the `Host:` request header.  The fetching MTA sets `Host: mta-sts.<domain>`
/// per RFC 8461 §3.3; we strip the `mta-sts.` prefix and look up the domain
/// in `config.mta_sts.hosted_domains`.
///
/// Returns 200 with `Content-Type: text/plain` on success, 404 if the domain
/// is not in the hosted list.
///
/// **Production note:** this endpoint MUST be served over HTTPS.  Run a
/// reverse proxy (nginx / Caddy) that terminates TLS and forwards plain HTTP
/// to this listener.  The admin server itself does not handle TLS.
async fn serve_mta_sts_policy(
    State(s): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Strip port suffix if present (e.g. "mta-sts.example.com:443").
    let host_no_port = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);

    // RFC 8461 §3.3: the policy URL is https://mta-sts.<domain>/.well-known/mta-sts.txt
    let domain = match host_no_port.strip_prefix("mta-sts.") {
        Some(d) if !d.is_empty() => d,
        _ => return (StatusCode::NOT_FOUND, "unknown domain").into_response(),
    };

    let cfg = s
        .config
        .mta_sts
        .hosted_domains
        .iter()
        .find(|d| d.domain.eq_ignore_ascii_case(domain));

    let cfg = match cfg {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, "unknown domain").into_response(),
    };

    let mode_str = match cfg.mode {
        MtaStsMode::None => "none",
        MtaStsMode::Testing => "testing",
        MtaStsMode::Enforce => "enforce",
    };

    // RFC 8461 §3.2 policy file format: version first, then mode, then zero
    // or more mx lines, then max_age.
    let mut body = format!("version: STSv1\r\nmode: {mode_str}\r\n");
    for mx in &cfg.mx_patterns {
        body.push_str(&format!("mx: {mx}\r\n"));
    }
    body.push_str(&format!("max_age: {}\r\n", cfg.max_age_secs));

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Returns `true` if `username` names a valid Sieve script namespace.
///
/// This server uses a single-user global delivery model: the only valid
/// namespace for Sieve script management is `_global`
/// (`crate::config::GLOBAL_SCRIPT_KEY`). Any other identifier is rejected
/// with 404. The function is named `user_exists` to mirror conventional
/// multi-user Sieve admin APIs, where each user has their own script namespace;
/// here the sole "user" is the global script key.
fn user_exists(s: &AdminState, username: &str) -> bool {
    if username.eq_ignore_ascii_case(crate::config::GLOBAL_SCRIPT_KEY) {
        return true;
    }
    s.config.auth.users.iter().any(|u| u.username == username)
}

/// Return the canonical store key for `username`.
///
/// The global script key is accepted case-insensitively (e.g. `_GLOBAL`,
/// `_Global`) but must be stored under the single canonical value
/// `GLOBAL_SCRIPT_KEY` so that `load_active_script` can find it.
fn normalize_username(username: &str) -> &str {
    if username.eq_ignore_ascii_case(crate::config::GLOBAL_SCRIPT_KEY) {
        crate::config::GLOBAL_SCRIPT_KEY
    } else {
        username
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt as _;

    use crate::config::{
        AuthConfig, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, TlsConfig,
    };

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".into(),
                port_587: "127.0.0.1:0".into(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
        })
    }

    async fn app_with_global() -> (Router, SqlitePool) {
        let (app, pool, _cache) = app_with_global_and_cache().await;
        (app, pool)
    }

    async fn app_with_global_and_cache() -> (Router, SqlitePool, crate::session::SieveCache) {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let config = test_config();
        let cache = crate::session::new_sieve_cache();
        let state = AdminState {
            config,
            pool: pool.clone(),
            sieve_cache: cache.clone(),
        };
        let app = Router::new()
            .route("/admin/sieve/{username}", get(list_scripts))
            .route("/admin/sieve/{username}/{name}", get(get_script))
            .route("/admin/sieve/{username}/{name}", put(put_script))
            .route("/admin/sieve/{username}/{name}", delete(delete_script))
            .route(
                "/admin/sieve/{username}/{name}/activate",
                post(activate_script),
            )
            .route("/admin/sieve/check", post(check_script))
            .with_state(state);
        (app, pool, cache)
    }

    async fn response_body(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn putscript_valid_stores_and_returns_201() {
        let (app, pool) = app_with_global().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/_global/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let stored = store::get_script(&pool, crate::config::GLOBAL_SCRIPT_KEY, "default")
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some(b"keep;" as &[u8]));
    }

    #[tokio::test]
    async fn putscript_invalid_sieve_returns_422() {
        let (app, _) = app_with_global().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/_global/default")
            .body(Body::from("this is not valid sieve @@@@"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn putscript_too_large_returns_413() {
        let (app, _) = app_with_global().await;
        let big = vec![b'#'; 65_537]; // one byte over 64 KiB default
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/_global/default")
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The global script key crate::config::GLOBAL_SCRIPT_KEY must be accepted case-insensitively.
    #[tokio::test]
    async fn listscripts_global_key_is_case_insensitive() {
        let (app, _) = app_with_global().await;
        for uri in &[
            "/admin/sieve/_global",
            "/admin/sieve/_GLOBAL",
            "/admin/sieve/_Global",
        ] {
            let req = Request::builder()
                .method(Method::GET)
                .uri(*uri)
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "expected 200 for {uri}; got {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn putscript_unknown_user_returns_404() {
        let (app, _) = app_with_global().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/unknown/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn getscript_returns_stored_bytes() {
        let (app, pool) = app_with_global().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "work",
            b"discard;",
            false,
        )
        .await
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global/work")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert_eq!(body, "discard;");
    }

    #[tokio::test]
    async fn getscript_missing_returns_404() {
        let (app, _) = app_with_global().await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn listscripts_returns_names_and_active_flag() {
        let (app, pool) = app_with_global().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "a",
            b"keep;",
            false,
        )
        .await
        .unwrap();
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "b",
            b"discard;",
            true,
        )
        .await
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(body.contains("\"a\""), "expected script a in list: {body}");
        assert!(body.contains("\"b\""), "expected script b in list: {body}");
    }

    #[tokio::test]
    async fn deletescript_removes_row() {
        let (app, pool) = app_with_global().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "tmp",
            b"keep;",
            false,
        )
        .await
        .unwrap();

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/_global/tmp")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let remaining = store::get_script(&pool, crate::config::GLOBAL_SCRIPT_KEY, "tmp")
            .await
            .unwrap();
        assert!(remaining.is_none(), "expected script to be deleted");
    }

    #[tokio::test]
    async fn deletescript_missing_returns_404() {
        let (app, _) = app_with_global().await;
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/_global/ghost")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn setactive_switches_active_script() {
        let (app, pool) = app_with_global().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "first",
            b"keep;",
            true,
        )
        .await
        .unwrap();
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "second",
            b"discard;",
            false,
        )
        .await
        .unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/_global/second/activate")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let scripts = store::list_scripts(&pool, crate::config::GLOBAL_SCRIPT_KEY)
            .await
            .unwrap();
        let first_active = scripts.iter().find(|(n, _)| n == "first").map(|(_, a)| *a);
        let second_active = scripts.iter().find(|(n, _)| n == "second").map(|(_, a)| *a);
        assert_eq!(first_active, Some(false), "first should be deactivated");
        assert_eq!(second_active, Some(true), "second should be active");
    }

    #[tokio::test]
    async fn checkscript_valid_returns_200_no_storage() {
        let (app, pool) = app_with_global().await;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/check")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Nothing should be stored.
        let scripts = store::list_scripts(&pool, crate::config::GLOBAL_SCRIPT_KEY)
            .await
            .unwrap();
        assert!(scripts.is_empty(), "check must not store anything");
    }

    #[tokio::test]
    async fn checkscript_invalid_returns_422() {
        let (app, _) = app_with_global().await;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/check")
            .body(Body::from("bogus @@ !! script"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    fn test_config_with_token(token: &str) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".into(),
                port_587: "127.0.0.1:0".into(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig {
                bearer_token: Some(token.to_string()),
                ..Default::default()
            },
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
        })
    }

    async fn app_with_token(token: &str) -> Router {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let config = test_config_with_token(token);
        let cache = crate::session::new_sieve_cache();
        let state = AdminState {
            config,
            pool,
            sieve_cache: cache,
        };
        Router::new()
            .route("/admin/sieve/{username}", get(list_scripts))
            .route("/admin/sieve/{username}/{name}", get(get_script))
            .route("/admin/sieve/{username}/{name}", put(put_script))
            .route("/admin/sieve/{username}/{name}", delete(delete_script))
            .route(
                "/admin/sieve/{username}/{name}/activate",
                post(activate_script),
            )
            .route("/admin/sieve/check", post(check_script))
            .route("/metrics", get(get_metrics))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer_token,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn bearer_token_missing_returns_401() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_wrong_returns_401() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global")
            .header("Authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_correct_allows_request() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/_global")
            .header("Authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Cache invalidation tests ──────────────────────────────────────────

    #[tokio::test]
    async fn put_script_invalidates_cache_entry() {
        let (app, _pool, cache) = app_with_global_and_cache().await;

        // Pre-populate the cache with a stale entry.
        cache.lock().await.insert(
            crate::config::GLOBAL_SCRIPT_KEY.to_string(),
            std::sync::Arc::new(stoa_sieve_native::compile(b"discard;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/_global/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(
            !cache
                .lock()
                .await
                .contains_key(crate::config::GLOBAL_SCRIPT_KEY),
            "cache entry must be removed after PUT"
        );
    }

    #[tokio::test]
    async fn delete_script_invalidates_cache_entry() {
        let (app, pool, cache) = app_with_global_and_cache().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "tmp",
            b"keep;",
            true,
        )
        .await
        .unwrap();

        cache.lock().await.insert(
            crate::config::GLOBAL_SCRIPT_KEY.to_string(),
            std::sync::Arc::new(stoa_sieve_native::compile(b"keep;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/_global/tmp")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !cache
                .lock()
                .await
                .contains_key(crate::config::GLOBAL_SCRIPT_KEY),
            "cache entry must be removed after DELETE"
        );
    }

    #[tokio::test]
    async fn activate_script_invalidates_cache_entry() {
        let (app, pool, cache) = app_with_global_and_cache().await;
        store::save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "s",
            b"discard;",
            false,
        )
        .await
        .unwrap();

        cache.lock().await.insert(
            crate::config::GLOBAL_SCRIPT_KEY.to_string(),
            std::sync::Arc::new(stoa_sieve_native::compile(b"discard;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/_global/s/activate")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !cache
                .lock()
                .await
                .contains_key(crate::config::GLOBAL_SCRIPT_KEY),
            "cache entry must be removed after activate"
        );
    }

    // ── Fail-closed startup check ─────────────────────────────────────────

    fn fail_closed_config(
        bind: &str,
        bearer_token: Option<&str>,
        allow_non_loopback: bool,
    ) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".into(),
                port_587: "127.0.0.1:0".into(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig {
                bind: bind.to_string(),
                allow_non_loopback,
                bearer_token: bearer_token.map(str::to_string),
                max_script_bytes: 65_536,
            },
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
        })
    }

    #[tokio::test]
    async fn start_non_loopback_no_token_returns_err() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:4190", None, false);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(
            result.is_err(),
            "expected Err for non-loopback without token"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("non-loopback"),
            "error message should mention non-loopback: {msg}"
        );
    }

    #[tokio::test]
    async fn start_non_loopback_with_token_returns_ok() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:0", Some("secret"), false);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(
            result.is_ok(),
            "expected Ok for non-loopback with token: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn start_non_loopback_allow_override_returns_ok() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:0", None, true);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(
            result.is_ok(),
            "expected Ok when allow_non_loopback=true: {:?}",
            result.err()
        );
    }

    // ── /metrics route ────────────────────────────────────────────────────

    #[tokio::test]
    async fn metrics_endpoint_returns_200_with_text_content_type() {
        // Force LazyLock initialization so at least some metrics are registered.
        crate::metrics::SMTP_CONNECTIONS_TOTAL.inc();

        let app = Router::new().route("/metrics", get(get_metrics));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/plain"),
            "expected text/plain Content-Type, got: {ct}"
        );
        let body = response_body(resp).await;
        assert!(
            body.contains("smtp_connections_total"),
            "expected smtp_connections_total in metrics output:\n{body}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_requires_auth_when_bearer_token_configured() {
        // /metrics is protected by the bearer-token middleware when a token is set.
        let app = app_with_token("secret").await;

        // Without Authorization header: expect 401.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "/metrics must return 401 without Authorization header when token configured"
        );

        // With correct token: expect 200.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .header("Authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/metrics must return 200 with correct Authorization header"
        );
    }

    // ── MTA-STS policy endpoint tests ────────────────────────────────────────

    async fn mta_sts_app(hosted_domains: Vec<crate::config::MtaStsDomainConfig>) -> Router {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let config = Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".into(),
                port_587: "127.0.0.1:0".into(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: crate::config::MtaStsConfig {
                enabled: true,
                hosted_domains,
                ..Default::default()
            },
        });
        let cache = crate::session::new_sieve_cache();
        let state = AdminState {
            config,
            pool,
            sieve_cache: cache,
        };
        Router::new()
            .route("/.well-known/mta-sts.txt", get(serve_mta_sts_policy))
            .with_state(state)
    }

    // T1: enforce mode with two MX patterns → 200, correct RFC 8461 body.
    // Oracle: RFC 8461 §3.2 policy file format.
    #[tokio::test]
    async fn mta_sts_enforce_returns_policy() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec![
                "mail.example.com".to_string(),
                "*.mx.example.com".to_string(),
            ],
            max_age_secs: 86400,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "mta-sts.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(body.starts_with("version: STSv1\r\n"), "body: {body}");
        assert!(body.contains("mode: enforce\r\n"), "body: {body}");
        assert!(body.contains("mx: mail.example.com\r\n"), "body: {body}");
        assert!(body.contains("mx: *.mx.example.com\r\n"), "body: {body}");
        assert!(body.contains("max_age: 86400\r\n"), "body: {body}");
    }

    // T2: mode=none with no mx patterns → 200, no mx lines in body.
    // Oracle: RFC 8461 §3.2 — mx is not required for mode=none.
    #[tokio::test]
    async fn mta_sts_none_mode_no_mx() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "example.net".to_string(),
            mode: MtaStsMode::None,
            mx_patterns: vec![],
            max_age_secs: 0,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "mta-sts.example.net")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(body.contains("mode: none\r\n"), "body: {body}");
        assert!(
            !body.contains("mx:"),
            "mode=none must not include mx lines: {body}"
        );
    }

    // T3: domain not in hosted_domains → 404.
    // Oracle: a non-hosted domain must not leak a policy.
    #[tokio::test]
    async fn mta_sts_unknown_domain_returns_404() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "mta-sts.other.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // T4: Host header without mta-sts. prefix → 404.
    // Oracle: RFC 8461 §3.3 — Host must be "mta-sts.<domain>".
    #[tokio::test]
    async fn mta_sts_wrong_host_prefix_returns_404() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // T5: Host header includes port → domain still matched correctly.
    // Oracle: RFC 7230 §5.4 — Host may include port; port must be stripped.
    #[tokio::test]
    async fn mta_sts_host_with_port_matched() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Testing,
            mx_patterns: vec!["mx.example.com".to_string()],
            max_age_secs: 3600,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "mta-sts.example.com:443")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(body.contains("mode: testing\r\n"), "body: {body}");
    }

    // T6: domain matching is case-insensitive (RFC 1034 §3.1).
    #[tokio::test]
    async fn mta_sts_domain_case_insensitive() {
        let app = mta_sts_app(vec![crate::config::MtaStsDomainConfig {
            domain: "Example.COM".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        }])
        .await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/mta-sts.txt")
            .header("Host", "mta-sts.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
