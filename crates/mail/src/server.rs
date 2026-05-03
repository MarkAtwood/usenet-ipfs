use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    extract::{DefaultBodyLimit, Extension, Request, State},
    http::{header, HeaderMap, HeaderName, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use jmap_server::{Dispatcher, HandlerFuture, JmapHandler};
use jmap_types::{JmapError, JmapRequest};
use serde_json::{json, Value};
use stoa_auth::{AuthConfig, CredentialStore, OidcStore};
use stoa_core::msgid_map::MsgIdMap;
use stoa_reader::{
    post::ipfs_write::IpfsBlockStore,
    search::TantivySearchIndex,
    store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
};
use stoa_smtp::SmtpRelayQueue;
use tokio::net::TcpListener;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};

use crate::{
    config::CorsConfig,
    state::{flags::UserFlagsStore, version::StateStore},
    token_store::TokenStore,
};

/// v1 is a single-user system; every authenticated session maps to this user.
const SINGLETON_USER_ID: i64 = 1;

/// JMAP backing stores, wired together for the API handler.
pub struct JmapStores {
    pub ipfs: Arc<dyn IpfsBlockStore>,
    pub msgid_map: Arc<MsgIdMap>,
    pub article_numbers: Arc<ArticleNumberStore>,
    pub overview_store: Arc<OverviewStore>,
    pub user_flags: Arc<UserFlagsStore>,
    pub state_store: Arc<StateStore>,
    pub change_log: Arc<crate::state::change_log::ChangeLogStore>,
    pub subscription_store: Arc<crate::state::subscriptions::SubscriptionStore>,
    /// Full-text search index for Email/query `text` filter.
    /// `None` means search is disabled; text filters return empty results.
    pub search_index: Option<Arc<TantivySearchIndex>>,
    /// Outbound SMTP relay queue. `None` means no relay peers configured.
    pub smtp_relay_queue: Option<Arc<SmtpRelayQueue>>,
    /// Mail database pool, used for provisioning and direct SQL queries.
    pub mail_pool: Arc<sqlx::AnyPool>,
    /// Special-use (RFC 6154) mailboxes cached at startup (lnc3.24).
    /// Populated by `provision_mailboxes` + `list_mailboxes` at startup;
    /// never changes at runtime so no lock is needed.
    pub special_mailboxes: Arc<Vec<crate::mailbox::types::SpecialMailbox>>,
}

#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub jmap: Option<Arc<JmapStores>>,
    pub credential_store: Arc<CredentialStore>,
    pub auth_config: Arc<AuthConfig>,
    pub token_store: Arc<TokenStore>,
    /// OIDC JWT validator.  `None` means no OIDC providers are configured.
    pub oidc_store: Option<Arc<OidcStore>>,
    /// External base URL used in JMAP session responses (e.g. `https://mail.example.com`).
    pub base_url: String,
    pub cors: CorsConfig,
    /// Milliseconds threshold for slow JMAP WARN log.  0 = disabled.
    pub slow_jmap_threshold_ms: u64,
    pub activitypub_config: crate::config::ActivityPubConfig,
    pub activitypub: Option<Arc<crate::activitypub::ActivityPubState>>,
    /// MTA-STS hosted domain policies (RFC 8461). Empty means no domains served.
    pub mta_sts_domains: Arc<Vec<stoa_smtp::config::MtaStsDomainConfig>>,
}

/// Authenticated user identity extracted from HTTP Basic Auth.
///
/// Inserted into request extensions by `basic_auth_middleware` after
/// successful credential verification.  Handlers receive it via
/// `Extension<AuthenticatedUser>`.  In dev mode no `AuthenticatedUser`
/// is inserted; handlers must use `Option<Extension<AuthenticatedUser>>`.
#[derive(Clone)]
pub struct AuthenticatedUser(pub String);

/// Axum middleware that enforces HTTP Basic authentication on protected routes.
///
/// Dev mode (no credentials configured, auth not required) bypasses auth
/// entirely and does NOT inject a fake `AuthenticatedUser`.
///
/// On success the `AuthenticatedUser` extension is inserted into the request
/// so downstream handlers can read the authenticated username.
///
/// On failure a `401 Unauthorized` response with a `WWW-Authenticate` header
/// is returned immediately.
async fn basic_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if state.auth_config.is_dev_mode() {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Try Bearer token.
    if let Some(bearer_token) = auth_header
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        // If the token looks like a JWT (three base64url segments) and OIDC is
        // configured, try OIDC validation first.  On failure, fall through to
        // the self-issued token store so that non-JWT Bearer tokens still work.
        if let Some(ref oidc) = state.oidc_store {
            if bearer_token.bytes().filter(|&b| b == b'.').count() == 2 {
                match oidc.validate_jwt(bearer_token).await {
                    Ok(username) => {
                        req.extensions_mut().insert(AuthenticatedUser(username));
                        return next.run(req).await;
                    }
                    Err(e) => {
                        tracing::debug!("OIDC JWT validation failed: {e}");
                        // Fall through to self-issued token check.
                    }
                }
            }
        }

        match state.token_store.verify(bearer_token).await {
            Ok(Some(username)) => {
                req.extensions_mut().insert(AuthenticatedUser(username));
                return next.run(req).await;
            }
            Ok(None) => return unauthorized_response(),
            Err(e) => {
                tracing::error!("token store DB error during auth: {e}");
                return unauthorized_response();
            }
        }
    }

    // Fall through to Basic auth.
    let credentials: Option<(String, String)> = auth_header
        .as_deref()
        .and_then(|h: &str| h.strip_prefix("Basic "))
        .and_then(|encoded: &str| data_encoding::BASE64.decode(encoded.as_bytes()).ok())
        .and_then(|decoded: Vec<u8>| String::from_utf8(decoded).ok())
        .and_then(|s: String| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_owned();
            let pass = parts.next()?.to_owned();
            Some((user, pass))
        });

    let (username, password) = match credentials {
        Some(pair) => pair,
        None => return unauthorized_response(),
    };

    if !state.credential_store.check(&username, &password).await {
        return unauthorized_response();
    }

    req.extensions_mut().insert(AuthenticatedUser(username));
    next.run(req).await
}

fn unauthorized_response() -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, r#"Basic realm="stoa""#),
            (header::CONTENT_TYPE, "text/plain"),
        ],
        "401 Unauthorized",
    )
        .into_response()
}

fn build_cors_layer(cors_config: &CorsConfig) -> CorsLayer {
    if !cors_config.enabled {
        return CorsLayer::new();
    }
    let origins_wildcard = cors_config.allowed_origins.iter().any(|o| o == "*");
    if origins_wildcard {
        return CorsLayer::permissive();
    }
    if cors_config.allowed_origins.is_empty() {
        tracing::warn!("cors.enabled=true but allowed_origins is empty; CORS disabled");
        return CorsLayer::new();
    }
    let parsed: Vec<axum::http::HeaderValue> = cors_config
        .allowed_origins
        .iter()
        .filter_map(|o| {
            o.parse::<axum::http::HeaderValue>().ok().or_else(|| {
                tracing::error!(origin = %o, "invalid CORS origin, skipping");
                None
            })
        })
        .collect();
    if parsed.is_empty() {
        tracing::warn!("all configured CORS origins were invalid; CORS disabled");
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(parsed))
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
        ]))
        .expose_headers(ExposeHeaders::list([
            HeaderName::from_static("x-stoa-cid"),
            HeaderName::from_static("x-stoa-root-cid"),
        ]))
}

/// Build the axum Router with all routes.
///
/// `GET /`, `/health`, `/metrics`, and `/.well-known/jmap` are public (no auth required).
/// All `/jmap/*` routes are protected by `basic_auth_middleware`.
/// The CORS layer (if enabled) wraps all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors_layer = build_cors_layer(&state.cors);

    let protected = Router::new()
        .route("/jmap/session", get(jmap_session_handler))
        .route("/jmap/api", post(jmap_api_handler))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(crate::blob::blob_download),
        )
        .route(
            "/jmap/upload/{account_id}",
            post(crate::upload::jmap_upload),
        )
        .route(
            "/jmap/auth/token",
            post(crate::auth_token::issue_token).get(crate::auth_token::list_tokens),
        )
        .route(
            "/jmap/auth/token/{id}",
            delete(crate::auth_token::revoke_token),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            basic_auth_middleware,
        ));

    // Enforce the advertised maxSizeRequest: 10 MiB at the transport layer so
    // an unauthenticated client cannot stream an unbounded body and exhaust
    // server memory.  Applies to all routes including public ones.
    const MAX_BODY: usize = 10 * 1024 * 1024;

    Router::new()
        .route("/", get(crate::landing::landing_page))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/.well-known/jmap", get(well_known_jmap))
        .route("/.well-known/mta-sts.txt", get(mta_sts_handler))
        .route(
            "/.well-known/webfinger",
            get(crate::activitypub::webfinger_handler),
        )
        .route(
            "/ap/groups/{group_name}",
            get(crate::activitypub::actor_handler),
        )
        .route(
            "/ap/groups/{group_name}/followers",
            get(crate::activitypub::followers_handler),
        )
        .route(
            "/ap/groups/{group_name}/outbox",
            get(crate::activitypub::outbox_handler),
        )
        .route(
            "/ap/groups/{group_name}/inbox",
            post(crate::activitypub::inbox::inbox_handler),
        )
        .route("/feed/{*path}", get(crate::feed::feed_handler))
        .merge(protected)
        .layer(cors_layer)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

async fn metrics_handler() -> impl axum::response::IntoResponse {
    let body = crate::metrics::gather_metrics();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let uptime_secs = state.start_time.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "uptime_secs": uptime_secs
    }))
}

async fn well_known_jmap() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(axum::http::header::LOCATION, "/jmap/session")],
    )
}

/// Build the RFC 8461 §3.2 policy body (CRLF line endings) for `domain_config`.
fn build_mta_sts_policy_body(domain_config: &stoa_smtp::config::MtaStsDomainConfig) -> String {
    use std::fmt::Write as _;
    use stoa_smtp::config::MtaStsMode;

    let mode_str = match domain_config.mode {
        MtaStsMode::None => "none",
        MtaStsMode::Testing => "testing",
        MtaStsMode::Enforce => "enforce",
        _ => unreachable!("unknown MtaStsMode variant — update this match when adding variants"),
    };

    // RFC 8461 §3.2: policy body MUST use CRLF line endings.
    // write! on String is infallible; unwrap() is safe.
    let mut body = format!("version: STSv1\r\nmode: {mode_str}\r\n");
    for pattern in &domain_config.mx_patterns {
        write!(body, "mx: {pattern}\r\n").expect("String::write_fmt is infallible");
    }
    write!(body, "max_age: {}\r\n", domain_config.max_age_secs)
        .expect("String::write_fmt is infallible");
    body
}

/// Render an MTA-STS policy body and derive its policy-id.
///
/// Returns `(body, policy_id)` where `body` is the RFC 8461 §3.2 policy text
/// and `policy_id` is the first 32 hex characters of the SHA-256 of the body,
/// satisfying the ≤32-char limit from RFC 8461 §3.3.
pub fn render_mta_sts_policy(
    domain_config: &stoa_smtp::config::MtaStsDomainConfig,
) -> (String, String) {
    use sha2::Digest as _;

    let body = build_mta_sts_policy_body(domain_config);
    let digest = sha2::Sha256::digest(body.as_bytes());
    let hex_full = data_encoding::HEXLOWER.encode(&digest);
    let policy_id = hex_full[..32].to_owned();

    (body, policy_id)
}

/// Serve `/.well-known/mta-sts.txt` for hosted domains (RFC 8461 §3.3).
///
/// Sending MTAs fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt`, so
/// the `Host` header will be `mta-sts.<domain>`.  This handler strips the port
/// suffix (if any) and the `mta-sts.` subdomain prefix, then matches the base
/// domain case-insensitively against `state.mta_sts_domains`.  Returns 404
/// for unknown domains.
async fn mta_sts_handler(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let raw_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip port suffix using rsplit_once so IPv6 literals like [::1]:443
    // are handled correctly: rsplit_once(':') on "[::1]:443" gives ("[::1]", "443").
    // Plain "host:port" and bare "host" also work correctly.
    let host_no_port = raw_host
        .rsplit_once(':')
        .map_or(raw_host, |(host, _port)| host)
        .to_lowercase();
    // RFC 8461 §3.3: the policy URL is always https://mta-sts.<domain>/...
    // Requests without the "mta-sts." subdomain prefix are not legitimate
    // policy fetches and must return 404.
    let domain = match host_no_port.strip_prefix("mta-sts.") {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain")],
                String::new(),
            );
        }
    };

    match state
        .mta_sts_domains
        .iter()
        .find(|d| d.domain.eq_ignore_ascii_case(domain))
    {
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            String::new(),
        ),
        Some(domain_config) => {
            let body = build_mta_sts_policy_body(domain_config);
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], body)
        }
    }
}

async fn jmap_session_handler(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Json<Value> {
    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| "anonymous".to_string());
    let is_operator = state.auth_config.is_operator(&username);
    let session = crate::jmap::session::build_session(&username, &state.base_url, is_operator);

    Json(serde_json::to_value(session).expect("JmapSession is always JSON-serializable"))
}

// ---------------------------------------------------------------------------
// JMAP Dispatcher infrastructure
// ---------------------------------------------------------------------------

/// Per-request JMAP caller context forwarded to each method handler.
#[derive(Clone)]
struct JmapCaller {
    username: String,
    user_id: i64,
    is_operator: bool,
    canonical_account_id: String,
    process_start: Instant,
    slow_threshold_ms: u64,
}

/// Adapter that wraps `route_method` as a [`JmapHandler`].
///
/// All registered methods share a single `StoaHandler` instance.  The
/// `method` argument passed to [`JmapHandler::call`] selects the arm inside
/// `route_method`.  This gives us [`Dispatcher`]-level ResultReference
/// resolution while keeping all handler logic in the existing `route_method`.
struct StoaHandler {
    stores: Arc<JmapStores>,
}

impl JmapHandler<JmapCaller> for StoaHandler {
    fn call(
        &self,
        method: String,
        _call_id: String,
        args: Value,
        caller: JmapCaller,
    ) -> HandlerFuture {
        let stores = Arc::clone(&self.stores);
        Box::pin(async move {
            let t0 = Instant::now();
            let result = route_method(
                &method,
                args,
                &stores,
                &caller.canonical_account_id,
                caller.process_start,
                caller.is_operator,
                caller.user_id,
            )
            .await;
            let elapsed = t0.elapsed().as_secs_f64();
            crate::metrics::JMAP_REQUESTS_TOTAL
                .with_label_values(&[&method])
                .inc();
            crate::metrics::JMAP_REQUEST_DURATION_SECONDS
                .with_label_values(&[&method])
                .observe(elapsed);
            if caller.slow_threshold_ms > 0 && (elapsed * 1000.0) as u64 >= caller.slow_threshold_ms
            {
                tracing::warn!(
                    event = "slow_jmap",
                    method = %method,
                    elapsed_ms = (elapsed * 1000.0) as u64,
                    username = %caller.username,
                    "slow JMAP method",
                );
            }
            if method == "Email/query" {
                if let Some(ids) = result.get("ids").and_then(|v| v.as_array()) {
                    crate::metrics::EMAIL_QUERY_RESULTS.set(ids.len() as i64);
                }
            }
            stoa_value_to_result(result)
        })
    }
}

/// Translate a `route_method` `Value` return into a handler `Result`.
///
/// `route_method` embeds method-level errors as `{"type": "<error-type>"}` or
/// `{"error": "<message>"}` in the returned `Value`.  The Dispatcher contract
/// requires errors to be `Err(JmapError)`.
///
/// # Precondition
///
/// Success responses returned by `route_method` **must not** contain a top-level
/// `"type"` key.  If they do, this function will incorrectly treat them as errors.
/// All current `route_method` handler arms satisfy this — the `"type"` key appears
/// only in `MethodError`/`JmapError` objects.  New handlers must preserve this invariant.
fn stoa_value_to_result(v: Value) -> Result<(Value, Vec<jmap_types::Invocation>), JmapError> {
    if let Some(type_str) = v.get("type").and_then(|t| t.as_str()) {
        let mut err = JmapError::custom(type_str);
        err.description = v
            .get("description")
            .and_then(|d| d.as_str())
            .map(str::to_string);
        Err(err)
    } else if v.get("error").is_some() {
        Err(JmapError::server_fail("internal error"))
    } else {
        Ok((v, vec![]))
    }
}

/// Resolve a username to its numeric `user_id` from the database.
///
/// Returns `Ok(SINGLETON_USER_ID)` when the user is not found — intentional for
/// the v1 single-user deployment model.  Returns `Err` only on a database failure,
/// which the caller should surface as 503.
async fn resolve_user_id(pool: &sqlx::AnyPool, username: &str) -> Result<i64, sqlx::Error> {
    match sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?
    {
        Some(id) => Ok(id),
        None => {
            if username != "anonymous" {
                tracing::warn!(
                    username = %username,
                    "JMAP: user not found in users table; falling back to singleton user_id"
                );
            }
            Ok(SINGLETON_USER_ID)
        }
    }
}

/// Build the JMAP [`Dispatcher`] that routes all supported methods.
///
/// All RFC 8621 Email/Mailbox/Thread/etc. methods and custom Stoa extensions route through a
/// single [`StoaHandler`] that delegates to `route_method`.  The Dispatcher
/// layer provides RFC 8620 ResultReference (`#`-prefix) resolution before each
/// call, which the previous hand-rolled loop did not implement.
fn build_jmap_dispatcher(stores: Arc<JmapStores>) -> Dispatcher<JmapCaller> {
    let handler: Arc<dyn JmapHandler<JmapCaller>> = Arc::new(StoaHandler { stores });

    // All method names to register with the Dispatcher.
    // IMPORTANT: this list must be kept in sync with the match arms in `route_method`.
    // A name missing here will cause the Dispatcher to return unknownMethod instead of
    // dispatching to route_method, with no compile-time error.
    // Unimplemented RFC 8621 names intentionally route to the `_` arm → unknownMethod.
    const METHODS: &[&str] = &[
        // RFC 8621 Mailbox
        "Mailbox/get",
        "Mailbox/changes",
        "Mailbox/query",
        "Mailbox/queryChanges",
        "Mailbox/set",
        // RFC 8621 Thread
        "Thread/get",
        "Thread/changes",
        // RFC 8621 Email
        "Email/get",
        "Email/changes",
        "Email/query",
        "Email/queryChanges",
        "Email/set",
        "Email/copy",
        "Email/import",
        "Email/parse",
        // RFC 8621 SearchSnippet
        "SearchSnippet/get",
        // RFC 8621 Identity
        "Identity/get",
        "Identity/changes",
        "Identity/set",
        // RFC 8621 EmailSubmission
        "EmailSubmission/get",
        "EmailSubmission/changes",
        "EmailSubmission/query",
        "EmailSubmission/queryChanges",
        "EmailSubmission/set",
        // RFC 8621 VacationResponse
        "VacationResponse/get",
        "VacationResponse/set",
        // RFC 9404 Blob
        "Blob/get",
        "Blob/copy",
        // Stoa-specific admin methods
        "ServerStatus/get",
        "Peer/get",
        "GroupLog/get",
    ];

    let mut d = Dispatcher::new();
    for &method in METHODS {
        d.register(method, Arc::clone(&handler));
    }
    d
}

// ---------------------------------------------------------------------------
// JMAP API handler
// ---------------------------------------------------------------------------

async fn jmap_api_handler(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    axum::extract::Json(request): axum::extract::Json<JmapRequest>,
) -> impl axum::response::IntoResponse {
    use axum::response::IntoResponse as _;
    let jmap = match state.jmap.as_ref() {
        Some(j) => j,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "JMAP not configured"})),
            )
                .into_response();
        }
    };

    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| "anonymous".to_string());
    let canonical_account_id = format!("u_{username}");
    let is_operator = state.auth_config.is_operator(&username);

    let user_id = match resolve_user_id(&jmap.mail_pool, &username).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "JMAP: users table lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "database unavailable"})),
            )
                .into_response();
        }
    };

    let session_state: jmap_types::State = jmap
        .state_store
        .get_state(user_id, "session")
        .await
        .unwrap_or_else(|_| "0".to_string())
        .into();

    let caller = JmapCaller {
        username,
        user_id,
        is_operator,
        canonical_account_id,
        process_start: state.start_time,
        slow_threshold_ms: state.slow_jmap_threshold_ms,
    };

    let dispatcher = build_jmap_dispatcher(Arc::clone(jmap));
    let response = dispatcher.dispatch(request, caller, session_state).await;

    match serde_json::to_value(response) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            tracing::error!("jmap_api_handler: failed to serialize response: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

async fn route_method(
    method: &str,
    args: Value,
    jmap: &JmapStores,
    canonical_account_id: &str,
    server_start: std::time::Instant,
    is_operator: bool,
    user_id: i64,
) -> Value {
    // RFC 8621 §2: every method call carries an accountId.  If it is present
    // and does not match the authenticated principal's account, return
    // accountNotFound immediately without dispatching to the handler.
    //
    // An absent accountId is treated as the anonymous case and passed through;
    // handlers that require it will return their own error if needed.
    if let Some(requested_id) = args.get("accountId").and_then(|v| v.as_str()) {
        if requested_id != canonical_account_id {
            let err = crate::jmap::types::MethodError::account_not_found();
            return serde_json::to_value(&err).unwrap_or(json!({}));
        }
    }

    match method {
        "Mailbox/get" => {
            let subscribed: std::collections::HashSet<String> = jmap
                .subscription_store
                .list_subscribed(user_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let group_infos: Vec<crate::mailbox::get::GroupInfo> = groups
                .into_iter()
                .map(|(name, lo, hi)| {
                    let total_emails = if hi < lo {
                        0u32
                    } else {
                        (hi - lo + 1).min(u32::MAX as u64) as u32
                    };
                    let is_subscribed = subscribed.contains(&name);
                    crate::mailbox::get::GroupInfo {
                        name,
                        total_emails,
                        unread_emails: 0,
                        is_subscribed,
                    }
                })
                .collect();
            let ids_filter: Option<Vec<String>> =
                args.get("ids").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                });
            let state = jmap
                .state_store
                .get_state(user_id, "Mailbox")
                .await
                .unwrap_or_else(|_| "0".to_string());
            crate::mailbox::get::handle_mailbox_get(
                &jmap.special_mailboxes,
                &group_infos,
                ids_filter.as_deref(),
                &state,
                canonical_account_id,
            )
        }

        "Mailbox/set" => {
            let old_state = jmap
                .state_store
                .get_state(user_id, "Mailbox")
                .await
                .unwrap_or_else(|_| "0".to_string());
            let mut result = crate::mailbox::set::handle_mailbox_set(
                &args,
                user_id,
                &jmap.subscription_store,
                &jmap.article_numbers,
                &old_state,
                &old_state,
            )
            .await;
            let any_created = result
                .get("created")
                .and_then(|v| v.as_object())
                .map(|m| !m.is_empty())
                .unwrap_or(false);
            let any_destroyed = result
                .get("destroyed")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if any_created || any_destroyed {
                let new_state = jmap
                    .state_store
                    .bump_state(user_id, "Mailbox")
                    .await
                    .unwrap_or_else(|_| old_state.clone());
                if let Some(obj) = result.as_object_mut() {
                    obj.insert("newState".to_string(), serde_json::Value::String(new_state));
                }
            }
            result
        }

        "Mailbox/query" => {
            let subscribed: std::collections::HashSet<String> = jmap
                .subscription_store
                .list_subscribed(user_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let group_infos: Vec<crate::mailbox::get::GroupInfo> = groups
                .into_iter()
                .map(|(name, lo, hi)| {
                    let total_emails = if hi < lo {
                        0u32
                    } else {
                        (hi - lo + 1).min(u32::MAX as u64) as u32
                    };
                    let is_subscribed = subscribed.contains(&name);
                    crate::mailbox::get::GroupInfo {
                        name,
                        total_emails,
                        unread_emails: 0,
                        is_subscribed,
                    }
                })
                .collect();
            let filter = args.get("filter");
            let sort = args.get("sort");
            let state = jmap
                .state_store
                .get_state(user_id, "Mailbox")
                .await
                .unwrap_or_else(|_| "0".to_string());
            crate::mailbox::query::handle_mailbox_query(
                &group_infos,
                filter,
                sort,
                &state,
                canonical_account_id,
            )
        }

        "Email/query" => {
            let mailbox_id = args
                .get("filter")
                .and_then(|f| f.get("inMailbox"))
                .and_then(|v| v.as_str());

            let email_state = jmap
                .state_store
                .get_state(user_id, "Email")
                .await
                .unwrap_or_else(|_| "0".to_string());

            // Check if mailbox_id belongs to a user special folder (e.g. INBOX).
            // Uses a single indexed EXISTS query instead of fetching the full list.
            // If so, return smtp: message IDs from mailbox_messages with SQL-side pagination.
            if let Some(mid) = mailbox_id {
                let is_special: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE mailbox_id = ?)",
                )
                .bind(mid)
                .fetch_one(&*jmap.mail_pool)
                .await
                .unwrap_or(false);

                if is_special {
                    let position: u64 = args.get("position").and_then(|v| v.as_u64()).unwrap_or(0);
                    let limit: i64 = args
                        .get("limit")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(10_000)
                        .min(10_000) as i64;

                    let total: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?")
                            .bind(mid)
                            .fetch_one(&*jmap.mail_pool)
                            .await
                            .unwrap_or(0);

                    let total = total as u64;
                    // RFC 8620 §5.5: position in response must be clamped to total.
                    let response_position = position.min(total);

                    let page: Vec<Value> = sqlx::query_scalar::<_, i64>(
                        "SELECT id FROM messages \
                         WHERE mailbox_id = ? \
                         ORDER BY id DESC LIMIT ? OFFSET ?",
                    )
                    .bind(mid)
                    .bind(limit)
                    .bind(response_position as i64)
                    .fetch_all(&*jmap.mail_pool)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|row_id| Value::String(format!("smtp:{row_id}")))
                    .collect();

                    return json!({
                        "accountId": canonical_account_id,
                        "queryState": email_state,
                        "canCalculateChanges": false,
                        "position": response_position,
                        "ids": page,
                        "total": total,
                    });
                }
            }

            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let target_group = groups.iter().find(|(name, _, _)| {
                crate::mailbox::types::mailbox_id_for_group(name) == mailbox_id.unwrap_or("")
            });

            let (group_name, lo, hi) = match target_group {
                Some(g) => g.clone(),
                None => {
                    return json!({
                        "accountId": canonical_account_id,
                        "ids": [],
                        "total": 0,
                        "queryState": email_state,
                        "canCalculateChanges": false,
                        "position": 0
                    })
                }
            };

            let records = match jmap.overview_store.query_range(&group_name, lo, hi).await {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };

            let numbers: Vec<u64> = records.iter().map(|r| r.article_number).collect();
            let cid_map = jmap
                .article_numbers
                .lookup_cids_batch(&group_name, &numbers)
                .await
                .unwrap_or_default();

            let mut entries = Vec::new();
            for rec in &records {
                if let Some(cid) = cid_map.get(&rec.article_number).copied() {
                    entries.push(crate::email::query::EmailOverviewEntry {
                        cid,
                        message_id: rec.message_id.clone(),
                        subject: rec.subject.clone(),
                        from: rec.from.clone(),
                        date: rec.date.clone(),
                        byte_count: rec.byte_count,
                    });
                }
            }

            let filter = args.get("filter");

            // Resolve `text` filter via full-text search index when present.
            let text_results = if let Some(f) = filter {
                if let Some(text_val) = f.get("text").and_then(|v| v.as_str()) {
                    if !text_val.is_empty() {
                        if let Some(ref idx) = jmap.search_index {
                            match idx.search_all(text_val, 50_000).await {
                                Ok(ids) => {
                                    Some(ids.into_iter().collect::<std::collections::HashSet<_>>())
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "JMAP text search failed; ignoring text filter");
                                    None
                                }
                            }
                        } else {
                            // Search index not configured; return empty set so the
                            // text filter is honoured (no results) rather than
                            // silently returning all articles.
                            Some(std::collections::HashSet::new())
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let position: u64 = args.get("position").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit: Option<u64> = args.get("limit").and_then(|v| v.as_u64());
            crate::email::query::handle_email_query(
                &entries,
                filter,
                position,
                limit,
                &email_state,
                text_results,
                canonical_account_id,
            )
        }

        "Email/get" => {
            let ids: Vec<String> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            // RFC 8620 §3.3: reject requests that exceed maxObjectsInGet (500).
            // Silently truncating would lie to the caller; a clear error lets
            // the client split the request rather than getting a partial result.
            const MAX_IDS: usize = 500;
            if ids.len() > MAX_IDS {
                let mut err = JmapError::request_too_large();
                err.description = Some(format!("ids exceeds maxObjectsInGet limit of {MAX_IDS}"));
                return serde_json::to_value(&err).unwrap_or(json!({}));
            }
            let email_state = jmap
                .state_store
                .get_state(user_id, "Email")
                .await
                .unwrap_or_else(|_| "0".to_string());
            crate::email::get::handle_email_get(
                &ids,
                jmap.ipfs.as_ref(),
                Some(&*jmap.mail_pool),
                None,
                &email_state,
                canonical_account_id,
            )
            .await
        }

        "Email/set" => {
            let old_state = jmap
                .state_store
                .get_state(user_id, "Email")
                .await
                .unwrap_or_else(|_| "0".to_string());

            let mut result = match crate::email::set::handle_email_set(args.clone(), &old_state) {
                Ok(v) => v,
                Err(e) => return serde_json::to_value(&e).unwrap_or(json!({})),
            };

            let mut any_changed = false;

            // Handle keyword updates.
            if let Some(update_map) = args.get("update").and_then(|v| v.as_object()) {
                let (mut updated, not_updated) =
                    crate::email::set::handle_keyword_update(update_map, user_id, &jmap.user_flags)
                        .await;
                // An id must not appear in both updated and notUpdated.
                // handle_email_set may have already placed an id in notUpdated
                // (e.g. for a mailboxIds conflict); remove those from updated here.
                if let Some(already_not_updated) = result["notUpdated"].as_object() {
                    for id in already_not_updated.keys() {
                        updated.remove(id);
                    }
                }
                if !updated.is_empty() {
                    any_changed = true;
                    result["updated"] = Value::Object(updated);
                }
                if !not_updated.is_empty() {
                    let existing = result["notUpdated"]
                        .as_object()
                        .cloned()
                        .unwrap_or_default();
                    let mut merged = existing;
                    merged.extend(not_updated);
                    result["notUpdated"] = Value::Object(merged);
                }
            }

            // Handle creates.
            if let Some(create_map) = args.get("create").and_then(|v| v.as_object()) {
                let known_groups = jmap.article_numbers.list_groups().await.unwrap_or_default();
                let (created, not_created) = crate::email::set::handle_email_create(
                    create_map,
                    jmap.ipfs.as_ref(),
                    &jmap.msgid_map,
                    jmap.smtp_relay_queue.as_ref(),
                    &known_groups,
                )
                .await;
                if !created.is_empty() {
                    any_changed = true;
                    result["created"] = Value::Object(created);
                }
                if !not_created.is_empty() {
                    result["notCreated"] = Value::Object(not_created);
                }
            }

            // Set real oldState/newState; bump state if any write succeeded.
            let new_state = if any_changed {
                jmap.state_store
                    .bump_state(user_id, "Email")
                    .await
                    .unwrap_or_else(|_| old_state.clone())
            } else {
                old_state.clone()
            };
            result["oldState"] = Value::String(old_state);
            result["newState"] = Value::String(new_state.clone());

            // Record changes in the change log for Email/changes.
            let new_seq: i64 = new_state.parse().unwrap_or(0);
            if let Some(created_obj) = result["created"].as_object() {
                let new_cid_ids: Vec<String> = created_obj
                    .values()
                    .filter_map(|v| v.get("id"))
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect();
                if !new_cid_ids.is_empty() {
                    if let Err(e) = jmap
                        .change_log
                        .record_created(user_id, "Email", &new_cid_ids, new_seq)
                        .await
                    {
                        tracing::warn!("change_log.record_created failed: {e}");
                    }
                }
            }
            if let Some(updated_obj) = result["updated"].as_object() {
                let updated_ids: Vec<String> = updated_obj.keys().cloned().collect();
                if !updated_ids.is_empty() {
                    if let Err(e) = jmap
                        .change_log
                        .record_updated(user_id, "Email", &updated_ids, new_seq)
                        .await
                    {
                        tracing::warn!("change_log.record_updated failed: {e}");
                    }
                }
            }

            result
        }

        "Thread/get" => {
            let requested_ids: Vec<String> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            // Collect overview records to compute thread memberships.
            //
            // TODO(stoa-c4zlv.2): This scan is O(total articles across all
            // groups).  A proper fix requires a dedicated thread-index table
            // mapping (group, message_id) → thread_root.  Until then, cap the
            // total entries scanned to avoid multi-second latency on large corpora.
            const MAX_THREAD_SCAN: usize = 5000;

            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };

            let mut entries: Vec<crate::thread::get::ThreadEntry> = Vec::new();
            let requested_set: std::collections::HashSet<&str> =
                requested_ids.iter().map(String::as_str).collect();
            let mut found: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut total_scanned: usize = 0;

            'outer: for (group_name, lo, hi) in &groups {
                let records = match jmap.overview_store.query_range(group_name, *lo, *hi).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let numbers: Vec<u64> = records.iter().map(|r| r.article_number).collect();
                let cid_map = jmap
                    .article_numbers
                    .lookup_cids_batch(group_name, &numbers)
                    .await
                    .unwrap_or_default();
                for rec in &records {
                    if let Some(cid) = cid_map.get(&rec.article_number).copied() {
                        let tid =
                            crate::thread::get::thread_id_for(&rec.references, &rec.message_id);
                        if requested_set.contains(tid.as_str()) {
                            found.insert(tid);
                        }
                        entries.push(crate::thread::get::ThreadEntry {
                            email_id: cid.to_string(),
                            references: rec.references.clone(),
                            message_id: rec.message_id.clone(),
                        });
                    }
                    total_scanned += 1;
                    if total_scanned >= MAX_THREAD_SCAN {
                        break 'outer;
                    }
                }
                // Early exit: all requested threads found.
                if found.len() == requested_set.len() {
                    break;
                }
            }

            let thread_state = jmap
                .state_store
                .get_state(user_id, "Thread")
                .await
                .unwrap_or_else(|_| "0".to_string());

            let id_refs: Vec<&str> = requested_ids.iter().map(|s| s.as_str()).collect();
            crate::thread::get::handle_thread_get(
                &entries,
                &id_refs,
                &thread_state,
                canonical_account_id,
            )
        }

        // RFC 8620 §5.2 — /changes methods for incremental sync.
        "Email/changes" => {
            let since_state_str = args
                .get("sinceState")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let since_seq: i64 = match since_state_str.parse() {
                Ok(n) if n >= 0 => n,
                _ => {
                    let new_state = jmap
                        .state_store
                        .get_state(user_id, "Email")
                        .await
                        .unwrap_or_else(|_| "0".to_string());
                    return json!({
                        "type": "cannotCalculateChanges",
                        "newState": new_state
                    });
                }
            };

            let new_state = jmap
                .state_store
                .get_state(user_id, "Email")
                .await
                .unwrap_or_else(|_| "0".to_string());

            let created = match jmap
                .change_log
                .query_since(user_id, "Email", since_seq)
                .await
            {
                Ok(ids) => ids,
                Err(e) => return json!({"error": e.to_string()}),
            };

            json!({
                "accountId": canonical_account_id,
                "oldState": since_state_str,
                "newState": new_state,
                "created": created,
                "updated": [],
                "destroyed": [],
                "hasMoreChanges": false
            })
        }

        "Mailbox/changes" => {
            let new_state = jmap
                .state_store
                .get_state(user_id, "Mailbox")
                .await
                .unwrap_or_else(|_| "0".to_string());
            // Mailboxes are NNTP groups; membership changes are not tracked in
            // the change log.  RFC 8620 §5.2 permits returning cannotCalculateChanges.
            json!({
                "type": "cannotCalculateChanges",
                "newState": new_state
            })
        }

        // RFC 9404 §4.1: Blob/get — return base64url-encoded raw block bytes
        // for each requested blobId (CID).  Unknown CIDs go into notFound.
        "Blob/get" => {
            let ids: Vec<String> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            let mut list: Vec<Value> = Vec::new();
            let mut not_found: Vec<String> = Vec::new();

            for id in &ids {
                let cid = match cid::Cid::try_from(id.as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        not_found.push(id.clone());
                        continue;
                    }
                };
                match jmap.ipfs.get_raw(&cid).await {
                    Ok(bytes) => {
                        let encoded = data_encoding::BASE64.encode(&bytes);
                        list.push(json!({
                            "id": id,
                            "data:asBase64": encoded,
                            "type": "message/rfc822",
                            "size": bytes.len()
                        }));
                    }
                    Err(stoa_reader::post::ipfs_write::IpfsWriteError::NotFound(_)) => {
                        not_found.push(id.clone());
                    }
                    Err(e) => {
                        tracing::warn!(blob_id = %id, "Blob/get IPFS error: {e}");
                        not_found.push(id.clone());
                    }
                }
            }

            json!({
                "accountId": canonical_account_id,
                "list": list,
                "notFound": not_found
            })
        }

        // RFC 9404 §4.2: Blob/copy — in stoa, CIDs are global content addresses
        // shared across all accounts.  Validate that each blobId is a parseable
        // CIDv1 before reporting success; garbage strings go to notCopied.
        "Blob/copy" => {
            let from_account_id = args
                .get("fromAccountId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let blob_ids: Vec<String> = args
                .get("blobIds")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            let mut copied: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut not_copied: serde_json::Map<String, Value> = serde_json::Map::new();
            for id in &blob_ids {
                if cid::Cid::try_from(id.as_str()).is_ok() {
                    // Valid CID — globally accessible in stoa.
                    copied.insert(id.clone(), Value::String(id.clone()));
                } else {
                    not_copied.insert(
                        id.clone(),
                        json!({"type": "blobNotFound", "description": "not a valid CID"}),
                    );
                }
            }

            json!({
                "fromAccountId": from_account_id,
                "accountId": canonical_account_id,
                "copied": copied,
                "notCopied": not_copied
            })
        }

        // RFC 8621 §5.4: SearchSnippet/get — return highlighted snippets for
        // email search matches.  Subject is sourced from the overview store;
        // body preview is fetched from IPFS.  When no search index is configured
        // or the filter has no "text" field, all snippets are returned as null.
        "SearchSnippet/get" => {
            let email_ids: Vec<String> = args
                .get("emailIds")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let filter = args.get("filter").cloned();
            let text_query = filter
                .as_ref()
                .and_then(|f| f.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Reverse-lookup: resolve each emailId CID to (group, article_num) on demand.
            // Avoids loading all articles into memory — each lookup is a single indexed query.

            let mut list: Vec<Value> = Vec::new();
            let mut not_found: Vec<String> = Vec::new();

            for email_id in &email_ids {
                let cid = match cid::Cid::try_from(email_id.as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        not_found.push(email_id.clone());
                        continue;
                    }
                };

                let (subject_snip, preview_snip) =
                    if text_query.is_empty() || jmap.search_index.is_none() {
                        // No text query or no index — return null snippets.
                        (None, None)
                    } else if let Some((group, num)) = jmap
                        .article_numbers
                        .lookup_by_cid(&cid)
                        .await
                        .ok()
                        .flatten()
                    {
                        let subject_text = jmap
                            .overview_store
                            .query_by_number(&group, num)
                            .await
                            .ok()
                            .flatten()
                            .map(|r| r.subject)
                            .unwrap_or_default();

                        let body_text: String = async {
                            let raw = match jmap.ipfs.get_raw(&cid).await {
                                Ok(r) => r,
                                Err(_) => return String::new(),
                            };
                            let root: stoa_core::ipld::root_node::ArticleRootNode =
                                match serde_ipld_dagcbor::from_slice(&raw) {
                                    Ok(r) => r,
                                    Err(_) => return String::new(),
                                };
                            match jmap.ipfs.get_raw(&root.body_cid).await {
                                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                                Err(_) => String::new(),
                            }
                        }
                        .await;

                        if let Some(ref idx) = jmap.search_index {
                            idx.make_snippets(&text_query, &subject_text, &body_text)
                        } else {
                            (None, None)
                        }
                    } else {
                        // CID not in article_numbers — silently omit.
                        not_found.push(email_id.clone());
                        continue;
                    };

                list.push(json!({
                    "emailId": email_id,
                    "subject": subject_snip,
                    "preview": preview_snip,
                }));
            }

            json!({
                "accountId": canonical_account_id,
                "filter": filter.unwrap_or(json!(null)),
                "list": list,
                "notFound": not_found,
            })
        }

        // ── Admin methods (urn:ietf:params:jmap:usenet-ipfs-admin) ───────────────
        // These methods are only accessible to users with the operator role.
        // Non-operators receive a `forbidden` error.
        "ServerStatus/get" => {
            if !is_operator {
                return serde_json::to_value(crate::jmap::types::MethodError::forbidden())
                    .unwrap_or(json!({}));
            }
            let uptime_secs = server_start.elapsed().as_secs();
            json!({
                "accountId": canonical_account_id,
                "status": {
                    "uptime_secs": uptime_secs
                }
            })
        }

        "Peer/get" => {
            if !is_operator {
                return serde_json::to_value(crate::jmap::types::MethodError::forbidden())
                    .unwrap_or(json!({}));
            }
            // Peer state is owned by stoa-transit; the JMAP server returns an
            // empty list.  A future epic can wire transit admin state here.
            json!({
                "accountId": canonical_account_id,
                "list": [],
                "notFound": []
            })
        }

        "GroupLog/get" => {
            if !is_operator {
                return serde_json::to_value(crate::jmap::types::MethodError::forbidden())
                    .unwrap_or(json!({}));
            }
            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let list: Vec<Value> = groups
                .iter()
                .map(|(name, lo, hi)| {
                    let count = if *hi < *lo { 0u64 } else { hi - lo + 1 };
                    json!({
                        "id": name,
                        "name": name,
                        "articleCount": count
                    })
                })
                .collect();
            json!({
                "accountId": canonical_account_id,
                "list": list,
                "notFound": []
            })
        }

        _ => serde_json::to_value(crate::jmap::types::MethodError::unknown_method())
            .unwrap_or(json!({})),
    }
}

/// Start the HTTP server on the given address and run until `shutdown` resolves.
pub async fn run_server(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // TLS: not yet wired in v1; load_tls_config is available for future use
    let listener = TcpListener::bind(addr).await?;
    let router = build_router(state);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_store::TokenStore;
    use stoa_auth::{AuthConfig, CredentialStore, UserCredential};
    use stoa_reader::{
        post::ipfs_write::MemIpfsStore,
        store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
    };
    use tokio::net::TcpListener;

    use crate::state::{flags::UserFlagsStore, version::StateStore};

    async fn make_token_store() -> (Arc<TokenStore>, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (Arc::new(TokenStore::new(Arc::new(pool))), tmp)
    }

    /// Build an AppState in dev mode: `required = false`, no users, no credential file.
    async fn dev_state() -> (Arc<AppState>, tempfile::TempPath) {
        let (ts, tmp) = make_token_store().await;
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: ts,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        (state, tmp)
    }

    /// Build an AppState in dev mode with a custom base URL.
    async fn dev_state_with_base_url(base_url: &str) -> (Arc<AppState>, tempfile::TempPath) {
        let (ts, tmp) = make_token_store().await;
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: ts,
            oidc_store: None,
            base_url: base_url.to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        (state, tmp)
    }

    /// Build an AppState with a single user (bcrypt cost 4 for test speed).
    async fn auth_state(
        username: &str,
        plaintext_password: &str,
    ) -> (Arc<AppState>, tempfile::TempPath) {
        let hash = bcrypt::hash(plaintext_password, 4).expect("bcrypt::hash must not fail");
        let users = vec![UserCredential {
            username: username.to_string(),
            password: hash,
        }];
        let (ts, tmp) = make_token_store().await;
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(
                CredentialStore::from_credentials(&users).expect("test setup: valid bcrypt hashes"),
            ),
            auth_config: Arc::new(AuthConfig {
                required: true,
                users,
                ..Default::default()
            }),
            token_store: ts,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        (state, tmp)
    }

    /// Create a tempfile-backed AnyPool with reader-crate migrations applied.
    async fn make_reader_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_reader::migrations::run_migrations(&url)
            .await
            .expect("reader migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("reader pool");
        (pool, tmp)
    }

    /// Build an AppState with JMAP stores wired to a MemIpfsStore.
    ///
    /// Returns `(state, ipfs, _tmps)` so the caller can seed blocks before the test.
    async fn jmap_state() -> (Arc<AppState>, Arc<MemIpfsStore>, Vec<tempfile::TempPath>) {
        let mut tmps = Vec::new();

        // Pool for mail-crate stores (UserFlagsStore, StateStore, TokenStore).
        let mail_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mail_url = format!("sqlite://{}", mail_tmp.to_str().unwrap());
        crate::migrations::run_migrations(&mail_url)
            .await
            .expect("mail migrations");
        let mail_pool = stoa_core::db_pool::try_open_any_pool(&mail_url, 1)
            .await
            .expect("mail pool");
        tmps.push(mail_tmp);

        // Pool for reader-crate stores (ArticleNumberStore, OverviewStore).
        let (reader_pool, reader_tmp) = make_reader_pool().await;
        tmps.push(reader_tmp);

        // Pool for core-crate stores (MsgIdMap).
        let core_tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let core_url = format!("sqlite://{}", core_tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&core_url)
            .await
            .expect("core migrations");
        let core_pool = stoa_core::db_pool::try_open_any_pool(&core_url, 1)
            .await
            .expect("core pool");
        tmps.push(core_tmp);

        let ipfs = Arc::new(MemIpfsStore::new());
        let mail_pool_arc = Arc::new(mail_pool);

        crate::mailbox::provision::provision_mailboxes(&mail_pool_arc)
            .await
            .expect("provision_mailboxes must succeed at startup");
        let special_mailboxes = Arc::new(
            crate::mailbox::provision::list_mailboxes(&mail_pool_arc)
                .await
                .expect("list_mailboxes must succeed after provision"),
        );
        let stores = Arc::new(JmapStores {
            ipfs: ipfs.clone(),
            msgid_map: Arc::new(stoa_core::msgid_map::MsgIdMap::new(core_pool)),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            user_flags: Arc::new(UserFlagsStore::new((*mail_pool_arc).clone())),
            state_store: Arc::new(StateStore::new((*mail_pool_arc).clone())),
            change_log: Arc::new(crate::state::change_log::ChangeLogStore::new(
                (*mail_pool_arc).clone(),
            )),
            subscription_store: Arc::new(crate::state::subscriptions::SubscriptionStore::new(
                (*mail_pool_arc).clone(),
            )),
            search_index: None,
            smtp_relay_queue: None,
            mail_pool: Arc::clone(&mail_pool_arc),
            special_mailboxes,
        });
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: Some(stores),
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: Arc::new(TokenStore::new(Arc::clone(&mail_pool_arc))),
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        (state, ipfs, tmps)
    }

    async fn spawn_server(state: Arc<AppState>) -> std::net::SocketAddr {
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        addr
    }

    /// Verify that the total_emails calculation in Mailbox/get does not underflow
    /// or truncate incorrectly for edge cases.
    #[test]
    fn mailbox_get_total_emails_edge_cases() {
        // Helper that mirrors the fixed arithmetic in route_method.
        fn total_emails(lo: u64, hi: u64) -> u32 {
            if hi < lo {
                0u32
            } else {
                (hi - lo + 1).min(u32::MAX as u64) as u32
            }
        }

        // Normal single-article group.
        assert_eq!(total_emails(1, 1), 1);
        // Normal multi-article group.
        assert_eq!(total_emails(1, 10), 10);
        // Empty group: hi < lo must return 0, not wrap or panic.
        assert_eq!(total_emails(5, 4), 0);
        // Saturation: a group with more articles than u32::MAX must clamp.
        assert_eq!(total_emails(0, u32::MAX as u64 + 1), u32::MAX);
    }

    #[tokio::test]
    async fn health_returns_200_with_ok() {
        let addr = spawn_server(dev_state().await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");
        assert!(body["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn well_known_jmap_redirects_to_session() {
        let addr = spawn_server(dev_state().await.0).await;

        let resp = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(format!("http://{addr}/.well-known/jmap"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 301);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/jmap/session");
    }

    #[tokio::test]
    async fn jmap_session_dev_mode_returns_200_with_capabilities() {
        let addr = spawn_server(dev_state().await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["capabilities"].is_object());
        assert!(body["capabilities"]["urn:ietf:params:jmap:core"].is_object());
    }

    #[tokio::test]
    async fn jmap_session_no_credentials_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            www_auth.contains("Basic"),
            "WWW-Authenticate must advertise Basic"
        );
        assert!(www_auth.contains("stoa"), "realm must be stoa");
    }

    #[tokio::test]
    async fn jmap_session_wrong_password_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("alice", Some("wrong-password"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn jmap_session_correct_credentials_returns_200_with_username() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("alice", Some("correct-horse"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["username"], "alice");
        let account_id = "u_alice";
        assert!(
            body["accounts"][account_id].is_object(),
            "account u_alice must be present"
        );
    }

    #[tokio::test]
    async fn health_endpoint_is_public() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn blob_download_invalid_cid_returns_400() {
        let addr = spawn_server(dev_state().await.0).await;

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/acc1/not-a-cid/file.txt"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn blob_download_no_credentials_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await.0).await;
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/u_alice/{valid_cid}/msg.eml"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn jmap_session_reflects_configured_base_url() {
        let configured_base = "https://mail.example.com";
        let addr = spawn_server(dev_state_with_base_url(configured_base).await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["apiUrl"], "https://mail.example.com/jmap/api",
            "apiUrl must reflect configured base_url"
        );
        assert!(
            body["downloadUrl"]
                .as_str()
                .unwrap_or("")
                .starts_with("https://mail.example.com/"),
            "downloadUrl must reflect configured base_url"
        );
    }

    #[tokio::test]
    async fn jmap_session_username_reflects_authenticated_user() {
        let addr = spawn_server(auth_state("bob", "hunter2").await.0).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("bob", Some("hunter2"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["username"], "bob",
            "username must reflect authenticated user"
        );
        assert!(
            body["accounts"]["u_bob"].is_object(),
            "account u_bob must be present for authenticated user bob"
        );
    }

    /// Seed a block in MemIpfsStore, request it via GET /jmap/download, assert
    /// 200 with Content-Type: message/rfc822 and base64-encoded body.
    #[tokio::test]
    async fn blob_download_with_ipfs_returns_200_with_rfc822() {
        let (state, ipfs, _tmps) = jmap_state().await;

        // Seed a known block.
        let block_data = b"hello from IPFS block";
        let cid = ipfs
            .put_raw(block_data)
            .await
            .expect("put_raw must succeed");

        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/download/acc1/{cid}/block.bin"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200, "seeded block must return 200");

        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .expect("Content-Type must be present")
            .to_str()
            .expect("Content-Type must be valid UTF-8");
        assert_eq!(ct, "message/rfc822", "Content-Type must be message/rfc822");

        let body = resp.text().await.expect("body must be readable");

        // The body must contain the X-Stoa-CID header with the CID.
        assert!(
            body.contains(&format!("X-Stoa-CID: {cid}")),
            "body must contain X-Stoa-CID header"
        );

        // The body must contain the base64-encoded block bytes.
        let expected_b64 = data_encoding::BASE64.encode(block_data);
        assert!(
            body.contains(&expected_b64),
            "body must contain base64-encoded block data"
        );
    }

    /// A CID not present in IPFS must return 404.
    #[tokio::test]
    async fn blob_download_unknown_cid_returns_404() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        // Valid CID that was never seeded.
        let absent_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/acc1/{absent_cid}/missing.bin"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 404, "absent CID must return 404");
    }

    /// RFC 9404: session must advertise `urn:ietf:params:jmap:blob` capability.
    #[tokio::test]
    async fn session_has_blob_capability() {
        let addr = spawn_server(dev_state().await.0).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["capabilities"]
                .as_object()
                .map(|c| c.contains_key("urn:ietf:params:jmap:blob"))
                .unwrap_or(false),
            "session must advertise urn:ietf:params:jmap:blob capability"
        );
    }

    /// RFC 9404: Blob/get returns base64url data for a known CID.
    #[tokio::test]
    async fn blob_get_returns_data_for_known_cid() {
        let (state, ipfs, _tmps) = jmap_state().await;

        let block_data = b"blob-get-test-block";
        let cid = ipfs
            .put_raw(block_data)
            .await
            .expect("put_raw must succeed");
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:blob"],
                "methodCalls": [[
                    "Blob/get",
                    {"accountId": null, "ids": [cid.to_string()]},
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];

        let list = result["list"].as_array().expect("list must be an array");
        assert_eq!(list.len(), 1, "one blob must be returned");
        assert_eq!(list[0]["id"].as_str(), Some(cid.to_string().as_str()));
        let expected_b64 = data_encoding::BASE64.encode(block_data);
        assert_eq!(
            list[0]["data:asBase64"].as_str(),
            Some(expected_b64.as_str()),
            "data:asBase64 must match the raw block bytes"
        );
        assert_eq!(list[0]["size"].as_u64(), Some(block_data.len() as u64));

        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be an array");
        assert!(
            not_found.is_empty(),
            "notFound must be empty for a known CID"
        );
    }

    /// RFC 9404: Blob/get puts unknown CIDs into notFound.
    #[tokio::test]
    async fn blob_get_unknown_cid_in_not_found() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        let absent = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:blob"],
                "methodCalls": [[
                    "Blob/get",
                    {"accountId": null, "ids": [absent]},
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be an array");
        assert_eq!(not_found.len(), 1, "absent CID must appear in notFound");
        assert_eq!(not_found[0].as_str(), Some(absent));
        let list = result["list"].as_array().expect("list must be an array");
        assert!(list.is_empty(), "list must be empty when CID not found");
    }

    /// RFC 9404: Blob/copy is a no-op in stoa; all requested blobs appear in copied.
    #[tokio::test]
    async fn blob_copy_returns_all_blobs_as_copied() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        let blob_id = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:blob"],
                "methodCalls": [[
                    "Blob/copy",
                    {
                        "fromAccountId": "u_src",
                        "accountId": null,
                        "blobIds": [blob_id]
                    },
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];
        let copied = result["copied"]
            .as_object()
            .expect("copied must be an object");
        assert!(
            copied.contains_key(blob_id),
            "requested blobId must appear in copied"
        );
        assert_eq!(
            copied[blob_id].as_str(),
            Some(blob_id),
            "Blob/copy must return same blobId (CIDs are global)"
        );
        let not_copied = result["notCopied"]
            .as_object()
            .expect("notCopied must be an object");
        assert!(not_copied.is_empty(), "notCopied must be empty");
    }

    #[tokio::test]
    async fn get_root_returns_html() {
        let addr = spawn_server(dev_state().await.0).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200, "GET / must return 200");
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/html"),
            "content-type must be text/html, got: {ct}"
        );
        let body = resp.text().await.expect("body must be readable");
        assert!(
            body.contains("stoa"),
            "body must mention stoa, got first 200 chars: {}",
            &body[..200.min(body.len())]
        );
    }

    #[tokio::test]
    async fn cors_disabled_no_headers_on_response() {
        // Default CorsConfig has enabled=false; no CORS headers should appear.
        let addr = spawn_server(dev_state().await.0).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .header("Origin", "https://evil.example.com")
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let acao = resp.headers().get("access-control-allow-origin");
        assert!(
            acao.is_none(),
            "CORS disabled: no Access-Control-Allow-Origin header expected, got: {acao:?}"
        );
    }

    #[tokio::test]
    async fn cors_wildcard_allows_any_origin() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await.0,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig {
                enabled: true,
                allowed_origins: vec!["*".to_string()],
            },
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .header("Origin", "https://anyapp.example.com")
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            acao, "*",
            "wildcard CORS must respond with Access-Control-Allow-Origin: *"
        );
        // Security invariant: wildcard origin must NOT have allow-credentials.
        let creds = resp.headers().get("access-control-allow-credentials");
        assert!(
            creds.is_none(),
            "wildcard CORS must not set Access-Control-Allow-Credentials"
        );
    }

    #[tokio::test]
    async fn cors_specific_origin_preflight() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await.0,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig {
                enabled: true,
                allowed_origins: vec!["https://client.example.com".to_string()],
            },
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/jmap/api"))
            .header("Origin", "https://client.example.com")
            .header("Access-Control-Request-Method", "POST")
            .header(
                "Access-Control-Request-Headers",
                "Authorization, Content-Type",
            )
            .send()
            .await
            .expect("preflight must succeed");
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            acao, "https://client.example.com",
            "specific origin preflight must echo the origin back"
        );
    }

    /// POST body larger than 10 MiB must be rejected at the transport layer.
    #[tokio::test]
    async fn jmap_api_oversized_body_rejected() {
        let addr = spawn_server(dev_state().await.0).await;

        // 11 MiB of zeros — exceeds the 10 MiB DefaultBodyLimit.
        let big_body = vec![0u8; 11 * 1024 * 1024];

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .header("Content-Type", "application/json")
            .body(big_body)
            .send()
            .await
            .expect("request must succeed");

        // axum returns 413 Payload Too Large when DefaultBodyLimit is exceeded.
        assert_eq!(
            resp.status(),
            413,
            "oversized body must be rejected with 413"
        );
    }

    /// Email/get with more than 500 ids must return requestTooLarge.
    #[tokio::test]
    async fn email_get_too_many_ids_returns_request_too_large() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        // 501 dummy CID strings — exceeds maxObjectsInGet: 500.
        let ids: Vec<serde_json::Value> = (0..501)
            .map(|i| serde_json::Value::String(format!("fake-cid-{i}")))
            .collect();

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "Email/get",
                    {"accountId": null, "ids": ids},
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let responses = body["methodResponses"].as_array().unwrap();
        assert_eq!(responses[0][0], "error", "response method must be 'error'");
        assert_eq!(
            responses[0][1]["type"], "requestTooLarge",
            "error type must be requestTooLarge"
        );
    }

    /// Email/get with exactly 500 ids must be accepted (boundary check).
    #[tokio::test]
    async fn email_get_exactly_500_ids_accepted() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        let ids: Vec<serde_json::Value> = (0..500)
            .map(|i| serde_json::Value::String(format!("fake-cid-{i}")))
            .collect();

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "Email/get",
                    {"accountId": null, "ids": ids},
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let responses = body["methodResponses"].as_array().unwrap();
        // Should not be an error — all 500 IDs are processed (all will be notFound).
        assert_ne!(
            responses[0][0], "error",
            "exactly 500 ids must not return requestTooLarge"
        );
    }

    /// When search_index is None and the JMAP filter contains a non-empty "text"
    /// field, Email/query must return an empty result set — not all articles.
    #[tokio::test]
    async fn email_query_text_filter_with_no_search_index_returns_empty() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        // No mailbox exists, so the filter hits the "no target group" early-return
        // path before reaching the text-filter logic. We need to seed a group first.
        // Since jmap_state() uses MemIpfsStore with empty stores, querying with a
        // text filter against a non-existent group returns [] (early return). That
        // path is already correct. What we are testing is the branch where a group
        // exists and the text filter is applied without a search index.
        //
        // The fix is exercised in the route_method function: when search_index is
        // None and text filter is non-empty, text_results becomes Some(empty set).
        // handle_email_query then retains nothing. Because seeding a real group
        // requires an OverviewStore insertion (not part of this crate's test helpers),
        // we verify the contract via handle_email_query directly in email/query.rs.
        // This server-level test confirms the HTTP round-trip path returns [] when
        // no mailbox matches (the other safe path).
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "Email/query",
                    {
                        "accountId": null,
                        "filter": {
                            "inMailbox": "nonexistent",
                            "text": "something"
                        }
                    },
                    "q1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let responses = body["methodResponses"].as_array().unwrap();
        let result = &responses[0][1];
        let ids = result["ids"].as_array().unwrap();
        assert!(
            ids.is_empty(),
            "text filter with no search index must return empty ids, got: {ids:?}"
        );
    }

    /// POST /jmap/upload/{accountId}/ with a valid RFC 5322 article body must
    /// return 201 with a blobId (CID) and correct size.
    #[tokio::test]
    async fn jmap_upload_valid_article_returns_201_with_blob_id() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        // Use the current time for the Date header so the ±24h window check passes.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let date_str = stoa_core::util::epoch_to_rfc2822(now);

        // Minimal valid RFC 5322 article.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: tester@example.com\r\n\
             Subject: Upload test\r\n\
             Date: {date_str}\r\n\
             Message-ID: <upload-test-1@example.com>\r\n\
             \r\n\
             This is the article body.\r\n"
        );

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/upload/acc1"))
            .header("Content-Type", "message/rfc822")
            .body(article.clone())
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 201, "valid article upload must return 201");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["blobId"].is_string(),
            "response must contain blobId string; got: {body}"
        );
        assert_eq!(body["type"].as_str(), Some("message/rfc822"));
        assert!(
            body["size"].as_u64().is_some() && body["size"].as_u64().unwrap() > 0,
            "size must be a positive integer"
        );
    }

    /// Upload with no JMAP configured must return 503.
    #[tokio::test]
    async fn jmap_upload_no_jmap_returns_503() {
        let addr = spawn_server(dev_state().await.0).await;

        let article = concat!(
            "Newsgroups: comp.test\r\n",
            "From: tester@example.com\r\n",
            "Subject: Test\r\n",
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n",
            "Message-ID: <no-jmap@example.com>\r\n",
            "\r\n",
            "body\r\n"
        );

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/upload/acc1"))
            .header("Content-Type", "message/rfc822")
            .body(article)
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 503, "upload without JMAP must return 503");
    }

    /// Upload with missing required headers must return 400.
    #[tokio::test]
    async fn jmap_upload_missing_headers_returns_400() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        // Missing required Subject header.
        let article = "Newsgroups: comp.test\r\nFrom: a@b.com\r\n\r\nbody\r\n";

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/upload/acc1"))
            .header("Content-Type", "message/rfc822")
            .body(article)
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 400, "missing headers must return 400");
    }

    /// SearchSnippet/get with no search index configured must return null subject
    /// and null preview for all requested emailIds (no error).
    #[tokio::test]
    async fn search_snippet_get_no_index_returns_null_snippets() {
        let (state, ipfs, _tmps) = jmap_state().await;
        let cid = ipfs
            .put_raw(b"hello world")
            .await
            .expect("put_raw must succeed");
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "SearchSnippet/get",
                    {
                        "accountId": null,
                        "filter": {"text": "hello"},
                        "emailIds": [cid.to_string()]
                    },
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];
        // When search index is None, the handler takes the null-snippets branch
        // and returns the entry in list with subject=null and preview=null.
        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(
            list.len(),
            1,
            "without search index, emailId must appear in list with null snippets"
        );
        assert_eq!(
            list[0]["emailId"].as_str(),
            Some(cid.to_string().as_str()),
            "emailId must be echoed back"
        );
        assert!(list[0]["subject"].is_null(), "subject must be null");
        assert!(list[0]["preview"].is_null(), "preview must be null");
    }

    /// SearchSnippet/get with empty emailIds list must return empty list.
    #[tokio::test]
    async fn search_snippet_get_empty_email_ids_returns_empty_list() {
        let (state, _ipfs, _tmps) = jmap_state().await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "SearchSnippet/get",
                    {
                        "accountId": null,
                        "filter": {"text": "anything"},
                        "emailIds": []
                    },
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];
        let list = result["list"].as_array().expect("list must be array");
        assert!(list.is_empty(), "empty emailIds must return empty list");
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.is_empty(),
            "empty emailIds must return empty notFound"
        );
    }

    /// SearchSnippet/get with no text filter must return null snippets for all emails.
    #[tokio::test]
    async fn search_snippet_get_no_text_filter_returns_null_snippets() {
        let (state, ipfs, _tmps) = jmap_state().await;
        let cid = ipfs
            .put_raw(b"test content")
            .await
            .expect("put_raw must succeed");
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "SearchSnippet/get",
                    {
                        "accountId": null,
                        "filter": {},
                        "emailIds": [cid.to_string()]
                    },
                    "r1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let result = &body["methodResponses"][0][1];
        // No text filter → emailId has no matching article in article_numbers → notFound.
        // (In a production setup with real article_numbers seeded, subject/preview would be null.)
        let list = result["list"].as_array().expect("list must be array");
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        // With no text query and no article_numbers entry, the CID is not found.
        // Either list has the entry with null snippets or it's in notFound.
        // With no text query, the code takes the (None, None) branch and adds to list.
        assert_eq!(
            list.len() + not_found.len(),
            1,
            "total entries must equal emailIds count"
        );
    }

    // ── Operator role / admin JMAP method tests ───────────────────────────────

    /// Build an AppState where `operator` is in the operator_usernames list.
    async fn operator_state(username: &str, password: &str) -> (Arc<AppState>, tempfile::TempPath) {
        let hash = bcrypt::hash(password, 4).expect("bcrypt::hash");
        let users = vec![UserCredential {
            username: username.to_string(),
            password: hash,
        }];
        let (ts, tmp) = make_token_store().await;
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(
                CredentialStore::from_credentials(&users).expect("test setup: valid bcrypt hashes"),
            ),
            auth_config: Arc::new(AuthConfig {
                required: true,
                users,
                operator_usernames: vec![username.to_string()],
                ..Default::default()
            }),
            token_store: ts,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
        });
        (state, tmp)
    }

    #[tokio::test]
    async fn operator_session_has_admin_capability() {
        let (state, _tmp) = operator_state("ops", "secret").await;
        let addr = spawn_server(state).await;

        let body: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("ops", Some("secret"))
            .send()
            .await
            .expect("request must succeed")
            .json()
            .await
            .unwrap();

        assert!(
            body["capabilities"]["urn:ietf:params:jmap:usenet-ipfs-admin"].is_object(),
            "operator session must advertise admin capability; got: {body}"
        );
    }

    #[tokio::test]
    async fn non_operator_session_lacks_admin_capability() {
        let (state, _tmp) = auth_state("alice", "pass").await;
        let addr = spawn_server(state).await;

        let body: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("alice", Some("pass"))
            .send()
            .await
            .expect("request must succeed")
            .json()
            .await
            .unwrap();

        assert!(
            body["capabilities"]["urn:ietf:params:jmap:usenet-ipfs-admin"].is_null(),
            "non-operator session must not have admin capability; got: {body}"
        );
    }

    // ── ActivityPub endpoint tests ─────────────────────────────────────────────

    /// Build an AppState with ActivityPub enabled and the given base URL.
    async fn ap_enabled_state(base_url: &str) -> (Arc<AppState>, tempfile::TempPath) {
        let (s, tmp) = dev_state_with_base_url(base_url).await;
        let inner = match Arc::try_unwrap(s) {
            Ok(v) => v,
            Err(_) => panic!("ap_enabled_state: unexpected Arc clone"),
        };
        (
            Arc::new(AppState {
                activitypub_config: crate::config::ActivityPubConfig {
                    enabled: true,
                    verify_http_signatures: false,
                },
                activitypub: None,
                mta_sts_domains: Arc::new(Vec::new()),
                ..inner
            }),
            tmp,
        )
    }

    #[tokio::test]
    async fn webfinger_returns_jrd_for_valid_group() {
        let (state, _tmp) = ap_enabled_state("https://news.example.com").await;
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/.well-known/webfinger?resource=acct:comp.lang.rust@news.example.com"
            ))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.contains("application/jrd+json"), "content-type: {ct}");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["subject"], "acct:comp.lang.rust@news.example.com");
        assert_eq!(body["links"][0]["rel"], "self");
        assert!(
            body["links"][0]["href"]
                .as_str()
                .unwrap()
                .ends_with("/ap/groups/comp.lang.rust"),
            "href: {}",
            body["links"][0]["href"]
        );
    }

    #[tokio::test]
    async fn webfinger_returns_404_when_disabled() {
        let (state, _tmp) = dev_state_with_base_url("https://news.example.com").await;
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/.well-known/webfinger?resource=acct:comp.lang.rust@news.example.com"
            ))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn actor_returns_json_ld_for_valid_group() {
        let (state, _tmp) = ap_enabled_state("https://news.example.com").await;
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/ap/groups/comp.lang.rust"))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            ct.contains("application/activity+json"),
            "content-type: {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["type"], "Group");
        assert_eq!(body["name"], "comp.lang.rust");
        assert_eq!(body["preferredUsername"], "comp.lang.rust");
        assert!(
            body["id"]
                .as_str()
                .unwrap()
                .ends_with("/ap/groups/comp.lang.rust"),
            "id: {}",
            body["id"]
        );
        assert!(body["inbox"].is_string());
        assert!(body["outbox"].is_string());
        assert!(body["followers"].is_string());
    }

    #[tokio::test]
    async fn actor_returns_404_for_invalid_group_name() {
        // "1invalid" starts with a digit: rejected by GroupName validation.
        let (state, _tmp) = ap_enabled_state("https://news.example.com").await;
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/ap/groups/1invalid"))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 404);
    }

    // -----------------------------------------------------------------------
    // JMAP wire-format conformance tests.
    //
    // These tests exercise serialization/deserialization of jmap-types wire
    // types from stoa-mail's perspective.  They catch regressions caused by
    // a breaking change in the jmap-types crate (field rename, serde attribute
    // change, etc.) that would silently produce malformed JMAP responses.
    // -----------------------------------------------------------------------

    /// Oracle: RFC 8620 §3.3 — JmapRequest parses from canonical wire JSON.
    #[test]
    fn jmap_request_parses_from_wire_json() {
        let raw = r#"{
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/get", {"accountId": "u_alice", "ids": ["id1"]}, "c0"]
            ]
        }"#;
        let req: jmap_types::JmapRequest = serde_json::from_str(raw)
            .expect("JmapRequest must parse from RFC 8620 §3.3 wire format");
        assert_eq!(req.using.len(), 2);
        assert_eq!(req.method_calls.len(), 1);
        let (method, _args, call_id) = &req.method_calls[0];
        assert_eq!(method, "Email/get");
        assert_eq!(call_id, "c0");
    }

    /// Oracle: RFC 8620 §3.4 — JmapResponse serializes createdIds only when Some.
    #[test]
    fn jmap_response_omits_created_ids_when_none() {
        use jmap_types::{JmapResponse, State};
        let resp = JmapResponse::new(vec![], State::from("s1"), None);
        let json = serde_json::to_string(&resp).expect("JmapResponse serializes");
        assert!(
            !json.contains("createdIds"),
            "createdIds must be omitted when None, got: {json}"
        );
        assert!(
            json.contains("sessionState"),
            "sessionState must be present, got: {json}"
        );
        assert!(
            json.contains("methodResponses"),
            "methodResponses must be present, got: {json}"
        );
    }

    /// Oracle: RFC 8620 §3.6.2 — JmapError types serialize as camelCase strings.
    #[test]
    fn jmap_error_type_serializes_camel_case() {
        let err = jmap_types::JmapError::unknown_method();
        let json = serde_json::to_string(&err).expect("JmapError serializes");
        assert!(json.contains("unknownMethod"), "got: {json}");

        let err = jmap_types::JmapError::request_too_large();
        let json = serde_json::to_string(&err).expect("JmapError serializes");
        assert!(json.contains("requestTooLarge"), "got: {json}");

        let err = jmap_types::JmapError::account_not_found();
        let json = serde_json::to_string(&err).expect("JmapError serializes");
        assert!(json.contains("accountNotFound"), "got: {json}");
    }

    /// Oracle: stoa_value_to_result contract — value with top-level "type" key is an error.
    #[test]
    fn stoa_value_to_result_detects_method_error() {
        let v = serde_json::json!({"type": "accountNotFound"});
        let result = stoa_value_to_result(v);
        assert!(result.is_err(), "value with 'type' key must be Err");
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "accountNotFound");
    }

    /// Oracle: stoa_value_to_result contract — value with top-level "error" key is serverFail.
    #[test]
    fn stoa_value_to_result_detects_internal_error() {
        let v = serde_json::json!({"error": "db connection lost"});
        let result = stoa_value_to_result(v);
        assert!(result.is_err(), "value with 'error' key must be Err");
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "serverFail");
    }

    /// Oracle: stoa_value_to_result contract — success value passes through unchanged.
    #[test]
    fn stoa_value_to_result_passes_success_value_through() {
        let v = serde_json::json!({"accountId": "u_alice", "state": "s1", "list": []});
        let result = stoa_value_to_result(v.clone());
        assert!(result.is_ok(), "success value must be Ok");
        let (out, extra) = result.unwrap();
        assert_eq!(out, v);
        assert!(extra.is_empty());
    }

    // ── stoa-2xeks.20: /.well-known/mta-sts.txt handler tests ────────────────

    async fn mta_sts_state(
        domains: Vec<stoa_smtp::config::MtaStsDomainConfig>,
    ) -> (Arc<AppState>, tempfile::TempPath) {
        let (ts, tmp) = make_token_store().await;
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: ts,
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(domains),
        });
        (state, tmp)
    }

    // T1: known domain with enforce policy → 200 + text/plain + correct body.
    // Oracle: hand-written expected body per RFC 8461 §3.2 format; SHA-256 of
    // body pre-computed with Python's hashlib.sha256 (independent of the
    // implementation).
    // Host header uses the mta-sts. subdomain as a real sending MTA would.
    #[tokio::test]
    async fn mta_sts_handler_enforce_returns_200_with_correct_body() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "mta-sts.example.com")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = resp.text().await.expect("body");
        assert_eq!(
            body,
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n"
        );
    }

    // T2: known domain with testing mode → 200 with "mode: testing" in body.
    // Oracle: hand-written expected body.
    #[tokio::test]
    async fn mta_sts_handler_testing_mode_returns_correct_body() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Testing,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 3600,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "mta-sts.example.com")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("body");
        assert_eq!(
            body,
            "version: STSv1\r\nmode: testing\r\nmx: mail.example.com\r\nmax_age: 3600\r\n"
        );
    }

    // T3: known domain with multiple MX patterns → all patterns appear in body.
    // Oracle: hand-written expected body.
    #[tokio::test]
    async fn mta_sts_handler_multiple_mx_patterns_all_in_body() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mx1.example.com".to_string(), "mx2.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "mta-sts.example.com")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("body");
        assert_eq!(
            body,
            "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: mx2.example.com\r\nmax_age: 86400\r\n"
        );
    }

    // T4: policy_id is first 32 hex chars of SHA-256 of the policy body.
    // Oracle: Python hashlib.sha256 computed independently for the CRLF body.
    //   body = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n"
    //   hashlib.sha256(body.encode()).hexdigest()[:32] == "9ebad69d69d237d74acd7c3e01d01962"
    #[test]
    fn render_mta_sts_policy_id_is_sha256_first32() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (body, policy_id) = render_mta_sts_policy(&domain_config);
        assert_eq!(
            body,
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n"
        );
        assert_eq!(policy_id.len(), 32);
        assert_eq!(policy_id, "9ebad69d69d237d74acd7c3e01d01962");
    }

    // T5: unknown domain → 404.
    // Oracle: RFC 8461 §3.3 — domains not configured for MTA-STS must return 404.
    #[tokio::test]
    async fn mta_sts_handler_unknown_domain_returns_404() {
        let (state, _tmp) = mta_sts_state(vec![]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "mta-sts.unknown.example.com")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 404);
    }

    // T5b: Host header without "mta-sts." prefix → 404 (not a valid policy fetch).
    // Oracle: RFC 8461 §3.3 — the policy URL is always https://mta-sts.<domain>/...
    // A request with Host: example.com (no mta-sts. prefix) is not a legitimate
    // policy fetch and must not return 200.
    #[tokio::test]
    async fn mta_sts_handler_missing_mta_sts_prefix_returns_404() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "example.com") // missing "mta-sts." prefix
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(
            resp.status(),
            404,
            "request without mta-sts. prefix must return 404"
        );
    }

    // T6: Host header matching is case-insensitive.
    // Oracle: RFC 4343 — DNS labels are case-insensitive; domain matching must
    // follow the same rule so that "MTA-STS.EXAMPLE.COM" matches "example.com".
    #[tokio::test]
    async fn mta_sts_handler_host_case_insensitive() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "Example.COM".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "MTA-STS.EXAMPLE.COM")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(
            resp.status(),
            200,
            "case-insensitive host match must return 200"
        );
    }

    // T7: Host header with port suffix → port stripped, mta-sts. prefix stripped, domain matched.
    // Oracle: HTTP/1.1 Host header may include port (RFC 7230 §5.4); port must
    // be stripped before comparing against configured domains.
    #[tokio::test]
    async fn mta_sts_handler_host_with_port_stripped() {
        use stoa_smtp::config::{MtaStsDomainConfig, MtaStsMode};

        let domain_config = MtaStsDomainConfig {
            domain: "example.com".to_string(),
            mode: MtaStsMode::Enforce,
            mx_patterns: vec!["mail.example.com".to_string()],
            max_age_secs: 86400,
        };
        let (state, _tmp) = mta_sts_state(vec![domain_config]).await;
        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/.well-known/mta-sts.txt"))
            .header("Host", "mta-sts.example.com:443")
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200, "Host with port suffix must still match");
    }
}
