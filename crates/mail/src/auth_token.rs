use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::server::{AppState, AuthenticatedUser, DEV_USERNAME};

#[derive(Deserialize)]
pub struct TokenIssueRequest {
    pub label: Option<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Serialize)]
pub struct TokenIssueResponse {
    pub token: String,
    pub id: String,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub struct TokenListEntry {
    pub id: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// POST /jmap/auth/token
///
/// Issues a new bearer token for the authenticated user.
/// The raw token is returned once in the response and cannot be retrieved again.
///
/// In dev mode (no auth required) the middleware does not inject `AuthenticatedUser`.
/// When no user identity is present we assign the canonical dev username `"dev"` rather
/// than an empty string, which would produce a token with no meaningful owner.
pub async fn issue_token(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    body: Option<Json<TokenIssueRequest>>,
) -> impl IntoResponse {
    let username = user
        .map(|Extension(u)| u.0)
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEV_USERNAME.to_string());

    let (label, expires_in_days) = match body {
        Some(Json(req)) => (req.label, req.expires_in_days),
        None => (None, None),
    };

    match state
        .token_store
        .issue(&username, label, expires_in_days)
        .await
    {
        Ok((token, id, expires_at)) => (
            StatusCode::CREATED,
            Json(
                serde_json::to_value(TokenIssueResponse {
                    token,
                    id,
                    expires_at,
                })
                .expect("TokenIssueResponse is always JSON-serializable"),
            ),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to issue token"})),
        ),
    }
}

/// GET /jmap/auth/token
///
/// Lists all tokens for the authenticated user (no raw token, no hash).
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
) -> impl IntoResponse {
    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| DEV_USERNAME.to_string());
    match state.token_store.list(&username).await {
        Ok(tokens) => {
            let entries: Vec<TokenListEntry> = tokens
                .into_iter()
                .map(|t| TokenListEntry {
                    id: t.id,
                    label: t.label,
                    created_at: t.created_at,
                    expires_at: t.expires_at,
                })
                .collect();
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(entries)
                        .expect("Vec<TokenListEntry> is always JSON-serializable"),
                ),
            )
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to list tokens"})),
        ),
    }
}

/// DELETE /jmap/auth/token/:id
///
/// Revokes the token with `id` if it is owned by the authenticated user.
/// Returns 200 on success, 404 if the token does not exist or is not owned
/// by the caller.
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| DEV_USERNAME.to_string());
    match state.token_store.revoke(&username, &id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"deleted": true}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "token not found"})),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to revoke token"})),
        ),
    }
}
