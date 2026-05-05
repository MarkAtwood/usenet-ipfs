//! JMAP binary upload endpoint (RFC 8620 §7.1).
//!
//! POST /jmap/upload/{accountId}/
//!
//! Accepts a raw RFC 5322 article body, validates required headers, writes
//! the article to IPFS as a proper IPLD block set, and returns a JMAP blob
//! descriptor with the resulting CID as `blobId`.
//!
//! Error mapping:
//! - 400: malformed or missing required headers.
//! - 403: authenticated user does not own the requested accountId.
//! - 413: body exceeds maxSizeUpload (enforced by the DefaultBodyLimit layer).
//! - 503: JMAP stores not configured.

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    Extension,
};
use serde_json::json;
use std::sync::Arc;
use stoa_reader::post::{find_header_boundary, validate_headers::validate_post_headers};

use crate::server::{AppState, AuthenticatedUser};

/// POST /jmap/upload/{accountId}/
pub async fn jmap_upload(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(account_id): Path<String>,
    body: Bytes,
) -> Response<Body> {
    // Verify the caller owns the requested account.
    if let Some(Extension(ref authenticated_user)) = user {
        let expected = format!("u_{}", authenticated_user.0);
        if account_id != expected {
            return json_response(
                StatusCode::FORBIDDEN,
                json!({"type": "forbidden", "description": "accountId does not match authenticated user"}),
            );
        }
    }

    let article_bytes = body.as_ref();

    if article_bytes.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"type": "invalidArticle", "description": "empty body"}),
        );
    }

    // Require JMAP stores.
    let jmap = match state.jmap.as_ref() {
        Some(j) => j,
        None => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"type": "serverUnavailable", "description": "JMAP not configured"}),
            );
        }
    };

    // Locate header/body separator.
    let body_start = match find_header_boundary(article_bytes) {
        Some(pos) => pos,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"type": "invalidArticle", "description": "no header/body separator found"}),
            );
        }
    };

    // Header bytes: everything before the blank-line separator.
    let header_bytes =
        if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
            &article_bytes[..body_start - 4]
        } else if body_start >= 2 {
            &article_bytes[..body_start - 2]
        } else {
            &article_bytes[..0]
        };

    // Validate required RFC 5536 headers.
    if let Err(resp) = validate_post_headers(header_bytes) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"type": "invalidArticle", "description": resp.text}),
        );
    }

    // Extract Message-ID and Newsgroups for the IPLD write.
    let (message_id, newsgroups) = match extract_msgid_newsgroups(header_bytes) {
        Ok(pair) => pair,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"type": "invalidArticle", "description": e}),
            );
        }
    };

    // HLC timestamp: milliseconds since Unix epoch.
    let hlc_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Write article to IPFS as a full IPLD block set.
    let cid = match stoa_reader::post::ipfs_write::write_ipld_article_to_ipfs(
        jmap.ipfs.as_ref(),
        &jmap.msgid_map,
        article_bytes,
        &message_id,
        newsgroups,
        hlc_timestamp,
        vec![], // blob upload path does not go through sign_article
    )
    .await
    {
        Ok(c) => c,
        Err(resp) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"type": "serverFail", "description": resp.text}),
            );
        }
    };

    json_response(
        StatusCode::CREATED,
        json!({
            "accountId": account_id,
            "blobId": cid.to_string(),
            "type": "message/rfc822",
            "size": article_bytes.len(),
        }),
    )
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap()
}

/// Extract `Message-ID` and `Newsgroups` from raw header bytes.
fn extract_msgid_newsgroups(header_bytes: &[u8]) -> Result<(String, Vec<String>), String> {
    let (parsed, _) = mailparse::parse_headers(header_bytes)
        .map_err(|_| "failed to parse article headers".to_string())?;

    let mut message_id: Option<String> = None;
    let mut newsgroups_str: Option<String> = None;

    for hdr in &parsed {
        let key = hdr.get_key().to_ascii_lowercase();
        match key.as_str() {
            "message-id" if message_id.is_none() => {
                message_id = Some(hdr.get_value());
            }
            "newsgroups" if newsgroups_str.is_none() => {
                newsgroups_str = Some(hdr.get_value());
            }
            _ => {}
        }
    }

    let mid = message_id.ok_or_else(|| "missing Message-ID header".to_string())?;
    let ng_raw = newsgroups_str.ok_or_else(|| "missing Newsgroups header".to_string())?;
    let newsgroups: Vec<String> = ng_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if newsgroups.is_empty() {
        return Err("Newsgroups header is empty".to_string());
    }

    Ok((mid, newsgroups))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::State;
    use std::sync::Arc;
    use std::time::Instant;
    use stoa_auth::{AuthConfig, CredentialStore};

    async fn make_dev_state() -> (Arc<AppState>, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            jmap_dispatcher: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: Arc::new(crate::token_store::TokenStore::new(Arc::new(pool))),
            oidc_store: None,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
            slow_jmap_threshold_ms: 0,
            activitypub_config: Default::default(),
            activitypub: None,
            mta_sts_domains: Arc::new(Vec::new()),
            db_pool: None,
        });
        (state, tmp)
    }

    /// Empty body must return 400 (no jmap needed to check this).
    #[tokio::test]
    async fn upload_empty_body_returns_400() {
        let (state, _tmp) = make_dev_state().await;
        let resp = jmap_upload(
            State(state),
            None,
            Path("u_alice".to_string()),
            Bytes::new(),
        )
        .await;
        // Empty body is caught before the JMAP stores check (empty article).
        // Because jmap is None and body is empty, 400 is returned first.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Missing JMAP configuration must return 503.
    #[tokio::test]
    async fn upload_no_jmap_config_returns_503() {
        let article = b"Newsgroups: comp.test\r\nFrom: a@b.com\r\nSubject: Test\r\n\
            Date: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <u1@test>\r\n\r\nbody\r\n";
        let (state, _tmp) = make_dev_state().await;
        let resp = jmap_upload(
            State(state),
            None,
            Path("u_alice".to_string()),
            Bytes::from_static(article),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Wrong account ID for the authenticated user must return 403.
    #[tokio::test]
    async fn upload_wrong_account_returns_403() {
        let (state, _tmp) = make_dev_state().await;
        let user = Some(Extension(AuthenticatedUser("alice".to_string())));
        let resp = jmap_upload(
            State(state),
            user,
            Path("u_bob".to_string()),
            Bytes::from_static(b"anything"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// extract_msgid_newsgroups correctly parses Message-ID and Newsgroups.
    #[test]
    fn extract_msgid_newsgroups_parses_headers() {
        let headers = b"Newsgroups: comp.lang.rust,comp.test\r\nMessage-ID: <abc@example.com>\r\n";
        let (mid, ngs) = extract_msgid_newsgroups(headers).expect("must parse");
        assert_eq!(mid, "<abc@example.com>");
        assert_eq!(ngs, vec!["comp.lang.rust", "comp.test"]);
    }

    /// extract_msgid_newsgroups returns an error when Message-ID is missing.
    #[test]
    fn extract_msgid_newsgroups_missing_msgid_returns_error() {
        let headers = b"Newsgroups: comp.test\r\n";
        let err = extract_msgid_newsgroups(headers).expect_err("must fail");
        assert!(
            err.contains("Message-ID"),
            "error must mention Message-ID; got: {err}"
        );
    }
}
