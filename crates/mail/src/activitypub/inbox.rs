//! ActivityPub inbox handler — Follow / Undo{Follow} lifecycle.
//!
//! Receives POST requests to `/ap/groups/{group_name}/inbox`.
//! Processes `Follow` and `Undo{Follow}` activities:
//!
//! - **Follow**: stores the follower, then sends an asynchronous `Accept{Follow}`
//!   back to the actor's inbox.
//! - **Undo{Follow}**: removes the follower.
//!
//! Inbound HTTP Signature verification is applied to all activity types when
//! `verify_http_signatures = true` is set in the ActivityPub config.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{info, warn};

/// Maximum response body size for actor document fetches (64 KiB).
const ACTOR_FETCH_MAX_BYTES: usize = 64 * 1024;

use crate::server::AppState;

/// POST `/ap/groups/{group_name}/inbox`
pub async fn inbox_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_name): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ap_state = match &state.activitypub {
        Some(s) => Arc::clone(s),
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Parse JSON body.
    let activity: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let activity_type = activity["type"].as_str().unwrap_or("");

    // HTTP Signature verification — applied to all activity types.
    if state.activitypub_config.verify_http_signatures {
        // Use the route path as the request path.
        let path = format!("/ap/groups/{}/inbox", group_name);
        match crate::activitypub::inbound::verify_http_signature(
            "post",
            &path,
            &headers,
            &body,
            &ap_state.http_client,
            &ap_state.pub_key_cache,
        )
        .await
        {
            Ok(actor) => {
                info!(group = %group_name, actor = %actor, "HTTP Signature verified");
            }
            Err(e) => {
                warn!(group = %group_name, error = %e, "HTTP Signature verification failed");
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    }

    match activity_type {
        "Follow" => handle_follow(&ap_state, &state.base_url, &group_name, &activity).await,
        "Undo" => {
            let inner = &activity["object"];
            if inner["type"].as_str() == Some("Follow") {
                handle_undo_follow(&ap_state, &group_name, inner).await
            } else {
                StatusCode::ACCEPTED.into_response()
            }
        }
        "Create" => handle_create(&ap_state, &state, &group_name, &activity).await,
        other => {
            info!(
                group = %group_name,
                activity_type = %other,
                "ActivityPub inbox: unhandled activity type"
            );
            StatusCode::ACCEPTED.into_response()
        }
    }
}

/// Fetch the `inbox` URL from an ActivityPub actor document.
///
/// Returns the `inbox` field value from the fetched actor JSON.
/// Falls back to `{actor_url}/inbox` if the fetch fails or the field is absent,
/// logging a warning so operators know the fallback was used.
///
/// Enforces a [`ACTOR_FETCH_MAX_BYTES`] body size cap to prevent a malicious
/// actor server from exhausting memory with an oversized response.
async fn fetch_actor_inbox(http_client: &reqwest::Client, actor_url: &str) -> String {
    match http_client
        .get(actor_url)
        .header("Accept", "application/activity+json, application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            // Reject up front if the server advertises a body larger than our cap.
            if resp
                .content_length()
                .map(|n| n > ACTOR_FETCH_MAX_BYTES as u64)
                .unwrap_or(false)
            {
                warn!(
                    actor = %actor_url,
                    "actor document Content-Length exceeds {ACTOR_FETCH_MAX_BYTES} bytes; using fallback inbox URL"
                );
                return format!("{}/inbox", actor_url);
            }

            // Fetch body with a hard cap so a lying server cannot OOM us.
            let buf = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!(actor = %actor_url, error = %e, "error reading actor response body; using fallback inbox URL");
                    return format!("{}/inbox", actor_url);
                }
            };
            if buf.len() > ACTOR_FETCH_MAX_BYTES {
                warn!(
                    actor = %actor_url,
                    "actor document body exceeded {ACTOR_FETCH_MAX_BYTES} bytes; using fallback inbox URL"
                );
                return format!("{}/inbox", actor_url);
            }

            match serde_json::from_slice::<serde_json::Value>(&buf) {
                Ok(actor) => {
                    if let Some(inbox) = actor["inbox"].as_str() {
                        return inbox.to_string();
                    }
                    warn!(actor = %actor_url, "actor document has no inbox field; using fallback");
                }
                Err(e) => {
                    warn!(actor = %actor_url, error = %e, "failed to parse actor JSON; using fallback inbox URL");
                }
            }
        }
        Ok(resp) => {
            warn!(actor = %actor_url, status = %resp.status(), "actor fetch returned error; using fallback inbox URL");
        }
        Err(e) => {
            warn!(actor = %actor_url, error = %e, "failed to fetch actor document; using fallback inbox URL");
        }
    }
    // Fallback: derive inbox by appending /inbox (works for Mastodon-style actors).
    format!("{}/inbox", actor_url)
}

async fn handle_follow(
    ap_state: &Arc<crate::activitypub::ActivityPubState>,
    base_url: &str,
    group_name: &str,
    activity: &Value,
) -> Response {
    let actor_url = match activity["actor"].as_str() {
        Some(u) => u.to_string(),
        None => {
            warn!(group = %group_name, "Follow activity missing actor field");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let inbox_url = fetch_actor_inbox(&ap_state.http_client, &actor_url).await;

    if let Err(e) = ap_state
        .follower_store
        .add(group_name, &actor_url, &inbox_url)
        .await
    {
        warn!(group = %group_name, actor = %actor_url, error = %e, "failed to store follower");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    info!(group = %group_name, actor = %actor_url, "ActivityPub: new follower");

    // Send Accept{Follow} asynchronously — fire and forget.
    let ap_state = Arc::clone(ap_state);
    let activity_id = activity["id"].as_str().unwrap_or("").to_string();
    let group_actor_url = format!("{}/ap/groups/{}", base_url, group_name);
    tokio::spawn(async move {
        deliver_accept(
            &ap_state,
            &group_actor_url,
            &actor_url,
            &activity_id,
            &inbox_url,
        )
        .await;
    });

    StatusCode::ACCEPTED.into_response()
}

async fn handle_undo_follow(
    ap_state: &Arc<crate::activitypub::ActivityPubState>,
    group_name: &str,
    follow_activity: &Value,
) -> Response {
    let actor_url = match follow_activity["actor"].as_str() {
        Some(u) => u,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(e) = ap_state.follower_store.remove(group_name, actor_url).await {
        warn!(group = %group_name, actor = %actor_url, error = %e, "failed to remove follower");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    info!(group = %group_name, actor = %actor_url, "ActivityPub: follower removed");
    StatusCode::ACCEPTED.into_response()
}

/// Deliver an Accept{Follow} activity to the remote actor's inbox.
async fn deliver_accept(
    ap_state: &crate::activitypub::ActivityPubState,
    group_actor_url: &str,
    actor_url: &str,
    follow_activity_id: &str,
    remote_inbox_url: &str,
) {
    let accept = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Accept",
        "actor": group_actor_url,
        "object": {
            "type": "Follow",
            "id": follow_activity_id,
            "actor": actor_url,
            "object": group_actor_url
        }
    });
    let body = match serde_json::to_vec(&accept) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize Accept activity");
            return;
        }
    };

    // Build HTTP Signature if a key is available.
    let (host, path) = super::extract_host_path(remote_inbox_url);
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let mut req = ap_state
        .http_client
        .post(remote_inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Date", &date)
        .header("Host", &host);

    if let Some(key) = &ap_state.key {
        req = req.header("Signature", key.sign_post(&host, &path, &date, &body));
    }

    match req.body(body).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(inbox = %remote_inbox_url, "delivered Accept{{Follow}}");
        }
        Ok(resp) => {
            warn!(inbox = %remote_inbox_url, status = %resp.status(), "Accept delivery returned error status");
        }
        Err(e) => {
            warn!(inbox = %remote_inbox_url, error = %e, "Accept delivery failed");
        }
    }
}

async fn handle_create(
    ap_state: &Arc<crate::activitypub::ActivityPubState>,
    state: &Arc<crate::server::AppState>,
    group_name: &str,
    activity: &Value,
) -> Response {
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // Only followers may inject content.  A valid HTTP Signature confirms key
    // ownership but not whether the actor is a follower of this group.
    let actor_url = activity["actor"].as_str().unwrap_or("");
    if actor_url.is_empty() {
        warn!(group = %group_name, "ActivityPub Create: missing actor field");
        return StatusCode::BAD_REQUEST.into_response();
    }
    match ap_state
        .follower_store
        .is_follower(group_name, actor_url)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                group = %group_name,
                actor = %actor_url,
                "ActivityPub Create rejected: actor is not a follower"
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        Err(e) => {
            warn!(group = %group_name, error = %e, "ActivityPub Create: follower lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let activity_id = activity["id"].as_str().unwrap_or("").to_string();
    let note_id = activity["object"]["id"].as_str().unwrap_or("").to_string();

    // Deduplication key: activity id → note id → SHA-256 of activity JSON.
    // Dedup always fires regardless of which fields are present.
    // Dedup priority: activity id → note id → SHA-256 of the Note object.
    // Hashing the Note (not the full Create wrapper) ensures re-deliveries of
    // the same Note in different wrapper activities are correctly deduplicated.
    let dedup_key = if !activity_id.is_empty() {
        activity_id.clone()
    } else if !note_id.is_empty() {
        note_id.clone()
    } else {
        let note_bytes = serde_json::to_vec(&activity["object"]).unwrap_or_default();
        let hash = Sha256::digest(&note_bytes);
        format!("sha256:{}", HEXLOWER.encode(&hash))
    };

    match ap_state.received_store.record_if_new(&dedup_key).await {
        Ok(false) => {
            return StatusCode::ACCEPTED.into_response();
        }
        Ok(true) => {}
        Err(e) => {
            warn!(dedup_key = %dedup_key, error = %e, "dedup store error; continuing");
        }
    }

    let note = &activity["object"];
    let (message_id, newsgroups, article_bytes) =
        crate::activitypub::inbound::note_to_article(note, group_name, &state.base_url);

    let jmap = match &state.jmap {
        Some(j) => Arc::clone(j),
        None => {
            warn!(group = %group_name, "ActivityPub Create received but JMAP stores unavailable");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let hlc_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    match stoa_reader::post::ipfs_write::write_ipld_article_to_ipfs(
        jmap.ipfs.as_ref(),
        &jmap.msgid_map,
        &article_bytes,
        &message_id,
        newsgroups,
        hlc_timestamp,
        vec![], // ActivityPub-ingested articles are not signed by this operator
    )
    .await
    {
        Ok(cid) => {
            info!(
                group = %group_name,
                cid = %cid,
                message_id = %message_id,
                "ActivityPub: injected inbound Note as article"
            );
        }
        Err(e) => {
            warn!(
                group = %group_name,
                message_id = %message_id,
                error = %e.text,
                "ActivityPub: failed to write Note to IPFS"
            );
        }
    }

    StatusCode::ACCEPTED.into_response()
}
