//! E2E integration test: full JMAP session against an in-process mail server.
//!
//! Seeds one article as a proper DAG-CBOR ArticleRootNode block, starts the
//! mail server in-process, then verifies Mailbox/get → Email/query →
//! Email/get works end-to-end.

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use stoa_core::ipld::root_node::{ArticleMetadata, ArticleRootNode};
use stoa_mail::{
    server::{build_router, AppState, JmapStores},
    store::new_sqlx_mail_store,
    token_store::TokenStore,
};
use stoa_reader::{
    post::ipfs_write::{IpfsBlockStore, IpfsWriteError},
    store::{
        article_numbers::ArticleNumberStore,
        overview::{extract_overview, OverviewStore},
    },
};
use tokio::net::TcpListener;

// ── In-memory IPFS store using DAG-CBOR codec (0x71) ─────────────────────────

struct MemIpfs {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemIpfs {
    fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(Default::default()),
        }
    }
}

#[async_trait]
impl IpfsBlockStore for MemIpfs {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.blocks.write().await.insert(cid.to_bytes(), data);
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.blocks
            .read()
            .await
            .get(&cid.to_bytes())
            .cloned()
            .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
    }
}

// ── Pool helpers ───────────────────────────────────────────────────────────────

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

async fn make_mail_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_mail::migrations::run_migrations(&url)
        .await
        .expect("mail migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("mail pool");
    (pool, tmp)
}

async fn make_core_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url)
        .await
        .expect("core migrations");
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .expect("core pool");
    (pool, tmp)
}

// ── Test ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn jmap_session_e2e() {
    let newsgroup = "comp.test";
    let subject = "E2E JMAP Test Article";
    let message_id = "<e2e-jmap@test.example>";
    let from = "test@example.com";
    let date = "Mon, 20 Apr 2026 12:00:00 +0000";

    // Build stores.
    let ipfs = Arc::new(MemIpfs::new());
    let (reader_pool, _reader_tmp) = make_reader_pool().await;
    let (mail_pool, _mail_tmp) = make_mail_pool().await;
    let (core_pool, _core_tmp) = make_core_pool().await;

    let article_numbers = Arc::new(ArticleNumberStore::new(reader_pool.clone()));
    let overview_store = Arc::new(OverviewStore::new(reader_pool));
    let mail_pool_arc = Arc::new(mail_pool);

    let token_store = Arc::new(TokenStore::new(Arc::clone(&mail_pool_arc)));

    // Build sub-block CIDs (placeholder raw blocks — only their identity matters
    // for the root node structure; they don't need to be retrievable for this test).
    let header_cid = {
        let digest = Code::Sha2_256.digest(b"e2e-header-block");
        Cid::new_v1(0x71, digest)
    };
    let body_cid = {
        let digest = Code::Sha2_256.digest(b"e2e-body-block");
        Cid::new_v1(0x71, digest)
    };

    // Build an ArticleRootNode and encode as DAG-CBOR so Email/get can decode it.
    let root = ArticleRootNode {
        schema_version: 1,
        header_cid,
        header_map_cid: None,
        body_cid,
        mime_cid: None,
        metadata: ArticleMetadata {
            message_id: message_id.to_string(),
            newsgroups: vec![newsgroup.to_string()],
            hlc_timestamp: 1_745_150_400_000,
            operator_signature: vec![],
            byte_count: 256,
            line_count: 1,
            content_type_summary: "text/plain".to_string(),
        },
    };
    let cbor = serde_ipld_dagcbor::to_vec(&root).expect("DAG-CBOR encode must succeed");
    let cid = ipfs.put_raw(&cbor).await.expect("put_raw must succeed");

    // Assign article number in article_numbers store.
    let article_number = article_numbers
        .assign_number(newsgroup, &cid)
        .await
        .expect("assign_number must succeed");

    // Build and insert overview record.
    let header_text = format!(
        "Newsgroups: {newsgroup}\r\nFrom: {from}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {message_id}\r\n"
    );
    let body_text = b"E2E test body.\r\n";
    let mut overview = extract_overview(header_text.as_bytes(), body_text);
    overview.article_number = article_number;
    overview_store
        .insert(newsgroup, &overview)
        .await
        .expect("insert overview must succeed");

    // Start mail server with stores.
    let mail_store = new_sqlx_mail_store(Arc::clone(&mail_pool_arc));
    mail_store
        .provision_mailboxes()
        .await
        .expect("provision_mailboxes must succeed at startup");
    let special_mailboxes = Arc::new(
        mail_store
            .list_mailboxes()
            .await
            .expect("list_mailboxes must succeed after provision"),
    );
    let jmap_stores = Arc::new(JmapStores {
        ipfs: Arc::clone(&ipfs) as Arc<dyn IpfsBlockStore>,
        msgid_map: Arc::new(stoa_core::msgid_map::MsgIdMap::new(core_pool)),
        article_numbers: Arc::clone(&article_numbers),
        overview_store: Arc::clone(&overview_store),
        search_index: None,
        outbound_mailer: None,
        mail_store,
        special_mailboxes,
    });
    let state = Arc::new(AppState {
        start_time: std::time::Instant::now(),
        jmap: Some(jmap_stores),
        jmap_dispatcher: None,
        credential_store: Arc::new(stoa_auth::CredentialStore::empty()),
        auth_config: Arc::new(stoa_auth::AuthConfig::default()),
        token_store,
        oidc_store: None,
        base_url: "http://localhost".to_string(),
        cors: stoa_mail::config::CorsConfig::default(),
        slow_jmap_threshold_ms: 0,
        activitypub_config: Default::default(),
        activitypub: None,
        mta_sts_domains: Arc::new(Vec::new()),
        db_pool: None,
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    // 1. GET /jmap/session — also extract the canonical accountId
    let resp = client
        .get(format!("{base}/jmap/session"))
        .send()
        .await
        .expect("session request must succeed");
    assert_eq!(resp.status(), 200, "session endpoint must return 200");
    let session: serde_json::Value = resp.json().await.unwrap();
    assert!(
        session.get("capabilities").is_some(),
        "session must have capabilities"
    );
    // Extract the accountId the server issued for this principal so all
    // subsequent method calls use the canonical value (u_anonymous in dev mode).
    let account_id = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("primaryAccounts must contain urn:ietf:params:jmap:mail")
        .to_string();

    // 2. Mailbox/get — expect comp.test mailbox to be present
    let req_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/get", {"accountId": account_id, "ids": null}, "c1"]]
    });
    let resp = client
        .post(format!("{base}/jmap/api"))
        .json(&req_body)
        .send()
        .await
        .expect("Mailbox/get request must succeed");
    assert_eq!(resp.status(), 200, "Mailbox/get must return 200");
    let jmap_resp: serde_json::Value = resp.json().await.unwrap();
    let method_responses = jmap_resp["methodResponses"].as_array().unwrap();
    assert_eq!(
        method_responses[0][0].as_str().unwrap(),
        "Mailbox/get",
        "response method name must be Mailbox/get"
    );
    let mailbox_list = method_responses[0][1]["list"].as_array().unwrap();
    assert!(
        !mailbox_list.is_empty(),
        "Mailbox/get must return at least one mailbox"
    );
    // Special folders now appear in the list too; find comp.test by name.
    let mailbox_id = mailbox_list
        .iter()
        .find(|m| m["name"].as_str() == Some(newsgroup))
        .expect("comp.test mailbox must be present in Mailbox/get list")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. Email/query — expect the seeded article to appear
    let req_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", {"accountId": account_id, "filter": {"inMailbox": mailbox_id}}, "c2"]]
    });
    let resp = client
        .post(format!("{base}/jmap/api"))
        .json(&req_body)
        .send()
        .await
        .expect("Email/query request must succeed");
    assert_eq!(resp.status(), 200, "Email/query must return 200");
    let jmap_resp: serde_json::Value = resp.json().await.unwrap();
    let method_responses = jmap_resp["methodResponses"].as_array().unwrap();
    assert_eq!(
        method_responses[0][0].as_str().unwrap(),
        "Email/query",
        "response method name must be Email/query"
    );
    let ids = method_responses[0][1]["ids"].as_array().unwrap();
    assert!(
        !ids.is_empty(),
        "Email/query must return at least one email id"
    );
    let email_id = ids[0].as_str().unwrap().to_string();

    // 4. Email/get — verify full round-trip through DAG-CBOR ArticleRootNode
    let req_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", {"accountId": account_id, "ids": [email_id]}, "c3"]]
    });
    let resp = client
        .post(format!("{base}/jmap/api"))
        .json(&req_body)
        .send()
        .await
        .expect("Email/get request must succeed");
    assert_eq!(resp.status(), 200, "Email/get must return 200");
    let jmap_resp: serde_json::Value = resp.json().await.unwrap();
    let method_responses = jmap_resp["methodResponses"].as_array().unwrap();
    assert_eq!(
        method_responses[0][0].as_str().unwrap(),
        "Email/get",
        "response method name must be Email/get"
    );
    let email_list = method_responses[0][1]["list"].as_array().unwrap();
    assert!(!email_list.is_empty(), "Email/get must return the email");
    assert_eq!(
        email_list[0]["id"].as_str().unwrap(),
        &email_id,
        "returned email id must match the requested id"
    );
    let not_found = method_responses[0][1]["notFound"].as_array().unwrap();
    assert!(
        not_found.is_empty(),
        "notFound must be empty for a valid CID"
    );
}
