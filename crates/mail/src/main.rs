use std::{path::PathBuf, sync::Arc, time::Instant};

use stoa_mail::{
    config::{Config, LogFormat},
    server::{build_jmap_dispatcher, AppState, JmapStores},
    token_store::TokenStore,
};
use tracing::{info, warn};

fn parse_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    for arg in args.by_ref() {
        if arg == "--config" {
            match args.next() {
                Some(path) => return PathBuf::from(path),
                None => {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
        }
    }
    eprintln!("error: --config <path> is required");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    sqlx::any::install_default_drivers();
    let start_time = Instant::now();
    let config_path = parse_args();

    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to load config from {}: {}",
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log.level));

    if config.log.format == LogFormat::Json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let addr = match config.listen.addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: invalid listen addr '{}': {e}", config.listen.addr);
            std::process::exit(1);
        }
    };

    info!(listen_addr = %addr, "stoa-mail starting");

    if config.auth.is_dev_mode() && !config.auth.operator_usernames.is_empty() {
        warn!(
            "auth.operator_usernames is set but no credentials are configured \
             (auth is in dev-mode); operator role designations have no effect in \
             dev-mode — add [[auth.users]] or auth.credential_file to enable authentication"
        );
    }

    let credential_store = match stoa_auth::build_credential_store(
        &config.auth.users,
        config.auth.credential_file.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to build credential store: {e}");
            std::process::exit(1);
        }
    };

    if let (Some(cert), Some(key)) = (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        if key.starts_with("secretx:") {
            let store = match secretx::from_uri(key) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: tls.key_path: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: tls.key_path: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) =
                stoa_tls::load_tls_server_config_with_key_bytes(cert, secret.as_bytes(), key)
            {
                eprintln!("error: failed to load TLS configuration: {e}");
                std::process::exit(1);
            }
        } else if let Err(e) = stoa_tls::load_tls_server_config(cert, key) {
            eprintln!("error: failed to load TLS configuration: {e}");
            std::process::exit(1);
        }
        info!(
            cert,
            "TLS certificate and key validated (HTTPS listener not yet active in v1)"
        );
    }

    // Run all three sets of migrations against the single mail database so that
    // all stores (mail, reader, core) can share one SQLite file.
    if let Err(e) = stoa_mail::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: mail database migration failed: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = stoa_reader::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: reader database migration failed: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = stoa_core::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: core database migration failed: {}", e);
        std::process::exit(1);
    }

    let pool = match stoa_core::db_pool::try_open_any_pool(&config.database.url, 5).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!(
                "error: failed to open database '{}': {}",
                config.database.url, e
            );
            std::process::exit(1);
        }
    };

    // Open the SQLite block store (shared with stoa-reader via the same path).
    let ipfs: Arc<dyn stoa_reader::post::ipfs_write::IpfsBlockStore> = {
        let path = std::path::Path::new(&config.database.block_store_path);
        match stoa_reader::post::sqlite_store::SqliteBlockStore::open(path).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("error: failed to open block store: {e}");
                std::process::exit(1);
            }
        }
    };

    // Provision the six RFC 6154 special-use mailboxes (idempotent INSERT OR IGNORE).
    if let Err(e) = stoa_mail::mailbox::provision::provision_mailboxes(&pool).await {
        eprintln!("error: mailbox provisioning failed: {e}");
        std::process::exit(1);
    }
    let special_mailboxes = match stoa_mail::mailbox::provision::list_mailboxes(&pool).await {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("error: failed to list mailboxes: {e}");
            std::process::exit(1);
        }
    };

    // Build the outbound SMTP relay queue if relay peers are configured.
    let smtp_relay_queue = if config.delivery.smtp_relay_peers.is_empty() {
        None
    } else {
        let queue_dir = std::path::PathBuf::from(&config.delivery.smtp_relay_queue_dir);
        let down_backoff = std::time::Duration::from_secs(config.delivery.smtp_peer_down_secs);
        match stoa_smtp::SmtpRelayQueue::new(
            queue_dir,
            config.delivery.smtp_relay_peers.clone(),
            down_backoff,
            None, // no DKIM signer from JMAP server
            "localhost",
            None, // no MTA-STS enforcer from JMAP server
        ) {
            Ok(q) => Some(q),
            Err(e) => {
                eprintln!("error: failed to build SMTP relay queue: {e}");
                std::process::exit(1);
            }
        }
    };

    let stores = Arc::new(JmapStores {
        ipfs,
        msgid_map: Arc::new(stoa_core::msgid_map::MsgIdMap::new((*pool).clone())),
        article_numbers: Arc::new(
            stoa_reader::store::article_numbers::ArticleNumberStore::new((*pool).clone()),
        ),
        overview_store: Arc::new(stoa_reader::store::overview::OverviewStore::new(
            (*pool).clone(),
        )),
        user_flags: Arc::new(stoa_mail::state::flags::UserFlagsStore::new(
            (*pool).clone(),
        )),
        state_store: Arc::new(stoa_mail::state::version::StateStore::new((*pool).clone())),
        change_log: Arc::new(stoa_mail::state::change_log::ChangeLogStore::new(
            (*pool).clone(),
        )),
        subscription_store: Arc::new(stoa_mail::state::subscriptions::SubscriptionStore::new(
            (*pool).clone(),
        )),
        search_index: None,
        smtp_relay_queue,
        mail_pool: Arc::clone(&pool),
        special_mailboxes,
    });

    let jmap_dispatcher = Arc::new(build_jmap_dispatcher(Arc::clone(&stores)));

    let token_store = Arc::new(TokenStore::new(Arc::clone(&pool)));

    let oidc_store = if config.auth.oidc_providers.is_empty() {
        None
    } else {
        Some(Arc::new(stoa_auth::OidcStore::new(
            config.auth.oidc_providers.clone(),
        )))
    };

    let state = Arc::new(AppState {
        start_time,
        jmap: Some(stores),
        jmap_dispatcher: Some(jmap_dispatcher),
        credential_store: Arc::new(credential_store),
        auth_config: Arc::new(config.auth),
        token_store,
        oidc_store,
        base_url: config.listen.base_url.clone(),
        cors: config.cors.clone(),
        slow_jmap_threshold_ms: config.log.slow_jmap_threshold_ms,
        activitypub_config: config.activitypub.clone(),
        activitypub: None,
        mta_sts_domains: Arc::new(config.mta_sts.hosted_domains),
    });

    if config.activitypub.enabled && !config.activitypub.verify_http_signatures {
        warn!(
            "ActivityPub HTTP signature verification is DISABLED — \
             all inbound activities are accepted without authentication. \
             Set verify_http_signatures = true in [activitypub] for production."
        );
    }

    let shutdown = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received CTRL-C, shutting down");
            }
            _ = sigterm() => {
                info!("received SIGTERM, shutting down");
            }
        }
    };

    if let Err(e) = stoa_mail::server::run_server(addr, state, shutdown).await {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    }

    info!("stoa-mail stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
