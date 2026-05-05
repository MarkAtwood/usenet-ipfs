use std::{path::PathBuf, sync::Arc, time::Instant};

use stoa_core::util::is_loopback_addr;
use stoa_mail::{
    config::{Config, LogFormat},
    server::{build_jmap_dispatcher, AppState, JmapStores},
    store::new_sqlx_mail_store,
    token_store::TokenStore,
};
use tracing::{info, warn};

fn parse_args() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            match args.next() {
                Some(path) => return Some(PathBuf::from(path)),
                None => {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() {
    sqlx::any::install_default_drivers();
    // Install the ring CryptoProvider before any TLS operations so that
    // stoa_tls::approved_provider() can call CryptoProvider::get_default()
    // without panicking.  The call is idempotent — if a provider was already
    // installed (e.g. in tests) the error is silently ignored.
    stoa_tls::install_ring_provider();
    let start_time = Instant::now();
    let config_path = parse_args();

    let config = match Config::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            match &config_path {
                Some(p) => eprintln!("error: failed to load config from {}: {}", p.display(), e),
                None => eprintln!("error: failed to load config from environment: {e}"),
            }
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

    stoa_core::emit_startup_banner(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

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

    // SECURITY: abort if dev mode is active on a non-loopback address (SOC2 CC6.1)
    if config.auth.is_dev_mode() && !is_loopback_addr(&config.listen.addr) {
        eprintln!(
            "error: stoa-mail is configured in dev mode (auth.required = false, \
no users configured) but is listening on a non-loopback address ({addr}). \
This accepts any password from untrusted networks. \
Either: (1) change listen.addr to 127.0.0.1 for local-only use, or \
(2) set auth.required = true and configure auth.users or auth.credential_file.",
            addr = config.listen.addr
        );
        std::process::exit(1);
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

    // Build the mail store before mailbox provisioning.
    let mail_store = new_sqlx_mail_store(Arc::clone(&pool));

    // Provision the six RFC 6154 special-use mailboxes (idempotent INSERT OR IGNORE).
    if let Err(e) = mail_store.provision_mailboxes().await {
        eprintln!("error: mailbox provisioning failed: {e}");
        std::process::exit(1);
    }
    let special_mailboxes = match mail_store.list_mailboxes().await {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("error: failed to list mailboxes: {e}");
            std::process::exit(1);
        }
    };

    // Build the outbound SMTP relay mailer if relay peers are configured.
    let outbound_mailer: Option<std::sync::Arc<dyn stoa_smtp::OutboundMailer>> =
        if config.delivery.smtp_relay_peers.is_empty() {
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
                Ok(q) => Some(std::sync::Arc::new(stoa_smtp::SmtpRelayMailer::new(q))),
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
        search_index: None,
        outbound_mailer,
        mail_store,
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
        db_pool: Some(Arc::clone(&pool)),
    });

    // SECURITY: abort if ActivityPub HTTP signature verification is disabled on non-loopback (SOC2 CC6.1)
    if config.activitypub.enabled && !config.activitypub.verify_http_signatures {
        if !is_loopback_addr(&config.listen.addr) {
            eprintln!(
                "error: stoa-mail: activitypub.verify_http_signatures = false disables \
HTTP signature verification, allowing any actor to forge inbound ActivityPub activities. \
Set verify_http_signatures = true or change the listen address to 127.0.0.1."
            );
            std::process::exit(1);
        } else {
            warn!("activitypub HTTP signature verification is disabled; only safe on loopback");
        }
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
