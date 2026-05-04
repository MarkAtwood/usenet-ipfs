use std::{path::PathBuf, sync::Arc, time::Instant};

use stoa_mail::{
    config::{Config, LogFormat},
    server::AppState,
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

    if let Err(e) = stoa_mail::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: database migration failed: {}", e);
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

    let token_store = Arc::new(TokenStore::new(pool));

    let oidc_store = if config.auth.oidc_providers.is_empty() {
        None
    } else {
        Some(Arc::new(stoa_auth::OidcStore::new(
            config.auth.oidc_providers.clone(),
        )))
    };

    let state = Arc::new(AppState {
        start_time,
        jmap: None,
        jmap_dispatcher: None,
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
