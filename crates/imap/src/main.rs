use std::{path::PathBuf, sync::Arc};

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use stoa_imap::{
    config::{Config, LogFormat},
    listener::{run_plain_listener, run_tls_listener},
};

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

    stoa_core::emit_startup_banner(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    info!(addr = %config.listen.addr, "stoa-imap starting");

    // SECURITY: abort if dev mode is active on a non-loopback address (SOC2 CC6.1)
    if config.auth.is_dev_mode() && !stoa_core::util::is_loopback_addr(&config.listen.addr) {
        eprintln!(
            "error: stoa-imap is configured in dev mode (auth.required = false, \
no users configured) but is listening on a non-loopback address ({addr}). \
This accepts any password from untrusted networks. \
Either: (1) change listen.addr to 127.0.0.1 for local-only use, or \
(2) set auth.required = true and configure auth.users or auth.credential_file.",
            addr = config.listen.addr
        );
        std::process::exit(1);
    }

    // Open SQLite pool and run migrations.
    let db_url = format!("sqlite:{}?mode=rwc", config.database.path);
    let pool = match sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            error!(
                "failed to open IMAP database at {}: {e}",
                config.database.path
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&*pool).await {
        error!("IMAP database migration failed: {e}");
        std::process::exit(1);
    }

    // Build TLS acceptor if cert and key are configured.
    let tls_acceptor: Option<Arc<TlsAcceptor>> = match (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => {
            let server_config = if key.starts_with("secretx:") {
                let store = match secretx::from_uri(key) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("tls.key_path: invalid secretx URI: {e}");
                        std::process::exit(1);
                    }
                };
                let secret = match store.get().await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("tls.key_path: secretx retrieval failed: {e}");
                        std::process::exit(1);
                    }
                };
                match stoa_tls::load_tls_server_config_with_key_bytes(cert, secret.as_bytes(), key)
                {
                    Ok(c) => c,
                    Err(e) => {
                        error!("failed to load TLS configuration: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                match stoa_tls::load_tls_server_config(cert, key) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("failed to load TLS configuration: {e}");
                        std::process::exit(1);
                    }
                }
            };
            info!(cert, "IMAP TLS acceptor loaded");
            Some(Arc::new(TlsAcceptor::from(server_config)))
        }
        _ => None,
    };

    // Semaphore enforces config.limits.max_connections across both listeners.
    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));

    // Build the credential store once; all sessions share it so the dummy
    // hash is computed only once rather than per-connection.
    let credential_store = Arc::new(
        match stoa_auth::build_credential_store(
            &config.auth.users,
            config.auth.credential_file.as_deref(),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                error!("failed to build credential store: {e}");
                std::process::exit(1);
            }
        },
    );
    let config = Arc::new(config);

    // Optional IMAPS (implicit TLS) listener.
    let tls_future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        if config.listen.tls_addr.is_some() {
            match tls_acceptor.clone() {
                Some(acceptor) => Box::pin(run_tls_listener(
                    config.clone(),
                    acceptor,
                    pool.clone(),
                    semaphore.clone(),
                    credential_store.clone(),
                )),
                None => {
                    error!("listen.tls_addr is set but tls.cert_path/key_path are not configured");
                    std::process::exit(1);
                }
            }
        } else {
            Box::pin(std::future::pending())
        };

    tokio::select! {
        _ = run_plain_listener(config.clone(), pool, semaphore, credential_store, tls_acceptor.clone()) => {}
        _ = tls_future => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("stoa-imap stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
