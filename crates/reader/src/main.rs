use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use stoa_reader::{
    admin::start_admin_server,
    config::{Config, LogFormat},
    session::lifecycle::{run_session, ListenerKind},
    store::{backfill::backfill_overview, server_stores::ServerStores},
    tls::TlsAcceptor,
};

fn parse_args() -> (PathBuf, bool, Vec<PathBuf>) {
    let args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch: `stoa-reader keygen --output <path> [--force]`
    if args.get(1).map(|s| s.as_str()) == Some("keygen") {
        cmd_keygen(&args[2..]);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!(
            "{} {} ({} {})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("GIT_SHA"),
            env!("BUILD_DATE"),
        );
        std::process::exit(0);
    }

    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut restore_files: Vec<PathBuf> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                    i += 2;
                } else {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--restore" => {
                i += 1;
                while i < args.len() && !args[i].starts_with("--") {
                    restore_files.push(PathBuf::from(&args[i]));
                    i += 1;
                }
                if restore_files.is_empty() {
                    eprintln!("error: --restore requires at least one backup file path");
                    std::process::exit(1);
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    match config_path {
        Some(p) => (p, check_only, restore_files),
        None => {
            eprintln!("error: --config <path> is required");
            std::process::exit(1);
        }
    }
}

/// Restore SQLite databases from backup files.
///
/// Each `backup_file` must be a valid SQLite file (verified by magic header).
/// The destination path is determined by the filename prefix:
/// - `reader-*.db` → `db.reader_url` (reader schema)
/// - `core-*.db`   → `db.core_url` (core schema)
/// - `verify-*.db` → `db.verify_url` (verify schema)
///
/// Files with unrecognised prefixes are skipped with a warning.
/// Exits 0 after all files are restored.
fn cmd_restore(backup_files: &[PathBuf], db: &stoa_reader::config::DatabaseConfig) -> ! {
    for src in backup_files {
        let stem = src.file_name().and_then(|n| n.to_str()).unwrap_or_default();

        // Verify SQLite magic header.
        let data = match std::fs::read(src) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: cannot read backup file {}: {e}", src.display());
                std::process::exit(1);
            }
        };
        if data.len() < 16 || &data[..16] != b"SQLite format 3\0" {
            eprintln!(
                "error: {} is not a valid SQLite file (bad magic header)",
                src.display()
            );
            std::process::exit(1);
        }

        let dest_url = if stem.starts_with("reader-") {
            &db.reader_url
        } else if stem.starts_with("core-") {
            &db.core_url
        } else if stem.starts_with("verify-") {
            &db.verify_url
        } else {
            eprintln!(
                "warning: skipping {}: unrecognised prefix (expected reader-, core-, or verify-)",
                src.display()
            );
            continue;
        };

        // Strip sqlite:// prefix to get the filesystem path.
        let dest = dest_url
            .strip_prefix("sqlite://")
            .unwrap_or(dest_url.as_str());

        if let Some(parent) = std::path::Path::new(dest).parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("error: cannot create directory {}: {e}", parent.display());
                    std::process::exit(1);
                }
            }
        }
        if let Err(e) = std::fs::copy(src, dest) {
            eprintln!("error: cannot restore {} → {dest}: {e}", src.display());
            std::process::exit(1);
        }
        println!("restored {} → {dest}", src.display());
    }
    std::process::exit(0);
}

async fn run_startup_checks(config: &Config) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // Kubo reachability check (skipped for non-Kubo backends).
    if let Some(url) = config.kubo_api_url() {
        let url = url.to_owned();
        let client = stoa_core::ipfs::KuboHttpClient::new(&url);
        match tokio::time::timeout(Duration::from_secs(5), client.node_id()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: {e} — is 'ipfs daemon' running?"
                ));
            }
            Err(_) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: timed out after 5s — is 'ipfs daemon' running?"
                ));
            }
        }
    }

    // TLS file readability check and certificate expiry warning.
    if let Some(cert) = config.tls.cert_path.as_deref() {
        if let Err(e) = std::fs::read(cert) {
            errors.push(format!("TLS file unreadable: {cert}: {e}"));
        } else {
            let _ = stoa_reader::tls::check_cert_expiry(cert);
        }
    }
    if let Some(key) = config.tls.key_path.as_deref() {
        // For secretx: URIs, validate URI syntax; resolution happens at load time.
        if key.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(key) {
                errors.push(format!("tls.key_path: invalid secretx URI: {e}"));
            }
        } else if let Err(e) = std::fs::read(key) {
            errors.push(format!("TLS file unreadable: {key}: {e}"));
        }
    }

    // Signing key check.
    if let Some(path) = config.operator.signing_key_path.as_deref() {
        if path.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(path) {
                errors.push(format!(
                    "operator.signing_key_path: invalid secretx URI: {e}"
                ));
            }
        } else if let Err(e) = stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
            errors.push(e.to_string());
        }
    }

    // Validate secretx URI syntax for remaining string secrets.
    if let Some(tok) = &config.admin.admin_token {
        if tok.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(tok) {
                errors.push(format!("admin.admin_token: invalid secretx URI: {e}"));
            }
        }
    }
    if let Some(path) = &config.auth.credential_file {
        if path.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(path) {
                errors.push(format!("auth.credential_file: invalid secretx URI: {e}"));
            }
        }
    }

    errors
}

/// Handle `stoa-reader keygen --output <path> [--force]`.
///
/// Generates a random 32-byte Ed25519 seed, writes it to `<path>` (mode 0600),
/// and prints the public key hex + HLC node ID to stdout.  Exits 0 on success,
/// 1 on any error.  Never returns — always calls `std::process::exit`.
fn cmd_keygen(args: &[String]) -> ! {
    let mut output: Option<&str> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                output = args.get(i + 1).map(|s| s.as_str());
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => {
                eprintln!("error: unknown keygen argument: {other}");
                std::process::exit(1);
            }
        }
    }
    let output_path = match output {
        Some(p) => std::path::Path::new(p),
        None => {
            eprintln!("error: keygen requires --output <path>");
            std::process::exit(1);
        }
    };
    let key = stoa_core::signing::generate_signing_key();
    let overwrite = if force {
        stoa_core::signing::Overwrite::Force
    } else {
        stoa_core::signing::Overwrite::NoOverwrite
    };
    if let Err(e) = stoa_core::signing::write_signing_key(&key, output_path, overwrite) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
    let node_id = stoa_core::signing::hlc_node_id(&key);
    let node_id_hex = hex::encode(node_id);
    println!("public_key: {pubkey_hex}");
    println!("node_id:    {node_id_hex}");
    println!("key_file:   {}", output_path.display());
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    sqlx::any::install_default_drivers();
    let (config_path, check_only, restore_files) = parse_args();

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

    if !restore_files.is_empty() {
        cmd_restore(&restore_files, &config.database);
    }

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log.level));

    let (_otel_guard, log_provider) = stoa_reader::telemetry::init_telemetry(&config.telemetry);
    let otel_trace_layer =
        tracing_opentelemetry::layer().with_tracer(opentelemetry::global::tracer("stoa-reader"));
    let otel_log_layer = log_provider
        .as_ref()
        .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new);

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    let (json_fmt, text_fmt) = if config.log.format == LogFormat::Json {
        (Some(tracing_subscriber::fmt::layer().json()), None)
    } else {
        (None, Some(tracing_subscriber::fmt::layer()))
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(json_fmt)
        .with(text_fmt)
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .init();

    stoa_core::emit_startup_banner(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    info!(
        binary = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
        git_sha = env!("GIT_SHA"),
        build_date = env!("BUILD_DATE"),
        "starting"
    );

    let check_errors = run_startup_checks(&config).await;
    if !check_errors.is_empty() {
        for msg in &check_errors {
            eprintln!("error: {msg}");
        }
        std::process::exit(1);
    }
    if check_only {
        println!("startup checks passed");
        std::process::exit(0);
    }

    // SECURITY: signing_key_path is required for non-loopback deployments (SOC2 CC6.1, zn0k).
    if config.operator.signing_key_path.is_none()
        && !stoa_core::util::is_loopback_addr(&config.listen.addr)
    {
        eprintln!(
            "error: operator.signing_key_path must be set when listening on a non-loopback \
             address ({}). Run `stoa-reader keygen --output <path>` to generate \
             a key, then set [operator] signing_key_path in your config.",
            config.listen.addr
        );
        std::process::exit(1);
    }

    // Abort when auth dev-mode is active on a non-loopback address.
    // Dev-mode (required=false, no users, no credential_file) accepts any password,
    // making the server an open relay if bound to a reachable interface.
    if config.auth.is_dev_mode() && !stoa_core::util::is_loopback_addr(&config.listen.addr) {
        eprintln!(
            "error: stoa-reader is configured in dev mode (auth.required = false, \
no users configured) but is listening on a non-loopback address ({addr}). \
This accepts any password from untrusted networks. \
Either: (1) change listen.addr to 127.0.0.1 for local-only use, or \
(2) set auth.required = true and configure auth.users or auth.credential_file.",
            addr = config.listen.addr
        );
        std::process::exit(1);
    }

    info!(
        listen_addr = %config.listen.addr,
        max_connections = config.limits.max_connections,
        "stoa-reader starting"
    );

    // Load TLS acceptor before binding the socket so that cert/key errors are
    // caught at startup rather than on the first client connection.
    let tls_acceptor: Option<Arc<TlsAcceptor>> = match (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => {
            let acceptor_result = if key.starts_with("secretx:") {
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
                stoa_reader::tls::load_tls_acceptor_with_key_bytes(cert, secret.as_bytes(), key)
            } else {
                stoa_reader::tls::load_tls_acceptor(cert, key)
            };
            match acceptor_result {
                Ok(a) => {
                    info!(cert = cert, "TLS acceptor loaded");
                    Some(Arc::new(a))
                }
                Err(e) => {
                    error!("Failed to load TLS acceptor: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => None,
    };

    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind to {}: {}", config.listen.addr, e);
            std::process::exit(1);
        }
    };

    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));
    let stores = Arc::new(match ServerStores::new_with_ipfs(&config).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to initialise stores: {e}");
            std::process::exit(1);
        }
    });

    let backfilled = backfill_overview(
        &stores.article_numbers,
        &stores.overview_store,
        stores.ipfs_store.as_ref(),
    )
    .await;
    if backfilled > 0 {
        info!(count = backfilled, "overview index backfill complete");
    }

    let config = Arc::new(config);

    // Optional admin HTTP server.
    if config.admin.enabled {
        let admin_addr: std::net::SocketAddr = match config.admin.addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("invalid admin.addr '{}': {}", config.admin.addr, e);
                std::process::exit(1);
            }
        };
        let admin_token = stoa_core::secret::resolve_secret_uri(
            config.admin.admin_token.clone(),
            "admin.admin_token",
        )
        .await
        .unwrap_or_else(|msg| {
            eprintln!("{msg}");
            std::process::exit(1);
        });
        let cert_paths: std::sync::Arc<Vec<String>> =
            std::sync::Arc::new(config.tls.cert_path.iter().cloned().collect());
        if let Err(e) = start_admin_server(
            admin_addr,
            std::time::Instant::now(),
            admin_token,
            config.admin.rate_limit_rpm,
            cert_paths,
        ) {
            error!("{e}");
            std::process::exit(1);
        }
    }

    // Optional NNTPS listener (implicit TLS, port 563 by convention).
    let tls_listener_future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        if let Some(tls_addr) = &config.tls.tls_addr {
            let tls_listener = match TcpListener::bind(tls_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("failed to bind NNTPS listener to {}: {}", tls_addr, e);
                    std::process::exit(1);
                }
            };
            info!(tls_addr = %tls_addr, "NNTPS (implicit TLS) listener started");
            let nntps_acceptor = match tls_acceptor.clone() {
                Some(a) => a,
                None => {
                    error!("NNTPS listener configured but no TLS cert/key provided");
                    std::process::exit(1);
                }
            };
            Box::pin(accept_loop(
                tls_listener,
                Arc::clone(&semaphore),
                config.clone(),
                stores.clone(),
                ListenerKind::Tls,
                Some(nntps_acceptor),
            ))
        } else {
            Box::pin(std::future::pending())
        };

    // Retain handles for the drain phase after shutdown signal.
    let semaphore_drain = Arc::clone(&semaphore);
    let max_connections = config.limits.max_connections;
    let drain_timeout_secs = config.limits.drain_timeout_secs.unwrap_or(30);

    tokio::select! {
        _ = accept_loop(listener, semaphore, config, stores, ListenerKind::Plain, tls_acceptor) => {}
        _ = tls_listener_future => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    // Drain: wait for all in-flight sessions to release their semaphore permits.
    let active = max_connections - semaphore_drain.available_permits();
    if active > 0 {
        info!(active_connections = active, "draining active connections");
        let drain_result = tokio::time::timeout(
            std::time::Duration::from_secs(drain_timeout_secs),
            semaphore_drain.acquire_many(max_connections as u32),
        )
        .await;
        match drain_result {
            Ok(_) => {
                info!("all connections drained cleanly");
            }
            Err(_) => {
                let remaining = max_connections - semaphore_drain.available_permits();
                warn!(
                    remaining_connections = remaining,
                    "drain timeout exceeded, forcing exit"
                );
                std::process::exit(1);
            }
        }
    }

    info!("stoa-reader stopped");
}

/// Accept loop shared by NNTP (plain or STARTTLS) and NNTPS (implicit TLS) listeners.
///
/// `kind`: `ListenerKind::Tls` for implicit-TLS listeners (port 563);
/// `ListenerKind::Plain` for plain-NNTP listeners (port 119) where TLS may be
/// negotiated via STARTTLS.
async fn accept_loop(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<Config>,
    stores: Arc<ServerStores>,
    kind: ListenerKind,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    let proto = if kind == ListenerKind::Tls {
        "NNTPS"
    } else {
        "NNTP"
    };
    loop {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("semaphore closed, stopping {proto} accept loop");
                break;
            }
        };

        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("{proto} accept error: {}", e);
                drop(permit);
                continue;
            }
        };

        let config = config.clone();
        let stores = stores.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_session(stream, kind, &config, stores, tls_acceptor).await;
            info!(%peer_addr, "{proto} connection closed");
        });
    }
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
