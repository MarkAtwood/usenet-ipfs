use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::MessageAuthenticator;
use rand_core::OsRng;

use stoa_core::{
    audit::{start_audit_logger, AuditLogger},
    group_log::SqliteLogStorage,
    hlc::HlcClock,
    msgid_map::MsgIdMap,
    wildmat::{GroupFilter, GroupPolicy},
};
use stoa_transit::{
    admin::{start_admin_server, AdminPools},
    config::{check_admin_addr, Config, LogFormat},
    hlc_persist::{load_hlc_checkpoint, save_hlc_checkpoint},
    instance_id::ensure_instance_node_id,
    peering::{
        auth::parse_trusted_peer_keys,
        backpressure::IpfsLatencyMonitor,
        blacklist::BlacklistConfig,
        ingestion_queue::ingestion_queue,
        pipeline::{
            run_pipeline, IpfsStore, PipelineCtx, ERR_MISSING_MESSAGE_ID,
            ERR_SIGNATURE_SELF_CHECK_FAILED,
        },
        rate_limit::{ExhaustionAction, PeerRateLimiter},
        session::{run_peering_session, PeeringShared},
    },
    reload::ReloadableState,
    retention::{
        gc::{start_gc_scheduler, GcMetrics, GcRunner},
        gc_candidates::select_gc_candidates,
        ipns_publisher::{IpnsEvent, IpnsPublisher},
        pin_client::HttpPinClient,
        policy::{PinAction, PinPolicy, PinRule},
        remote_pin_worker::RemotePinWorker,
    },
    staging::StagingStore,
};
use stoa_verify::VerificationStore;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{error, info, warn};

fn parse_args() -> (PathBuf, bool, Vec<PathBuf>) {
    let args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch: `stoa-transit keygen --output <path> [--force]`
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
/// - `transit-*.db` → `db.url` (transit schema)
/// - `core-*.db`    → `db.core_url` (core schema)
/// - `verify-*.db`  → `db.verify_url` (verify schema)
///
/// Files with unrecognised prefixes are skipped with a warning.
/// Exits 0 after all files are restored.
fn cmd_restore(backup_files: &[PathBuf], db: &stoa_transit::config::DatabaseConfig) -> ! {
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

        // Strip "sqlite://" prefix if present to get the file path.
        // Do NOT strip leading slashes after the prefix: sqlite:///data/transit.db
        // yields /data/transit.db (absolute path), which must be preserved as-is.
        fn url_to_path(url: &str) -> &str {
            url.strip_prefix("sqlite://").unwrap_or(url)
        }

        let dest = if stem.starts_with("transit-") {
            url_to_path(&db.url)
        } else if stem.starts_with("core-") {
            url_to_path(&db.core_url)
        } else if stem.starts_with("verify-") {
            url_to_path(&db.verify_url)
        } else {
            eprintln!(
                "warning: skipping {}: unrecognised prefix (expected transit-, core-, or verify-)",
                src.display()
            );
            continue;
        };

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

/// Handle `stoa-transit keygen --output <path> [--force]`.
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

async fn run_startup_checks(
    config: &stoa_transit::config::Config,
) -> (Vec<String>, Option<TcpListener>) {
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
    if let Some(ref tls_cfg) = config.tls {
        if let Err(e) = std::fs::read(&tls_cfg.cert_path) {
            errors.push(format!("TLS file unreadable: {}: {e}", tls_cfg.cert_path));
        } else {
            let _ = stoa_transit::admin::check_cert_expiry(&tls_cfg.cert_path);
        }
        // For secretx: URIs, validate URI syntax here; resolution happens at startup.
        if tls_cfg.key_path.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(&tls_cfg.key_path) {
                errors.push(format!("tls.key_path: invalid secretx URI: {e}"));
            }
        } else if let Err(e) = std::fs::read(&tls_cfg.key_path) {
            errors.push(format!("TLS file unreadable: {}: {e}", tls_cfg.key_path));
        }
    }

    // Signing key check.
    if let Some(ref path) = config.operator.signing_key_path {
        if path.starts_with("secretx:") {
            // Validate URI syntax; retrieval and byte validation happen at load time.
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
    if let Some(ref tok) = config.admin.bearer_token {
        if tok.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(tok) {
                errors.push(format!("admin.bearer_token: invalid secretx URI: {e}"));
            }
        }
    }
    for svc in &config.pinning.external_services {
        if let Err(e) = svc.api_key.validate_uri_syntax() {
            errors.push(format!(
                "pinning.external_services[{}].api_key: invalid secretx URI: {e}",
                svc.name
            ));
        }
    }

    // Admin bind address check: bind once here and return the listener so
    // start_admin_server can reuse it, eliminating the race window between
    // the connectivity test and the server bind.
    let admin_listener = match TcpListener::bind(&config.admin.addr).await {
        Ok(l) => Some(l),
        Err(e) => {
            errors.push(format!(
                "Admin address {} already in use or invalid: {e}",
                config.admin.addr
            ));
            None
        }
    };

    (errors, admin_listener)
}

/// Notify the IPNS publisher of the new article tip for each group.
///
/// Called from both the ingestion drain and the staging drain after a
/// successful `run_pipeline` to avoid duplicating the channel-send loop.
fn publish_ipns_tip(
    result: &stoa_transit::peering::pipeline::PipelineResult,
    ipns_tx: &Option<tokio::sync::mpsc::Sender<IpnsEvent>>,
) {
    if let Some(ref tx) = ipns_tx {
        for group in &result.groups {
            let event = IpnsEvent {
                group: group.clone(),
                cid: result.cid,
            };
            if let Err(e) = tx.try_send(event) {
                warn!(group, "IPNS channel full, skipping publish: {e}");
            }
        }
    }
}

/// Enqueue successfully stored articles for external pinning services.
///
/// Called from both the ingestion drain and the staging drain after a
/// successful `run_pipeline` to avoid duplicating the SQL insert loop.
async fn enqueue_pin_jobs(
    result: &stoa_transit::peering::pipeline::PipelineResult,
    pin_service_filters: &[(String, GroupPolicy)],
    pool: &sqlx::AnyPool,
) {
    if pin_service_filters.is_empty() {
        return;
    }
    let cid_str = result.cid.to_string();
    for (svc_name, filter) in pin_service_filters {
        let should_pin = match filter {
            None => true,
            Some(f) => result.groups.iter().any(|g| f.accepts(g)),
        };
        if should_pin {
            if let Err(e) = sqlx::query(
                "INSERT INTO remote_pin_jobs \
                 (cid, service_name) VALUES (?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(&cid_str)
            .bind(svc_name)
            .execute(pool)
            .await
            {
                warn!(
                    cid = %cid_str,
                    service = %svc_name,
                    "failed to enqueue remote pin job: {e}"
                );
            }
        }
    }
}

/// Stable per-server fields passed to [`run_pipeline_and_notify`].
///
/// Groups the parameters that are constant across all articles in a drain loop,
/// keeping `run_pipeline_and_notify` under the clippy argument-count limit.
struct PipelineArgs<'a> {
    hlc: &'a tokio::sync::Mutex<HlcClock>,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    local_hostname: &'a str,
    verify_store: Option<&'a VerificationStore>,
    trusted_keys: Arc<[ed25519_dalek::VerifyingKey]>,
    dkim_auth: Option<&'a MessageAuthenticator>,
    group_filter: GroupPolicy,
    ipfs: &'a dyn IpfsStore,
    msgid_map: &'a MsgIdMap,
    log_storage: &'a SqliteLogStorage,
    transit_pool: &'a sqlx::AnyPool,
    ipns_tx: &'a Option<tokio::sync::mpsc::Sender<IpnsEvent>>,
    pin_service_filters: &'a [(String, GroupPolicy)],
    ipfs_latency_monitor: Arc<IpfsLatencyMonitor>,
}

/// Outcome of a `run_pipeline_and_notify` call.
enum PipelineOutcome {
    /// Pipeline succeeded; article was written to IPFS and recorded.
    Success,
    /// Pipeline failed with a permanent error (invalid article format, signing
    /// self-check failure).  Retrying will never succeed; the staging row must
    /// be purged immediately.
    PermanentFailure,
    /// Pipeline failed with a transient error (IPFS unavailable, DB lock).
    /// The staging row should be kept for retry, subject to a max-retry limit.
    TransientFailure,
}

/// Classify a `run_pipeline` error string into permanent vs transient.
///
/// The error strings are defined in `peering/pipeline.rs`; they are stable
/// internal constants, not user-visible messages.
fn classify_pipeline_error(msg: &str) -> PipelineOutcome {
    // Permanent: article-level defects that cannot be fixed by retrying.
    // The constants are defined in peering/pipeline.rs; matching here will
    // break at compile time if the strings ever change.
    if msg.contains(ERR_MISSING_MESSAGE_ID) || msg.contains(ERR_SIGNATURE_SELF_CHECK_FAILED) {
        return PipelineOutcome::PermanentFailure;
    }
    // Everything else (IPFS write failed, msgid insert failed, articles table
    // insert failed, DB contention) is treated as transient.
    PipelineOutcome::TransientFailure
}

/// Run `run_pipeline`, emit structured telemetry, and drive post-success hooks
/// (IPNS publish + remote pin enqueue).  Common to the ingestion drain and the
/// staging drain; the only difference is the success log message.
///
/// Returns a [`PipelineOutcome`] so the staging drain can distinguish
/// permanent failures (purge the row immediately) from transient ones (retain
/// for retry).
async fn run_pipeline_and_notify(
    bytes: &[u8],
    message_id: &str,
    success_label: &'static str,
    args: &PipelineArgs<'_>,
) -> PipelineOutcome {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let timestamp = args.hlc.lock().await.send(now_ms);
    let ctx = PipelineCtx {
        timestamp,
        operator_signing_key: Arc::clone(&args.signing_key),
        local_hostname: args.local_hostname,
        verify_store: args.verify_store,
        trusted_keys: Arc::clone(&args.trusted_keys),
        dkim_auth: args.dkim_auth,
        group_filter: args.group_filter.clone(),
    };
    match run_pipeline(
        bytes,
        args.ipfs,
        args.msgid_map,
        args.log_storage,
        args.transit_pool,
        ctx,
    )
    .await
    {
        Ok((result, metrics)) => {
            args.ipfs_latency_monitor
                .record_latency_ms(metrics.ipfs_write_latency_ms as f64);
            info!(
                cid = %result.cid,
                groups = ?result.groups,
                msgid = %message_id,
                "{success_label}",
            );
            publish_ipns_tip(&result, args.ipns_tx);
            enqueue_pin_jobs(&result, args.pin_service_filters, args.transit_pool).await;
            PipelineOutcome::Success
        }
        Err(e) => {
            warn!(msgid = %message_id, "pipeline failed: {e}");
            classify_pipeline_error(&e)
        }
    }
}

#[tokio::main]
async fn main() {
    sqlx::any::install_default_drivers();
    let start_time = Instant::now();
    let (config_path, check_only, restore_files) = parse_args();

    let mut config = match Config::from_file(&config_path) {
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

    let (_otel_guard, log_provider) = stoa_transit::telemetry::init_telemetry(&config.telemetry);
    let otel_trace_layer =
        tracing_opentelemetry::layer().with_tracer(opentelemetry::global::tracer("stoa-transit"));
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

    info!(
        binary = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
        git_sha = env!("GIT_SHA"),
        build_date = env!("BUILD_DATE"),
        "starting"
    );

    let (check_errors, admin_listener) = run_startup_checks(&config).await;
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

    // Build group filter from config. Empty names list means accept all groups.
    let group_filter: GroupPolicy = if config.groups.names.is_empty() {
        None
    } else {
        Some(Arc::new(
            GroupFilter::new(&config.groups.names)
                .expect("config already validated group patterns"),
        ))
    };

    info!(
        listen_addr = %config.listen.addr,
        peer_count = config.peers.addresses.len() + config.peers.peer.len(),
        group_count = config.groups.names.len(),
        "stoa-transit starting"
    );
    if !config.groups.names.is_empty() {
        info!(
            patterns = %config.groups.names.join(", "),
            "group filter active: accepting articles matching configured patterns"
        );
    } else {
        info!("group filter inactive: accepting articles from all groups");
    }

    if let Err(e) = check_admin_addr(&config.admin) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // ── Databases (two separate pools: core schema + transit schema) ─────────

    if let Err(e) = stoa_core::migrations::run_migrations(&config.database.core_url).await {
        eprintln!("error: core database migration failed: {e}");
        std::process::exit(1);
    }
    let core_pool = Arc::new(
        stoa_core::db_pool::open_any_pool(&config.database.core_url, config.database.pool_size)
            .await
            .unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            }),
    );
    let msgid_map = Arc::new(MsgIdMap::new((*core_pool).clone()));
    let log_storage = Arc::new(SqliteLogStorage::new((*core_pool).clone()));

    if let Err(e) = stoa_transit::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: transit database migration failed: {e}");
        std::process::exit(1);
    }
    let transit_pool = Arc::new(
        stoa_core::db_pool::open_any_pool(&config.database.url, config.database.pool_size)
            .await
            .unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            }),
    );

    // ── Verify pool (separate schema; no version conflicts with transit) ───────

    if let Err(e) = stoa_verify::run_migrations(&config.database.verify_url).await {
        eprintln!("error: verify database migration failed: {e}");
        std::process::exit(1);
    }
    let verify_pool =
        stoa_core::db_pool::open_any_pool(&config.database.verify_url, config.database.pool_size)
            .await
            .unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
    let verification_store = Arc::new(VerificationStore::new(verify_pool));

    let dkim_authenticator = match MessageAuthenticator::new_cloudflare_tls() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("error: DKIM authenticator init failed: {e}");
            std::process::exit(1);
        }
    };

    // ── Remote pinning worker ─────────────────────────────────────────────────

    // Resolve any secretx: URIs in pinning service API keys before the worker starts.
    for svc in config.pinning.external_services.iter_mut() {
        let label = format!("pinning.external_services[{}].api_key", svc.name);
        svc.api_key = svc.api_key.clone().resolve(&label).await;
    }

    if !config.pinning.external_services.is_empty() {
        match RemotePinWorker::from_config(
            (*transit_pool).clone(),
            &config.pinning.external_services,
        ) {
            Ok(worker) => {
                info!(
                    services = config.pinning.external_services.len(),
                    "remote pin worker started"
                );
                tokio::spawn(worker.run());
            }
            Err(e) => {
                eprintln!("error: failed to build remote pin worker: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── IPFS block store ──────────────────────────────────────────────────────

    let build_result = match stoa_transit::peering::pipeline::build_store(&config).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to build IPFS store: {e}");
            std::process::exit(1);
        }
    };
    if let Some(url) = config.kubo_api_url() {
        info!(api_url = %url, "connecting to Kubo IPFS node");
    }
    // Extract the Kubo client before boxing so the IPNS publisher can use it.
    let kubo_client_for_ipns = if config.ipns.enabled {
        build_result.kubo_client
    } else {
        None
    };
    let mut ipfs_store: Arc<dyn stoa_transit::peering::pipeline::IpfsStore> = build_result.store;

    // ── Block cache (optional) ─────────────────────────────────────────────────

    if let Some(cache_cfg) = config.cache.take() {
        match tokio::fs::create_dir_all(&cache_cfg.path).await {
            Ok(()) => {
                info!(path = %cache_cfg.path, "block cache directory ready");
                ipfs_store = Arc::new(stoa_transit::block_cache::BlockCache::new(
                    cache_cfg,
                    Arc::clone(&transit_pool),
                    ipfs_store,
                ));
            }
            Err(e) => {
                eprintln!("error: could not create block cache directory: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── IPNS channel ──────────────────────────────────────────────────────────

    let ipns_tx: Option<tokio::sync::mpsc::Sender<IpnsEvent>> = if config.ipns.enabled {
        let (tx, rx) = tokio::sync::mpsc::channel::<IpnsEvent>(256);
        let client = kubo_client_for_ipns
            .clone()
            .expect("kubo_client_for_ipns set when enabled");
        let interval = config.ipns.republish_interval_secs;
        // When using PostgreSQL, elect a single IPNS publisher via advisory lock
        // (ky62.5): only the instance that holds IPNS_ADVISORY_LOCK_ID publishes.
        let publisher = if config.database.url.starts_with("postgres") {
            IpnsPublisher::new(client, interval).with_pg_lock((*transit_pool).clone())
        } else {
            IpnsPublisher::new(client, interval)
        };
        tokio::spawn(publisher.run(rx));
        info!(
            "IPNS publishing enabled (interval {}s)",
            config.ipns.republish_interval_secs
        );
        Some(tx)
    } else {
        None
    };

    // Derive the IPNS path string (/ipns/<peer_id>) for the admin endpoint.
    // Only set when IPNS is enabled; the admin /ipns endpoint returns null otherwise.
    let ipns_path_string: Option<String> = if let Some(ref client) = kubo_client_for_ipns {
        match client.node_id().await {
            Ok(peer_id) => {
                let path = format!("/ipns/{peer_id}");
                info!(ipns_path = %path, "IPNS address ready");
                Some(path)
            }
            Err(e) => {
                warn!("IPNS: failed to get Kubo node peer identity: {e}");
                None
            }
        }
    } else {
        None
    };

    // ── Operator signing key ──────────────────────────────────────────────────

    // DECISION (rbe3.35): signing key required for non-loopback listeners
    //
    // An ephemeral key (generated at startup, not saved) changes on every
    // restart, breaking X-Stoa-Sig verification for peers that cached the
    // operator's public key.  Loopback-only deployments (dev/test mode) are
    // permitted to use ephemeral keys with a warn-level log; production
    // deployments that accept external peering connections must supply a
    // persistent key file so that signatures remain verifiable across restarts.
    // Do NOT remove this check for non-loopback listeners.
    // Enforce signing_key_path for non-loopback deployments (zn0k).
    if config.operator.signing_key_path.is_none()
        && !stoa_transit::config::is_loopback_addr(&config.listen.addr)
    {
        eprintln!(
            "error: operator.signing_key_path must be set when listening on a non-loopback \
             address ({}). Run `stoa-transit keygen --output <path>` to generate \
             a key, then set [operator] signing_key_path in your config.",
            config.listen.addr
        );
        std::process::exit(1);
    }

    let signing_key = Arc::new(match &config.operator.signing_key_path {
        Some(path) if path.starts_with("secretx:") => {
            let store = match secretx::from_uri(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            match stoa_core::signing::load_signing_key_from_bytes(secret.as_bytes()) {
                Ok(k) => {
                    info!(path, "loaded operator signing key via secretx");
                    k
                }
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(path) => match stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
            Ok(k) => {
                info!(path, "loaded operator signing key");
                k
            }
            Err(e) => {
                eprintln!("error: cannot load operator signing key from '{path}': {e}");
                std::process::exit(1);
            }
        },
        None => {
            warn!(
                "operator.signing_key_path not set — using ephemeral key; \
                 article signatures will not survive restart"
            );
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        }
    });

    // ── Trusted peer keys ─────────────────────────────────────────────────────

    let trusted_keys = parse_trusted_peer_keys(&config.peering.trusted_peers).unwrap_or_else(|e| {
        error!(
            "invalid trusted_peers key in config: {e} — \
             peering auth is a security control; startup aborted"
        );
        std::process::exit(1);
    });

    // ── Local hostname (needed for HLC node_id and Path: header) ─────────────

    let local_hostname: String = config
        .operator
        .hostname
        .clone()
        .unwrap_or_else(resolve_local_hostname);
    info!(hostname = %local_hostname, "local hostname for Path: header");

    // ── HLC clock and ingestion queue ─────────────────────────────────────────

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    // Derive node_id from a per-instance UUID stored in the transit database
    // (usenet-ipfs-ky62.5).  Multiple transit instances sharing a signing key
    // each get a distinct, stable node_id as long as they run on different
    // hostnames.  For single-instance SQLite deployments, the value is
    // generated once on first startup and reused across restarts.
    let node_id = ensure_instance_node_id(&transit_pool, &local_hostname).await;
    // DECISION (rbe3.34): HLC checkpoint persisted across restarts for monotone timestamps
    //
    // Without persistence, a server restart resets the HLC logical counter to 0.
    // If the wall-clock millisecond at restart equals the last emitted timestamp's
    // wall millisecond, the new timestamp would collide with or regress below a
    // previous one, violating the HLC ordering guarantee that the Merkle-CRDT
    // group log depends on for causal consistency.  Loading the checkpoint and
    // seeding the clock ensures the first post-restart timestamp is strictly
    // greater than any previously emitted one.
    // Do NOT remove the checkpoint load; do NOT seed the clock with zero on startup.
    // Load persisted HLC checkpoint so the first send() after restart is
    // strictly greater than any previously emitted timestamp (usenet-ipfs-gq0z).
    let hlc = {
        let clock = match load_hlc_checkpoint(&transit_pool).await {
            Ok(Some(checkpoint)) => {
                if checkpoint.node_id != [0u8; 8] && checkpoint.node_id != node_id {
                    warn!(
                        checkpoint_node_id = hex::encode(checkpoint.node_id),
                        instance_node_id   = hex::encode(node_id),
                        "HLC checkpoint node_id differs from current instance node_id; \
                         node identity may have changed since last run"
                    );
                }
                info!(
                    wall_ms = checkpoint.wall_ms,
                    logical = checkpoint.logical,
                    node_id = hex::encode(checkpoint.node_id),
                    "loaded HLC checkpoint"
                );
                HlcClock::new_seeded(node_id, now_ms, checkpoint)
            }
            Ok(None) => {
                info!("no HLC checkpoint found; starting from wall clock");
                HlcClock::new(node_id, now_ms)
            }
            Err(e) => {
                warn!("failed to load HLC checkpoint: {e}; starting from wall clock");
                HlcClock::new(node_id, now_ms)
            }
        };
        Arc::new(Mutex::new(clock))
    };

    // Background task: persist the HLC state every 30 seconds so that after a
    // restart the clock continues above the last emitted timestamp.
    {
        let hlc_bg = Arc::clone(&hlc);
        let pool_bg = transit_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let ts = hlc_bg.lock().await.last_timestamp();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if let Err(e) = save_hlc_checkpoint(&pool_bg, ts, now).await {
                    warn!("HLC checkpoint save failed: {e}");
                }
            }
        });
    }

    let (ingestion_sender, mut ingestion_receiver) = ingestion_queue(
        config.ingest.max_pending_articles,
        config.ingest.max_pending_bytes,
    );
    let ingestion_sender = Arc::new(ingestion_sender);

    // ── Optional TLS acceptor for inbound peering ─────────────────────────────

    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = if let Some(ref tls_cfg) = config.tls
    {
        let server_config_result = if tls_cfg.key_path.starts_with("secretx:") {
            let store = match secretx::from_uri(&tls_cfg.key_path) {
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
            stoa_tls::load_tls_server_config_with_key_bytes(
                &tls_cfg.cert_path,
                secret.as_bytes(),
                &tls_cfg.key_path,
            )
        } else {
            stoa_tls::load_tls_server_config(&tls_cfg.cert_path, &tls_cfg.key_path)
        };
        match server_config_result {
            Ok(server_config) => {
                info!("peering TLS enabled");
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(server_config)))
            }
            Err(e) => {
                eprintln!("error: failed to load peering TLS config: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Extract GC config before config.staging is moved (partial move workaround).
    let gc_kubo_url: Option<String> = config.kubo_api_url().map(|s| s.to_string());
    let gc_max_age_days: u64 = config.gc.max_age_days;
    let gc_pinning_rules: Vec<String> = config.pinning.rules.clone();
    let db_url_is_pg: bool = config.database.url.starts_with("postgres");

    // ── Write-ahead staging area (optional) ───────────────────────────────────

    let staging_store: Option<Arc<StagingStore>> = if let Some(staging_cfg) = config.staging {
        match tokio::fs::create_dir_all(&staging_cfg.path).await {
            Ok(()) => {
                info!(path = %staging_cfg.path, "write-ahead staging directory ready");
                Some(Arc::new(StagingStore::new(
                    staging_cfg,
                    Arc::clone(&transit_pool),
                )))
            }
            Err(e) => {
                eprintln!("error: could not create staging directory: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // ── Live-reloadable state (group filter + trusted keys) ───────────────────

    let reload_state = ReloadableState::new(
        config_path.clone(),
        group_filter.clone(),
        trusted_keys.clone(),
        config.groups.names.clone(),
        config.peering.trusted_peers.clone(),
        config.log.level.clone(),
    );

    // ── Shared state for peering sessions ─────────────────────────────────────

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::clone(&ipfs_store),
        msgid_map: Arc::clone(&msgid_map),
        signing_key: Arc::clone(&signing_key),
        hlc: Arc::clone(&hlc),
        ingestion_sender: Arc::clone(&ingestion_sender),
        local_hostname: local_hostname.clone(),
        // Per-IP rate limiter: all connections from one host share this budget.
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            config.peering.rate_limit_rps,
            config.peering.rate_limit_burst,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::clone(&transit_pool),
        blacklist_config: BlacklistConfig {
            failure_threshold: config.peering.blacklist_failure_threshold,
            duration_secs: config.peering.blacklist_duration_secs,
        },
        trusted_keys: Arc::clone(&reload_state.trusted_keys),
        tls_acceptor,
        staging: staging_store.clone(),
        verification_store: Some(Arc::clone(&verification_store)),
        dkim_authenticator: Some(Arc::clone(&dkim_authenticator)),
    });

    // ── Pipeline drain task ───────────────────────────────────────────────────

    // Shared IPFS write latency monitor — records every pipeline's IPFS write
    // duration and activates backpressure when the EMA exceeds the threshold.
    let ipfs_latency_monitor = IpfsLatencyMonitor::new_default();

    // Extract (service_name, filter) pairs for the pipeline hook.
    // Avoids moving the full config (with PinningApiKey) into the async closure.
    // GroupFilter patterns were validated in Config::validate(), so expect() cannot fail.
    let pin_service_filters: Vec<(String, GroupPolicy)> = config
        .pinning
        .external_services
        .iter()
        .map(|svc| {
            let filter = if svc.groups.is_empty() {
                None
            } else {
                Some(Arc::new(GroupFilter::new(&svc.groups).expect(
                    "config already validated pin service group patterns",
                )))
            };
            (svc.name.clone(), filter)
        })
        .collect();

    // Pre-clone values that both drain tasks need.  String::clone is a heap copy.
    let ipns_tx_staging = ipns_tx.clone();
    let local_hostname_staging = local_hostname.clone();
    let pin_service_filters_staging = pin_service_filters.clone();
    let verification_store_staging = Arc::clone(&verification_store);
    let dkim_authenticator_staging = Arc::clone(&dkim_authenticator);
    let reload_state_staging = Arc::clone(&reload_state);

    // Clone the metrics Arc before moving the sender into PeeringShared, so we can
    // read queue depth from the drain timeout log without holding a Sender (which
    // would prevent the channel from closing — see nzr6.17).
    let ingestion_metrics = ingestion_sender.clone_metrics();

    let ingestion_handle = {
        let ipfs = Arc::clone(&ipfs_store);
        let msgid_map_drain = Arc::clone(&msgid_map);
        let log_storage_drain = Arc::clone(&log_storage);
        let signing_key_drain = Arc::clone(&signing_key);
        let hlc_drain = Arc::clone(&hlc);
        let local_hostname_drain = local_hostname;
        let transit_pool_drain = Arc::clone(&transit_pool);
        let ingestion_metrics_task = Arc::clone(&ingestion_metrics);
        let ipns_tx_drain = ipns_tx;
        let verification_store_drain = Arc::clone(&verification_store);
        let dkim_authenticator_drain = Arc::clone(&dkim_authenticator);
        let reload_drain = Arc::clone(&reload_state);
        let latency_monitor_drain = Arc::clone(&ipfs_latency_monitor);

        tokio::spawn(async move {
            while let Some(article) = ingestion_receiver.recv().await {
                stoa_transit::metrics::INGESTION_QUEUE_DEPTH
                    .set(ingestion_metrics_task.current_depth() as i64);
                let trusted_keys_snap = Arc::from(reload_drain.trusted_keys.read().await.clone());
                let group_filter_current = reload_drain.group_filter.read().await.clone();
                let pipeline_args = PipelineArgs {
                    hlc: &hlc_drain,
                    signing_key: Arc::clone(&signing_key_drain),
                    local_hostname: &local_hostname_drain,
                    verify_store: Some(&verification_store_drain),
                    trusted_keys: trusted_keys_snap,
                    dkim_auth: Some(&dkim_authenticator_drain),
                    group_filter: group_filter_current,
                    ipfs: &*ipfs,
                    msgid_map: &msgid_map_drain,
                    log_storage: log_storage_drain.as_ref(),
                    transit_pool: &transit_pool_drain,
                    ipns_tx: &ipns_tx_drain,
                    pin_service_filters: &pin_service_filters,
                    ipfs_latency_monitor: Arc::clone(&latency_monitor_drain),
                };
                run_pipeline_and_notify(
                    &article.bytes,
                    &article.message_id,
                    "article ingested",
                    &pipeline_args,
                )
                .await;
            }
            info!("ingestion drain task stopped");
        })
    };

    // ── Staging drain task (only when [staging] is configured) ────────────────

    let mut staging_shutdown_opt: Option<tokio::sync::watch::Sender<bool>> = None;
    let mut staging_drain_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if let Some(staging) = staging_store {
        // Log how many articles survived the previous run.
        match staging.pending_count().await {
            Ok(n) if n > 0 => info!(count = n, "re-draining staged articles from previous run"),
            _ => {}
        }
        // Clear stale claims left by a previous run that crashed after claiming
        // but before completing an article, so they can be re-drained.
        if let Err(e) = staging.reset_claims().await {
            warn!("staging: reset_claims failed: {e}");
        }
        // Remove orphaned staging files: written by try_stage but never
        // committed to the DB (e.g. future cancelled on peer disconnect).
        match staging.cleanup_orphaned_files().await {
            Ok(0) => {}
            Ok(n) => info!(
                count = n,
                "staging: removed orphaned files from previous run"
            ),
            Err(e) => warn!("staging: cleanup_orphaned_files failed: {e}"),
        }

        let (staging_shutdown_tx, staging_shutdown_rx) = tokio::sync::watch::channel(false);
        staging_shutdown_opt = Some(staging_shutdown_tx);

        let drain_workers = staging.config.drain_workers.max(1) as usize;
        info!(drain_workers, "starting staging drain workers");

        for _ in 0..drain_workers {
            let staging = Arc::clone(&staging);
            let mut staging_shutdown_rx = staging_shutdown_rx.clone();
            let ipfs = Arc::clone(&ipfs_store);
            let msgid_map_drain = Arc::clone(&msgid_map);
            let log_storage_drain = Arc::clone(&log_storage);
            let signing_key_drain = Arc::clone(&signing_key);
            let hlc_drain = Arc::clone(&hlc);
            let local_hostname_drain = local_hostname_staging.clone();
            let transit_pool_drain = Arc::clone(&transit_pool);
            let ipns_tx_drain = ipns_tx_staging.clone();
            let pin_service_filters = pin_service_filters_staging.clone();
            let verification_store_drain = Arc::clone(&verification_store_staging);
            let dkim_authenticator_drain = Arc::clone(&dkim_authenticator_staging);
            let reload_staging = Arc::clone(&reload_state_staging);
            let latency_monitor_staging = Arc::clone(&ipfs_latency_monitor);

            staging_drain_handles.push(tokio::spawn(async move {
                loop {
                    match staging.drain_one().await {
                        Ok(None) => {
                            tokio::select! {
                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                                _ = staging_shutdown_rx.changed() => { break; }
                            }
                        }
                        Ok(Some(article)) => {
                            let trusted_keys_snap =
                                Arc::from(reload_staging.trusted_keys.read().await.clone());
                            let group_filter_current =
                                reload_staging.group_filter.read().await.clone();
                            let pipeline_args = PipelineArgs {
                                hlc: &hlc_drain,
                                signing_key: Arc::clone(&signing_key_drain),
                                local_hostname: &local_hostname_drain,
                                verify_store: Some(&verification_store_drain),
                                trusted_keys: trusted_keys_snap,
                                dkim_auth: Some(&dkim_authenticator_drain),
                                group_filter: group_filter_current,
                                ipfs: &*ipfs,
                                msgid_map: &msgid_map_drain,
                                log_storage: log_storage_drain.as_ref(),
                                transit_pool: &transit_pool_drain,
                                ipns_tx: &ipns_tx_drain,
                                pin_service_filters: &pin_service_filters,
                                ipfs_latency_monitor: Arc::clone(&latency_monitor_staging),
                            };
                            // Maximum transient-failure retries before the article
                            // is treated as permanently broken and purged.
                            const MAX_STAGING_RETRIES: i64 = 10;

                            match run_pipeline_and_notify(
                                &article.bytes,
                                &article.message_id,
                                "staged article ingested",
                                &pipeline_args,
                            )
                            .await
                            {
                                PipelineOutcome::Success => {
                                    if let Err(e) = staging.complete(&article).await {
                                        warn!(
                                            msgid = %article.message_id,
                                            "could not complete staging record: {e}"
                                        );
                                    }
                                }
                                PipelineOutcome::PermanentFailure => {
                                    warn!(
                                        msgid = %article.message_id,
                                        "permanent pipeline failure; purging staging row"
                                    );
                                    if let Err(e) = staging.purge(&article).await {
                                        warn!(
                                            msgid = %article.message_id,
                                            "could not purge staging record: {e}"
                                        );
                                    }
                                }
                                PipelineOutcome::TransientFailure => {
                                    match staging.increment_retry_count(&article).await {
                                        Ok(new_count) if new_count >= MAX_STAGING_RETRIES => {
                                            warn!(
                                                msgid = %article.message_id,
                                                retry_count = new_count,
                                                "transient failure exceeded max retries; \
                                                 purging staging row"
                                            );
                                            if let Err(e) = staging.purge(&article).await {
                                                warn!(
                                                    msgid = %article.message_id,
                                                    "could not purge staging record: {e}"
                                                );
                                            }
                                        }
                                        Ok(new_count) => {
                                            warn!(
                                                msgid = %article.message_id,
                                                retry_count = new_count,
                                                "transient failure; will retry"
                                            );
                                        }
                                        Err(e) => {
                                            warn!(
                                                msgid = %article.message_id,
                                                "could not increment retry count: {e}; \
                                                 article remains claimed until next restart"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("staging drain error: {e}");
                            tokio::select! {
                                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                                _ = staging_shutdown_rx.changed() => { break; }
                            }
                        }
                    }
                }
                info!("staging drain task stopped");
            }));
        }
    }

    // ── Peering TCP listener (atu) ────────────────────────────────────────────

    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind {}: {e}", config.listen.addr);
            std::process::exit(1);
        }
    };
    info!(addr = %config.listen.addr, "peering TCP listener bound");

    // ── GC runner (pre-constructed for admin last_report handle) ─────────────
    // Build the runner before the admin server so its last_report handle can
    // be wired into `GET /gc/last-run`.  The runner is moved into
    // start_gc_scheduler below.
    let gc_pre_pin_rules: Vec<PinRule> = gc_pinning_rules
        .iter()
        .filter_map(|r| match r.as_str() {
            "pin-all" => Some(PinRule {
                groups: "all".to_string(),
                max_age_days: Some(gc_max_age_days),
                max_article_bytes: None,
                action: PinAction::Pin,
            }),
            other => {
                warn!(rule = other, "GC: unrecognised pinning rule, ignored");
                None
            }
        })
        .collect();
    let (gc_runner_pre, gc_last_report) = if gc_kubo_url.is_some() && !gc_pre_pin_rules.is_empty() {
        let policy = PinPolicy::new(gc_pre_pin_rules.clone());
        if let Err(e) = policy.validate() {
            eprintln!("error: invalid retention policy: {e}");
            std::process::exit(1);
        }
        let pin_client = HttpPinClient::new(gc_kubo_url.as_deref().unwrap().to_string());
        let gc_metrics = GcMetrics::new();
        let runner = GcRunner::new(pin_client, policy, gc_metrics)
            .with_report_dir(config.gc.report_dir.clone())
            .with_pools((*transit_pool).clone(), (*core_pool).clone());
        let handle = runner.last_report_handle();
        (Some(runner), Some(handle))
    } else {
        (None, None)
    };

    // ── Admin HTTP server (5vc) ───────────────────────────────────────────────

    {
        // admin_listener was bound in run_startup_checks; reuse it here to
        // eliminate the race window between the connectivity test and the
        // server bind (bug 29ad).
        let admin_listener = admin_listener
            .expect("admin_listener must be Some when startup checks passed without errors");
        let admin_bearer_token = stoa_core::secret::resolve_secret_uri(
            config.admin.bearer_token.clone(),
            "admin.bearer_token",
        )
        .await
        .unwrap_or_else(|msg| {
            eprintln!("{msg}");
            std::process::exit(1);
        });
        let admin_audit_logger: Arc<dyn AuditLogger> = Arc::new(start_audit_logger(
            (*core_pool).clone(),
            100,
            Duration::from_secs(5),
        ));
        let admin_cert_paths: Arc<Vec<String>> = Arc::new(
            config
                .tls
                .as_ref()
                .map(|t| t.cert_path.clone())
                .into_iter()
                .collect(),
        );
        if let Err(e) = start_admin_server(
            admin_listener,
            AdminPools {
                transit_pool: Arc::clone(&transit_pool),
                core_pool: Arc::clone(&core_pool),
                audit_logger: Some(admin_audit_logger),
                backup_dest_dir: config.backup.dest_dir.clone(),
                reload_state: Some(Arc::clone(&reload_state)),
                ipfs_api_url: Some(config.ipfs.api_url.clone()),
                last_gc_report: gc_last_report,
            },
            start_time,
            admin_bearer_token,
            config.admin.rate_limit_rpm,
            Arc::clone(&ipfs_store),
            ipns_path_string.clone(),
            admin_cert_paths,
        ) {
            eprintln!("error: admin server: {e}");
            std::process::exit(1);
        }
    }

    // ── Scheduled backup (optional) ───────────────────────────────────────────

    if let (Some(schedule), Some(dest_dir)) = (
        config.backup.schedule.clone(),
        config.backup.dest_dir.clone(),
    ) {
        info!(schedule = %schedule, "backup scheduler starting");
        tokio::spawn(stoa_transit::backup_scheduler::run_backup_scheduler(
            Arc::clone(&transit_pool),
            Arc::clone(&core_pool),
            dest_dir,
            config.backup.s3_bucket.clone(),
            config.backup.s3_prefix.clone(),
            schedule,
        ));
    }

    // ── Per-group metrics sampler ─────────────────────────────────────────────

    tokio::spawn(stoa_transit::group_metrics::run_group_metrics_sampler(
        Arc::clone(&transit_pool),
        std::time::Duration::from_secs(60),
    ));

    // ── GC scheduler (ky62.4) ─────────────────────────────────────────────────
    //
    // Only started when a Kubo API URL is configured (required for unpin).
    // The GC interval is hardcoded to 1 hour; the cron schedule in config.gc
    // is reserved for a future cron-expression parser.
    //
    // PG deployments use pg_try_advisory_lock(GC_ADVISORY_LOCK_ID) so that
    // exactly one instance runs GC at a time.

    if let Some(runner) = gc_runner_pre {
        let policy_for_candidates = PinPolicy::new(gc_pre_pin_rules);
        let gc_transit = Arc::clone(&transit_pool);
        let grace_ms = gc_max_age_days.saturating_mul(24 * 60 * 60 * 1000);

        let candidates_fn = move || {
            let pool = Arc::clone(&gc_transit);
            let pol = policy_for_candidates.clone();
            async move {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                select_gc_candidates(&pool, &pol, now, grace_ms)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(Into::into)
                    .collect()
            }
        };

        let gc_lock = if db_url_is_pg {
            Some((*transit_pool).clone())
        } else {
            None
        };

        start_gc_scheduler(runner, Duration::from_secs(3600), candidates_fn, gc_lock).await;
        info!(interval_secs = 3600, "GC scheduler started");
    }

    // ── SIGHUP config reload ──────────────────────────────────────────────────

    {
        let reload_for_sighup = Arc::clone(&reload_state);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup =
                signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
            loop {
                sighup.recv().await;
                info!("received SIGHUP, reloading config");
                let result = reload_for_sighup.do_reload().await;
                info!(
                    changed = ?result.changed,
                    errors = ?result.errors,
                    "config reload complete"
                );
            }
        });
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    let drain_timeout_secs = config.peering.drain_timeout_secs.unwrap_or(30);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
        result = accept_loop(listener, shared) => {
            if let Err(e) = result {
                warn!("accept loop error: {e}");
            }
        }
    }

    // Signal the staging drain tasks to stop (if running), then wait briefly.
    if let Some(shutdown_tx) = staging_shutdown_opt {
        let _ = shutdown_tx.send(true);
        for staging_handle in staging_drain_handles {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(drain_timeout_secs),
                staging_handle,
            )
            .await;
        }
    }

    // Signal the ingestion task to stop by dropping the last sender, then
    // wait for it to finish processing any queued articles.
    info!("shutting down, draining ingestion queue");
    drop(ingestion_sender);
    let drain_result = tokio::time::timeout(
        std::time::Duration::from_secs(drain_timeout_secs),
        ingestion_handle,
    )
    .await;
    match drain_result {
        Ok(Ok(())) => {
            info!("ingestion task drained cleanly");
        }
        Ok(Err(e)) => {
            warn!("ingestion task panicked: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            let remaining = ingestion_metrics.current_depth();
            warn!(
                remaining_queue_depth = remaining,
                "ingestion drain timeout, forcing exit"
            );
            std::process::exit(1);
        }
    }

    info!("stoa-transit stopped");
}

async fn accept_loop(listener: TcpListener, shared: Arc<PeeringShared>) -> std::io::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let peer_addr = addr.to_string();
        let peer_ip = addr.ip();
        tracing::debug!(%peer_addr, "new peering connection");
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Some(ref acceptor) = shared.tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        run_peering_session(tls_stream, peer_addr, peer_ip, shared).await;
                    }
                    Err(e) => {
                        tracing::warn!(%peer_addr, "peering TLS accept failed: {e}");
                    }
                }
            } else {
                run_peering_session(stream, peer_addr, peer_ip, shared).await;
            }
        });
    }
}

/// Resolve the local FQDN for use in the `Path:` header.
///
/// Tries `/etc/hostname` first (reliable on Linux), then falls back to
/// `"localhost"`.  Operators should set `operator.hostname` in config.
fn resolve_local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
