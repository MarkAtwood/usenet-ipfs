//! `stoa-rnews` — batch ingest articles from a UUCP rnews batch on stdin.
//!
//! Reads a `#! rnews` batch from stdin, parses it into individual articles,
//! and ingests each through the transit pipeline.  Designed for use as a
//! UUCP rnews handler or offline batch injector.
//!
//! Exit codes:
//!   0 — batch processed (some articles may have been rejected individually)
//!   1 — configuration error, migration failure, or stdin parse failure
//!  75 — EX_TEMPFAIL: transient infrastructure errors occurred; UUCP should retry

use std::{path::PathBuf, sync::Arc};

use rand_core::OsRng;
use stoa_core::{group_log::SqliteLogStorage, hlc::HlcClock, msgid_map::MsgIdMap};
use stoa_transit::{
    hlc_persist::load_hlc_checkpoint,
    import::rnews::parse_rnews_batch,
    instance_id::ensure_instance_node_id,
    peering::{
        ingestion::{check_ingest, extract_body_msgid, IngestResult},
        pipeline::{run_pipeline, PipelineCtx, PipelineError},
    },
    rnews_config::{build_store_for_rnews, RnewsConfig},
};

// ── CLI parsing ───────────────────────────────────────────────────────────────

struct Args {
    config_path: PathBuf,
    check_only: bool,
}

fn print_usage() {
    eprintln!("Usage: stoa-rnews --config <path> [--check]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --config <path>   Path to rnews.toml configuration file (required)");
    eprintln!("  --check           Validate configuration and exit without processing stdin");
    eprintln!("  --help, -h        Show this help message");
    eprintln!("  --version         Show version information");
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1).peekable();
    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => match args.next() {
                Some(path) => config_path = Some(PathBuf::from(path)),
                None => {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            },
            "--check" => check_only = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" => {
                eprintln!("stoa-rnews {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            arg => {
                eprintln!("error: unknown argument: {arg}");
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("error: --config <path> is required");
            std::process::exit(1);
        }
    };

    Args {
        config_path,
        check_only,
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sqlx::any::install_default_drivers();

    let args = parse_args();

    // Load config.
    let config = match RnewsConfig::from_file(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to load config from {}: {}",
                args.config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    // Init tracing.
    {
        use stoa_transit::config::LogFormat;
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log.level));

        let (json_fmt, text_fmt) = if config.log.format == LogFormat::Json {
            (Some(tracing_subscriber::fmt::layer().json()), None)
        } else {
            (None, Some(tracing_subscriber::fmt::layer()))
        };
        tracing_subscriber::registry()
            .with(filter)
            .with(json_fmt)
            .with(text_fmt)
            .init();
    }

    // Run migrations.
    if let Err(e) = stoa_core::migrations::run_migrations(&config.database.core_url).await {
        eprintln!("error: core database migration failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = stoa_transit::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: transit database migration failed: {e}");
        std::process::exit(1);
    }

    // Open pools.
    // AnyPool is internally reference-counted; no Arc wrapper needed.
    let core_pool: sqlx::AnyPool =
        match stoa_core::db_pool::try_open_any_pool(&config.database.core_url, 3).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: failed to open core pool: {e}");
                std::process::exit(1);
            }
        };
    let transit_pool: sqlx::AnyPool =
        match stoa_core::db_pool::try_open_any_pool(&config.database.url, 3).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: failed to open transit pool: {e}");
                std::process::exit(1);
            }
        };

    // Build IPFS store.
    let ipfs_store = match build_store_for_rnews(&config).await {
        Ok(r) => r.store,
        Err(e) => {
            eprintln!("error: failed to build IPFS store: {e}");
            std::process::exit(1);
        }
    };

    // Build msgid_map and log_storage.
    let msgid_map = MsgIdMap::new(core_pool.clone());
    let log_storage = SqliteLogStorage::new(core_pool.clone());

    // Load or generate signing key.
    let signing_key = Arc::new(match config.operator.signing_key_path.as_deref() {
        Some(path) if !path.is_empty() => {
            match stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
                Ok(k) => {
                    tracing::info!(path, "loaded operator signing key");
                    k
                }
                Err(e) => {
                    eprintln!("error: cannot load operator signing key from '{path}': {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            tracing::warn!(
                "using ephemeral signing key \
                     — articles will not be re-verifiable across restarts"
            );
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        }
    });

    // Resolve local hostname.
    let hostname: String = config
        .operator
        .hostname
        .clone()
        .unwrap_or_else(resolve_local_hostname);

    // Build HLC clock. Owned locally; each article gets a timestamp via send().
    let mut hlc = {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default() // safe: only fails if system clock is before 1970, which cannot happen in practice
            .as_millis() as u64;
        let node_id = ensure_instance_node_id(&transit_pool, &hostname).await;
        match load_hlc_checkpoint(&transit_pool).await {
            Ok(Some(checkpoint)) => HlcClock::new_seeded(node_id, now_ms, checkpoint),
            Ok(None) => HlcClock::new(node_id, now_ms),
            Err(e) => {
                tracing::warn!("failed to load HLC checkpoint: {e}; starting from wall clock");
                HlcClock::new(node_id, now_ms)
            }
        }
    };

    // --check: config validated, infrastructure reachable — exit 0.
    if args.check_only {
        tracing::info!("config OK");
        return Ok(());
    }

    // Read stdin.
    let mut stdin_bytes: Vec<u8> = Vec::new();
    {
        use std::io::Read;
        if let Err(e) = std::io::stdin().read_to_end(&mut stdin_bytes) {
            eprintln!("error: failed to read stdin: {e}");
            std::process::exit(1);
        }
    }
    // Cap raw stdin read at 1 GiB to prevent trivially unbounded input.
    // For compressed (#! gunbatch) batches, the wire size may be much smaller
    // than the decompressed content — the real cap is enforced in
    // decompress_gunbatch (.take(limit+1)) and parse_rnews_batch_plain
    // per article (MAX_RNEWS_ARTICLE_BYTES).
    const MAX_STDIN_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB
    if stdin_bytes.len() > MAX_STDIN_BYTES {
        eprintln!("error: stdin exceeds maximum raw batch size (1 GiB)");
        std::process::exit(1);
    }

    // Parse the batch.
    let articles = match parse_rnews_batch(&stdin_bytes) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("failed to parse rnews batch: {e}");
            eprintln!("error: failed to parse rnews batch: {e}");
            std::process::exit(1);
        }
    };

    let total = articles.len();
    let mut accepted: u64 = 0;
    let mut filtered: u64 = 0;
    let mut duplicates: u64 = 0;
    let mut rejected: u64 = 0;
    let mut transient: u64 = 0;

    // Hoist trusted_keys allocation outside the loop — one allocation, not one per article.
    let trusted_keys: Arc<[ed25519_dalek::VerifyingKey]> = Arc::from(vec![].into_boxed_slice());

    // Process each article.
    for article_bytes in &articles {
        // Extract Message-ID from article body (RFC 5322 folding-aware).
        let message_id = match extract_body_msgid(article_bytes) {
            Some(id) => id,
            None => {
                tracing::warn!("article missing Message-ID, skipping");
                rejected += 1;
                continue;
            }
        };

        // Pre-check: validate and dedup.
        let ingest_result = check_ingest(&message_id, article_bytes, &msgid_map).await;

        match ingest_result {
            IngestResult::Accepted => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default() // safe: only fails if system clock is before 1970, which cannot happen in practice
                    .as_millis() as u64;
                let timestamp = hlc.send(now_ms);

                let ctx = PipelineCtx {
                    timestamp,
                    operator_signing_key: Arc::clone(&signing_key),
                    local_hostname: &hostname,
                    verify_store: None,
                    trusted_keys: Arc::clone(&trusted_keys),
                    dkim_auth: None,
                    group_filter: None,
                };

                match run_pipeline(
                    article_bytes,
                    ipfs_store.as_ref(),
                    &msgid_map,
                    &log_storage,
                    &transit_pool,
                    ctx,
                )
                .await
                {
                    Ok((result, _metrics)) => {
                        if result.groups.is_empty() {
                            tracing::warn!(
                                cid = %result.cid,
                                msgid = %message_id,
                                "article stored but has no group log entries \
                                 (all Newsgroups rejected by group filter); \
                                 article is invisible to NNTP readers"
                            );
                            filtered += 1;
                        } else {
                            tracing::info!(cid = %result.cid, msgid = %message_id, "article accepted");
                            accepted += 1;
                        }
                    }
                    Err(PipelineError::Permanent(msg)) => {
                        tracing::warn!(msgid = %message_id, "pipeline permanent error: {msg}");
                        rejected += 1;
                    }
                    Err(PipelineError::Transient(msg)) => {
                        tracing::error!(msgid = %message_id, "pipeline transient error: {msg}");
                        transient += 1;
                    }
                }
            }
            IngestResult::Duplicate => {
                tracing::debug!(msgid = %message_id, "duplicate article, skipping");
                duplicates += 1;
            }
            IngestResult::Rejected(msg) => {
                tracing::warn!(msgid = %message_id, "article rejected: {msg}");
                rejected += 1;
            }
            IngestResult::TransientError(msg) => {
                tracing::error!(msgid = %message_id, "transient error during ingest check: {msg}");
                transient += 1;
            }
        }
    }

    if rejected > 0 || transient > 0 || filtered > 0 {
        tracing::warn!(
            accepted,
            filtered,
            duplicates,
            rejected,
            transient_errors = transient,
            total,
            "stoa-rnews batch complete"
        );
    } else {
        tracing::info!(
            accepted,
            filtered,
            duplicates,
            rejected,
            transient_errors = transient,
            total,
            "stoa-rnews batch complete"
        );
    }

    // Transient errors (database failures, store write failures) must signal
    // EX_TEMPFAIL (75) so the UUCP scheduler retries the batch.  Exit 0 would
    // tell UUCP the batch was fully processed, permanently losing those articles.
    if transient > 0 {
        tracing::error!(
            transient_errors = transient,
            "batch had transient errors; exiting EX_TEMPFAIL (75) so UUCP will retry"
        );
        std::process::exit(75); // EX_TEMPFAIL
    }

    // Exit 0: batch processed (individual rejections are permanent and expected).
    Ok(())
}

/// Resolve the local hostname for the `Path:` header.
///
/// Tries `/etc/hostname` first (reliable on Linux), then falls back to `"localhost"`.
/// Operators should set `operator.hostname` in config to avoid this fallback.
fn resolve_local_hostname() -> String {
    let name = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    match name {
        Some(h) => h,
        None => {
            tracing::warn!(
                "operator.hostname not set and /etc/hostname is empty; \
                 using 'localhost' for Path: header — set operator.hostname \
                 in config for production deployments"
            );
            "localhost".to_owned()
        }
    }
}
