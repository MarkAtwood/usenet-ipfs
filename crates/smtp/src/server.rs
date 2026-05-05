use std::str::FromStr as _;
use std::sync::Arc;

use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::dns_cache::DnsCache;
use crate::queue::NntpQueue;
use crate::session::{run_session, SieveCache};
use crate::tls::{accept_tls, TlsAcceptor};

/// Accept connections on the port-25, port-587, and optional SMTPS (port 465)
/// listeners, spawning a `run_session` task for each.  Returns when all
/// listeners close or an unrecoverable error occurs.
///
/// `listener_smtps` — optional implicit-TLS listener.
/// `starttls_acceptor` — when `Some`, ports 25/587 advertise and handle STARTTLS.
#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    listener_25: TcpListener,
    listener_587: TcpListener,
    listener_smtps: Option<(TcpListener, TlsAcceptor)>,
    starttls_acceptor: Option<Arc<TlsAcceptor>>,
    config: Arc<Config>,
    nntp_queue: Arc<NntpQueue>,
    pool: Option<SqlitePool>,
    sieve_cache: Option<SieveCache>,
) -> Result<(), String> {
    // Open the mail database if configured.  Uses create_if_missing(false) so
    // we never create the file — the mail binary is responsible for migrations.
    let mail_pool: Option<SqlitePool> = if let Some(ref path) = config.delivery.mail_db_path {
        let url = format!("sqlite:{path}");
        match sqlx::sqlite::SqliteConnectOptions::from_str(&url)
            .map(|opts| opts.create_if_missing(false))
        {
            Ok(opts) => {
                match sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(3)
                    .connect_with(opts)
                    .await
                {
                    Ok(p) => {
                        info!(path = %path, "mail DB opened; SMTP→JMAP bridge enabled");
                        Some(p)
                    }
                    Err(e) => {
                        warn!(path = %path, "mail DB open failed: {e}; SMTP→JMAP bridge disabled");
                        None
                    }
                }
            }
            Err(e) => {
                warn!(path = %path, "mail DB URL parse failed: {e}");
                None
            }
        }
    } else {
        None
    };
    // Look up the INBOX mailbox_id once at startup so per-message delivery
    // never needs to query it again (lnc3.23).
    let inbox_mailbox_id: Option<String> = if let Some(ref mp) = mail_pool {
        sqlx::query_scalar("SELECT mailbox_id FROM mailboxes WHERE role = 'inbox'")
            .fetch_optional(mp)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let auth: Option<Arc<MessageAuthenticator>> = {
        let result = match config.dns_resolver {
            crate::config::DnsResolver::Cloudflare => MessageAuthenticator::new_cloudflare(),
            crate::config::DnsResolver::Google => MessageAuthenticator::new_google(),
            crate::config::DnsResolver::Quad9 => MessageAuthenticator::new_quad9(),
            crate::config::DnsResolver::System => MessageAuthenticator::new_system_conf(),
        };
        match result {
            Ok(a) => {
                info!(resolver = %config.dns_resolver, "inbound auth (SPF/DKIM/DMARC/ARC) enabled");
                Some(Arc::new(a))
            }
            Err(e) => {
                warn!("failed to create DNS resolver — inbound auth disabled: {e}");
                None
            }
        }
    };

    // DNS record cache shared across all SMTP sessions.  One instance per
    // server process; entries are keyed by domain/IP and expire on first
    // read after their TTL.
    let dns_cache = Arc::new(DnsCache::new());

    // Build the credential store once at startup and share it across sessions.
    // credential_file may be a filesystem path or a secretx: URI.
    let credential_store = Arc::new(
        stoa_auth::build_credential_store(
            &config.auth.users,
            config.auth.credential_file.as_deref(),
        )
        .await
        .map_err(|e| format!("failed to build credential store: {e}"))?,
    );

    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));

    loop {
        // Acquire a permit before accepting so we apply back-pressure when
        // the connection limit is reached (same pattern as stoa-reader).
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("connection semaphore closed, stopping accept loop");
                break;
            }
        };

        // Unified accepted-connection enum so both branches of the select!
        // produce the same type.  TLS handshake happens inline in the SMTPS
        // branch so that handshake failures never reach the session.
        // `is_submission` is true for port-587 connections so that AUTH PLAIN
        // is advertised to mail clients even on plaintext sessions.
        enum Accepted {
            Plain(tokio::net::TcpStream, std::net::SocketAddr, bool),
            Tls(
                Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
                std::net::SocketAddr,
            ),
        }

        let accepted = if let Some((ref smtps_listener, ref tls_acceptor)) = listener_smtps {
            tokio::select! {
                result = listener_25.accept() => match result {
                    Ok((s, a)) => Accepted::Plain(s, a, false),
                    Err(e) => {
                        error!("port_25 accept error: {e}");
                        drop(permit);
                        continue;
                    }
                },
                result = listener_587.accept() => match result {
                    Ok((s, a)) => Accepted::Plain(s, a, true),
                    Err(e) => {
                        error!("port_587 accept error: {e}");
                        drop(permit);
                        continue;
                    }
                },
                result = smtps_listener.accept() => match result {
                    Ok((tcp_stream, peer_addr)) => {
                        match accept_tls(tls_acceptor, tcp_stream).await {
                            Ok(tls_stream) => Accepted::Tls(Box::new(tls_stream), peer_addr),
                            Err(e) => {
                                debug!(peer = %peer_addr, "SMTPS TLS handshake failed: {e}");
                                drop(permit);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        error!("smtps accept error: {e}");
                        drop(permit);
                        continue;
                    }
                },
            }
        } else {
            tokio::select! {
                result = listener_25.accept() => match result {
                    Ok((s, a)) => Accepted::Plain(s, a, false),
                    Err(e) => {
                        error!("port_25 accept error: {e}");
                        drop(permit);
                        continue;
                    }
                },
                result = listener_587.accept() => match result {
                    Ok((s, a)) => Accepted::Plain(s, a, true),
                    Err(e) => {
                        error!("port_587 accept error: {e}");
                        drop(permit);
                        continue;
                    }
                },
            }
        };

        let config = config.clone();
        let nntp_queue = Arc::clone(&nntp_queue);
        let auth = auth.clone();
        let dns_cache_clone = Arc::clone(&dns_cache);
        let pool = pool.clone();
        let mail_pool_clone = mail_pool.clone();
        let cache = sieve_cache.clone();
        let cred_store = Arc::clone(&credential_store);
        let inbox_id = inbox_mailbox_id.clone();
        let starttls = starttls_acceptor.clone();

        match accepted {
            Accepted::Plain(stream, peer_addr, is_submission) => {
                let peer_str = peer_addr.to_string();
                info!(%peer_str, is_submission, "accepted plaintext connection");
                tokio::spawn(async move {
                    let _permit = permit;
                    run_session(
                        Box::new(stream),
                        false,
                        is_submission,
                        peer_str,
                        config,
                        cred_store,
                        nntp_queue,
                        auth,
                        dns_cache_clone,
                        pool,
                        mail_pool_clone,
                        cache,
                        inbox_id,
                        starttls,
                    )
                    .await;
                });
            }
            Accepted::Tls(tls_stream, peer_addr) => {
                let peer_str = peer_addr.to_string();
                info!(%peer_str, "accepted SMTPS connection");
                tokio::spawn(async move {
                    let _permit = permit;
                    run_session(
                        Box::new(*tls_stream),
                        true,
                        false,
                        peer_str,
                        config,
                        cred_store,
                        nntp_queue,
                        auth,
                        dns_cache_clone,
                        pool,
                        mail_pool_clone,
                        cache,
                        inbox_id,
                        None,
                    )
                    .await;
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, DatabaseConfig, DeliveryConfig, LimitsConfig, ListenConfig, LogConfig,
        ReaderConfig, SieveAdminConfig, TlsConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: crate::config::LogFormat::Text,
            },
            reader: ReaderConfig::default(),
            delivery: DeliveryConfig::default(),
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: crate::config::DnsResolver::System,
            auth: AuthConfig::default(),
            peer_whitelist: vec![],
            mta_sts: Default::default(),
            shutdown: Default::default(),
        })
    }

    /// Spin up run_server on ephemeral ports and verify the greeting arrives.
    #[tokio::test]
    async fn server_sends_greeting_on_connect() {
        let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_25 = listener_25.local_addr().unwrap();

        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");

        tokio::spawn(run_server(
            listener_25,
            listener_587,
            None,
            None,
            config,
            nntp_queue,
            None,
            None,
        ));

        let mut client = tokio::net::TcpStream::connect(addr_25).await.unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let greeting = std::str::from_utf8(&buf[..n]).unwrap();

        assert!(
            greeting.starts_with("220 "),
            "expected SMTP greeting, got: {greeting:?}"
        );
    }

    /// Two simultaneous connections both get greeted (semaphore not exhausted).
    #[tokio::test]
    async fn server_handles_multiple_connections() {
        let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_25 = listener_25.local_addr().unwrap();
        let addr_587 = listener_587.local_addr().unwrap();

        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path(), None).expect("NntpQueue::new");

        tokio::spawn(run_server(
            listener_25,
            listener_587,
            None,
            None,
            config,
            nntp_queue,
            None,
            None,
        ));

        // Connect to port_25 and port_587 concurrently.
        let (c1, c2) = tokio::join!(
            tokio::net::TcpStream::connect(addr_25),
            tokio::net::TcpStream::connect(addr_587),
        );
        let mut c1 = c1.unwrap();
        let mut c2 = c2.unwrap();

        let mut buf1 = [0u8; 256];
        let mut buf2 = [0u8; 256];
        let (n1, n2) = tokio::join!(c1.read(&mut buf1), c2.read(&mut buf2));

        let g1 = std::str::from_utf8(&buf1[..n1.unwrap()]).unwrap();
        let g2 = std::str::from_utf8(&buf2[..n2.unwrap()]).unwrap();

        assert!(g1.starts_with("220 "), "conn1 expected 220: {g1:?}");
        assert!(g2.starts_with("220 "), "conn2 expected 220: {g2:?}");

        // Send QUIT on both connections.
        c1.write_all(b"QUIT\r\n").await.unwrap();
        c2.write_all(b"QUIT\r\n").await.unwrap();
    }
}
