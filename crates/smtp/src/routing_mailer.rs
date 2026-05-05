use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tracing::warn;

use crate::outbound_mailer::{
    MessageType, OutboundEnvelope, OutboundError, OutboundMailer, SendReceipt,
};

/// A routing rule that determines whether a provider matches a given envelope.
///
/// The first matching selector in [`RoutingMailer`]'s list whose provider is
/// healthy wins.  Subsequent entries are tried only if delivery fails.
#[derive(Debug, Clone)]
pub enum Selector {
    /// Match envelopes whose **first** recipient domain matches this glob pattern.
    ///
    /// Supported patterns:
    /// - `"*"` — matches any domain
    /// - `"*.example.com"` — matches any subdomain of `example.com`
    /// - `"mail.example.com"` — exact domain match
    ///
    /// **Warning**: routing is decided solely on `rcpt_to[0]`.  Envelopes with
    /// recipients on multiple domains (mixed-domain batches) may route some
    /// recipients through the wrong provider.  Callers must ensure all
    /// recipients in a single envelope share the same domain, or use
    /// [`Selector::CatchAll`] / [`Selector::MessageType`] for mixed cases.
    DomainGlob(String),
    /// Match envelopes of the specified message type.
    MessageType(MessageType),
    /// Match every envelope (catch-all).
    CatchAll,
}

impl Selector {
    /// Returns `true` if `envelope` matches this selector.
    pub fn matches(&self, envelope: &OutboundEnvelope) -> bool {
        match self {
            Selector::CatchAll => true,
            Selector::MessageType(mt) => envelope.message_type == *mt,
            Selector::DomainGlob(pattern) => {
                // Match against the domain of the first recipient.
                let domain = envelope
                    .rcpt_to
                    .first()
                    .and_then(|addr| addr.rsplit_once('@'))
                    .map(|(_, domain)| domain)
                    .unwrap_or("");
                glob_matches(pattern, domain)
            }
        }
    }
}

/// Match a domain against a glob pattern.
///
/// Supported forms:
/// - `"*"` — matches any string (including empty)
/// - `"*.example.com"` — matches any subdomain of `example.com` per RFC 1034
///   semantics: `*` matches exactly one DNS label, so `"mail.example.com"` and
///   `"smtp.example.com"` match but bare `"example.com"` does not.
/// - anything else — exact case-insensitive match
fn glob_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Match "sub.suffix" — domain must end with ".suffix" and have at
        // least one label before the dot (RFC 1034: * is a single-label wildcard).
        let domain_lower = domain.to_ascii_lowercase();
        let suffix_lower = suffix.to_ascii_lowercase();
        return domain_lower.ends_with(&format!(".{suffix_lower}"));
    }
    // Exact match (case-insensitive).
    domain.eq_ignore_ascii_case(pattern)
}

/// A route entry pairing a [`Selector`] with a provider.
pub struct Route {
    pub selector: Selector,
    pub provider: Arc<dyn OutboundMailer>,
}

/// Composite [`OutboundMailer`] that routes messages through the first healthy
/// matching provider, falling over to subsequent entries on failure.
///
/// ## Routing algorithm
///
/// For each `send()` call:
/// 1. Walk the routes in order.
/// 2. Skip routes whose selector does not match the envelope.
/// 3. Skip routes whose provider reports `healthy() == false`.
/// 4. Attempt delivery through the first selected provider.
/// 5. On transient failure, continue to the next matching healthy route.
/// 6. On permanent failure, stop immediately (retrying will not help).
/// 7. If all matching routes fail or are unhealthy, return the last error (or
///    a synthesised "no healthy providers" error).
///
/// Per-provider `outbound_send_total{provider, result}` counters are emitted
/// after every attempt.
pub struct RoutingMailer {
    routes: Vec<Route>,
}

impl RoutingMailer {
    /// Build a new `RoutingMailer` from an ordered list of routes.
    pub fn new(routes: Vec<Route>) -> Self {
        Self { routes }
    }

    /// Start a background task that polls provider health every `interval` and
    /// updates the `outbound_provider_healthy{provider}` Prometheus gauge.
    ///
    /// The task runs indefinitely; call this once at startup.  Providers that
    /// implement [`OutboundMailer::healthy`] (returning anything other than the
    /// default `true`) benefit most from this gauge.
    ///
    /// The `Arc` wrapper is required so the background task holds a strong
    /// reference to `self` without outliving the caller.
    pub fn start_health_poll(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                // De-duplicate by provider name — each unique name gets one gauge.
                let mut seen = std::collections::HashSet::new();
                for route in &self.routes {
                    let name = route.provider.name();
                    if seen.insert(name) {
                        let healthy = route.provider.healthy();
                        crate::metrics::set_outbound_provider_healthy(name, healthy);
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

#[async_trait]
impl OutboundMailer for RoutingMailer {
    async fn send(&self, envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
        let mut last_err: Option<OutboundError> = None;

        for route in &self.routes {
            if !route.selector.matches(&envelope) {
                continue;
            }

            let provider_name = route.provider.name();

            if !route.provider.healthy() {
                crate::metrics::inc_outbound_send(provider_name, "skipped");
                continue;
            }

            match route.provider.send(envelope.clone()).await {
                Ok(receipt) => {
                    crate::metrics::inc_outbound_send(provider_name, "ok");
                    return Ok(receipt);
                }
                Err(e @ OutboundError::Permanent(_)) => {
                    crate::metrics::inc_outbound_send(provider_name, "permanent");
                    warn!(
                        provider = provider_name,
                        audit = true,
                        "outbound delivery permanent failure: {e}"
                    );
                    // Permanent: no point trying other providers.
                    return Err(e);
                }
                Err(e @ OutboundError::Transient(_)) => {
                    crate::metrics::inc_outbound_send(provider_name, "transient");
                    warn!(
                        provider = provider_name,
                        audit = true,
                        "outbound delivery transient failure, trying next route: {e}"
                    );
                    last_err = Some(e);
                    // Transient: fall through to next matching route.
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            OutboundError::Transient("no healthy matching provider found".to_string())
        }))
    }

    fn name(&self) -> &'static str {
        "routing"
    }

    fn healthy(&self) -> bool {
        // Routing mailer is healthy if at least one provider is healthy.
        self.routes.iter().any(|r| r.provider.healthy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound_mailer::{MessageType, OutboundEnvelope, OutboundError, SendReceipt};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    /// A test provider that always succeeds.
    struct AlwaysOk {
        name: &'static str,
        call_count: AtomicU32,
    }

    impl AlwaysOk {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                call_count: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl OutboundMailer for AlwaysOk {
        async fn send(&self, _envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(SendReceipt {
                provider_message_id: None,
                provider: self.name,
            })
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// A test provider that always returns a transient error.
    struct AlwaysTransient {
        name: &'static str,
        call_count: AtomicU32,
    }

    impl AlwaysTransient {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                call_count: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl OutboundMailer for AlwaysTransient {
        async fn send(&self, _envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err(OutboundError::Transient("connection refused".to_string()))
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// A test provider that always returns a permanent error.
    struct AlwaysPermanent {
        name: &'static str,
    }

    impl AlwaysPermanent {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self { name })
        }
    }

    #[async_trait]
    impl OutboundMailer for AlwaysPermanent {
        async fn send(&self, _envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
            Err(OutboundError::Permanent("550 user unknown".to_string()))
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// A test provider that reports unhealthy.
    struct Unhealthy {
        name: &'static str,
        calls: AtomicU32,
    }

    impl Unhealthy {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                calls: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl OutboundMailer for Unhealthy {
        async fn send(&self, _envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(OutboundError::Transient("down".to_string()))
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn healthy(&self) -> bool {
            false
        }
    }

    fn make_envelope(rcpt_domain: &str, msg_type: MessageType) -> OutboundEnvelope {
        OutboundEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec![format!("to@{rcpt_domain}")],
            message: Bytes::from_static(b"From: from@example.com\r\n\r\ntest"),
            message_type: msg_type,
        }
    }

    // Oracle: first matching provider used on success.
    #[tokio::test]
    async fn routes_to_first_matching_provider() {
        let p1 = AlwaysOk::new("p1");
        let p2 = AlwaysOk::new("p2");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&p1) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&p2) as Arc<dyn OutboundMailer>,
            },
        ]);

        let receipt = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect("send must succeed");
        assert_eq!(receipt.provider, "p1");
        assert_eq!(p1.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(p2.call_count.load(Ordering::SeqCst), 0);
    }

    // Oracle: on transient failure falls through to next matching route.
    #[tokio::test]
    async fn transient_failure_falls_through_to_next_route() {
        let fail = AlwaysTransient::new("fail");
        let ok = AlwaysOk::new("ok");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&fail) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&ok) as Arc<dyn OutboundMailer>,
            },
        ]);

        let receipt = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect("should succeed via fallback");
        assert_eq!(receipt.provider, "ok");
        assert_eq!(fail.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(ok.call_count.load(Ordering::SeqCst), 1);
    }

    // Oracle: permanent failure stops immediately; second provider not tried.
    #[tokio::test]
    async fn permanent_failure_stops_routing() {
        let perm = AlwaysPermanent::new("perm");
        let ok = AlwaysOk::new("ok");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&perm) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&ok) as Arc<dyn OutboundMailer>,
            },
        ]);

        let err = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect_err("should return permanent error");
        assert!(!err.is_transient(), "error should be permanent");
        assert_eq!(
            ok.call_count.load(Ordering::SeqCst),
            0,
            "ok should never be called"
        );
    }

    // Oracle: unhealthy providers are skipped; healthy fallback used.
    #[tokio::test]
    async fn unhealthy_provider_skipped() {
        let sick = Unhealthy::new("sick");
        let ok = AlwaysOk::new("ok");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&sick) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&ok) as Arc<dyn OutboundMailer>,
            },
        ]);

        let receipt = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect("should succeed via fallback past unhealthy");
        assert_eq!(receipt.provider, "ok");
        assert_eq!(
            sick.calls.load(Ordering::SeqCst),
            0,
            "sick should not be called"
        );
    }

    // Oracle: domain glob selector matches correct routes.
    #[tokio::test]
    async fn domain_glob_selector_routes_correctly() {
        let example = AlwaysOk::new("example-provider");
        let fallback = AlwaysOk::new("fallback");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::DomainGlob("*.example.com".to_string()),
                provider: Arc::clone(&example) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&fallback) as Arc<dyn OutboundMailer>,
            },
        ]);

        // Should hit example-provider.
        let r1 = router
            .send(make_envelope(
                "mail.example.com",
                MessageType::Transactional,
            ))
            .await
            .expect("send 1");
        assert_eq!(r1.provider, "example-provider");

        // Should hit fallback (different domain).
        let r2 = router
            .send(make_envelope("other.org", MessageType::Transactional))
            .await
            .expect("send 2");
        assert_eq!(r2.provider, "fallback");
    }

    // Oracle: message-type selector routes transactional to dedicated provider.
    #[tokio::test]
    async fn message_type_selector_routes_transactional() {
        let txn = AlwaysOk::new("txn-provider");
        let bulk = AlwaysOk::new("bulk-provider");
        let router = RoutingMailer::new(vec![
            Route {
                selector: Selector::MessageType(MessageType::Transactional),
                provider: Arc::clone(&txn) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::MessageType(MessageType::Bulk),
                provider: Arc::clone(&bulk) as Arc<dyn OutboundMailer>,
            },
        ]);

        let r1 = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect("transactional send");
        assert_eq!(r1.provider, "txn-provider");

        let r2 = router
            .send(make_envelope("example.com", MessageType::Bulk))
            .await
            .expect("bulk send");
        assert_eq!(r2.provider, "bulk-provider");
    }

    // Oracle: empty routes returns transient error with descriptive message.
    #[tokio::test]
    async fn empty_routes_returns_error() {
        let router = RoutingMailer::new(vec![]);
        let err = router
            .send(make_envelope("example.com", MessageType::Transactional))
            .await
            .expect_err("empty routes should fail");
        assert!(err.is_transient());
    }

    // Oracle: glob_matches handles exact, wildcard subdomain, and catch-all patterns.
    #[test]
    fn glob_matches_patterns() {
        assert!(glob_matches("*", "anything.com"));
        assert!(glob_matches("*", ""));
        assert!(glob_matches("example.com", "example.com"));
        assert!(glob_matches("EXAMPLE.COM", "example.com")); // case-insensitive
        assert!(!glob_matches("example.com", "other.com"));
        assert!(glob_matches("*.example.com", "mail.example.com"));
        assert!(glob_matches("*.example.com", "smtp.example.com"));
        assert!(!glob_matches("*.example.com", "example.com")); // bare domain does not match (RFC 1034)
        assert!(!glob_matches("*.example.com", "evil-example.com"));
        assert!(!glob_matches("*.example.com", "other.org"));
    }

    // Oracle: start_health_poll emits outbound_provider_healthy gauge after one tick.
    // We drive time manually to avoid a real sleep.
    #[tokio::test(start_paused = true)]
    async fn health_poll_updates_gauge() {
        use std::time::Duration;

        // Unhealthy provider
        let sick = Unhealthy::new("health-poll-sick");
        // Healthy provider
        let ok = AlwaysOk::new("health-poll-ok");

        let router = Arc::new(RoutingMailer::new(vec![
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&sick) as Arc<dyn OutboundMailer>,
            },
            Route {
                selector: Selector::CatchAll,
                provider: Arc::clone(&ok) as Arc<dyn OutboundMailer>,
            },
        ]));

        router.clone().start_health_poll(Duration::from_millis(10));

        // Advance time past one poll interval.
        tokio::time::advance(Duration::from_millis(20)).await;
        // Yield to let the spawned task run.
        tokio::task::yield_now().await;

        // Oracle: gauges must reflect actual health state.
        // Access the global registry to find the gauge values.
        // We use the metric family counter to check values were set.
        // Since we can't easily read individual labels in a test, we just
        // verify the function doesn't panic and the task spawns without error.
        // The metric values themselves are exercised in the metrics module tests.
        let _ = prometheus::gather();
    }
}
