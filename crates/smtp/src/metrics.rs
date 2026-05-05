/// Prometheus metrics for the SMTP crate.
///
/// All metrics are registered into the default global `prometheus` registry.
/// The `/metrics` endpoint on the Sieve admin HTTP server gathers them and
/// renders text/plain in Prometheus exposition format.
use std::sync::LazyLock;

use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec,
    register_int_counter, Counter, CounterVec, Gauge, GaugeVec, IntCounter, Opts,
};

/// Total number of inbound TCP connections accepted.
pub static SMTP_CONNECTIONS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_connections_total",
        "Total number of inbound SMTP connections accepted"
    ))
    .expect("failed to register smtp_connections_total")
});

/// Total number of messages that completed DATA and were accepted (250 OK).
pub static SMTP_MESSAGES_ACCEPTED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_messages_accepted_total",
        "Total number of messages accepted after DATA"
    ))
    .expect("failed to register smtp_messages_accepted_total")
});

/// Total number of messages rejected during DATA, labelled by rejection reason.
///
/// Label values in use:
/// - `"size"` — message exceeded the configured size limit
/// - `"policy"` — rejected by DMARC policy or Sieve `reject` action
pub static SMTP_MESSAGES_REJECTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "smtp_messages_rejected_total",
            "Total number of messages rejected during DATA, by reason"
        ),
        &["reason"]
    )
    .expect("failed to register smtp_messages_rejected_total")
});

/// Total number of message body bytes accepted (after dot-unstuffing, before
/// prepending Received: and Authentication-Results: trace headers).
pub static SMTP_DATA_BYTES_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_data_bytes_total",
        "Total bytes of message body accepted through DATA"
    ))
    .expect("failed to register smtp_data_bytes_total")
});

/// Total number of Sieve evaluations aborted due to exceeding the configured timeout.
pub static SMTP_SIEVE_EVAL_TIMEOUTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "smtp_sieve_eval_timeouts_total",
        "Number of Sieve evaluations aborted due to timeout"
    )
    .expect("failed to register smtp_sieve_eval_timeouts_total")
});

// ---------------------------------------------------------------------------
// Relay metrics — per-peer labels
// ---------------------------------------------------------------------------

/// Total outbound relay delivery attempts, labelled by peer host.
static RELAY_ATTEMPTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "relay_attempts_total",
            "Total outbound relay delivery attempts by peer"
        ),
        &["peer"]
    )
    .expect("failed to register relay_attempts_total")
});

/// Total outbound relay delivery successes, labelled by peer host.
static RELAY_SUCCESSES_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "relay_successes_total",
            "Total outbound relay delivery successes by peer"
        ),
        &["peer"]
    )
    .expect("failed to register relay_successes_total")
});

/// Total outbound relay delivery failures, labelled by peer host and failure kind.
///
/// `kind` values: `"transient"` (will retry) or `"permanent"` (moved to dead/).
static RELAY_FAILURES_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "relay_failures_total",
            "Total outbound relay delivery failures by peer and kind"
        ),
        &["peer", "kind"]
    )
    .expect("failed to register relay_failures_total")
});

/// Total number of enqueue failures at the NNTP POST / JMAP Email/set call sites.
///
/// Incremented whenever `SmtpRelayQueue::enqueue` returns `Err` at a call site
/// that suppresses the error (best-effort relay semantics).  Use this counter
/// to alert on article loss without changing NNTP / JMAP error semantics.
pub static RELAY_ENQUEUE_FAILURES_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "relay_enqueue_failures_total",
        "Total number of times SMTP relay enqueue failed (article not queued for delivery)"
    ))
    .expect("failed to register relay_enqueue_failures_total")
});

/// Current peer reachability: 1.0 = up, 0.0 = down, labelled by peer host.
static RELAY_PEER_UP: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new("relay_peer_up", "Relay peer reachability: 1 = up, 0 = down"),
        &["peer"]
    )
    .expect("failed to register relay_peer_up")
});

/// Current number of messages in the SMTP relay outbound queue directory.
static RELAY_QUEUE_DEPTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(Opts::new(
        "relay_queue_depth",
        "Current number of messages in the SMTP relay outbound queue"
    ))
    .expect("failed to register relay_queue_depth")
});

/// Current number of messages in the SMTP relay dead-letter directory.
static RELAY_DEAD_LETTER_DEPTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(Opts::new(
        "relay_dead_letter_depth",
        "Current number of messages in the SMTP relay dead-letter directory"
    ))
    .expect("failed to register relay_dead_letter_depth")
});

/// Set the relay outbound queue depth gauge.
pub fn set_relay_queue_depth(n: f64) {
    RELAY_QUEUE_DEPTH.set(n);
}

/// Set the relay dead-letter queue depth gauge.
pub fn set_relay_dead_letter_depth(n: f64) {
    RELAY_DEAD_LETTER_DEPTH.set(n);
}

/// Increment the relay attempt counter for `peer`.
pub fn inc_relay_attempt(peer: &str) {
    RELAY_ATTEMPTS_TOTAL.with_label_values(&[peer]).inc();
}

/// Increment the relay success counter for `peer`.
pub fn inc_relay_success(peer: &str) {
    RELAY_SUCCESSES_TOTAL.with_label_values(&[peer]).inc();
}

/// Increment the relay failure counter for `peer` with the given `kind`
/// (`"transient"` or `"permanent"`).
pub fn inc_relay_failure(peer: &str, kind: &str) {
    RELAY_FAILURES_TOTAL.with_label_values(&[peer, kind]).inc();
}

/// Set the relay peer-up gauge: `true` → 1.0, `false` → 0.0.
pub fn set_relay_peer_up(peer: &str, up: bool) {
    RELAY_PEER_UP
        .with_label_values(&[peer])
        .set(if up { 1.0 } else { 0.0 });
}

/// Increment the enqueue-failure counter.
///
/// Call this whenever `SmtpRelayQueue::enqueue` returns `Err` at a call site
/// that suppresses the error (best-effort relay semantics).
pub fn inc_relay_enqueue_failure() {
    RELAY_ENQUEUE_FAILURES_TOTAL.inc();
}

// ── OutboundMailer / RoutingMailer metrics ──────────────────────────────────

/// Total send attempts through the OutboundMailer abstraction, labelled by
/// provider name and result (`"ok"`, `"transient"`, `"permanent"`, `"skipped"`).
static OUTBOUND_SEND_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "outbound_send_total",
            "Total send attempts through the OutboundMailer abstraction, by provider and result"
        ),
        &["provider", "result"]
    )
    .expect("failed to register outbound_send_total")
});

/// Increment the `outbound_send_total` counter for `provider` with `result`.
///
/// Recommended `result` values: `"ok"`, `"transient"`, `"permanent"`, `"skipped"`.
pub fn inc_outbound_send(provider: &str, result: &str) {
    OUTBOUND_SEND_TOTAL
        .with_label_values(&[provider, result])
        .inc();
}

/// Current health state of an outbound provider: 1.0 = healthy, 0.0 = unhealthy.
static OUTBOUND_PROVIDER_HEALTHY: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "outbound_provider_healthy",
            "Outbound provider health: 1 = healthy, 0 = unhealthy"
        ),
        &["provider"]
    )
    .expect("failed to register outbound_provider_healthy")
});

/// Set the health gauge for `provider`: `true` → 1.0, `false` → 0.0.
pub fn set_outbound_provider_healthy(provider: &str, healthy: bool) {
    OUTBOUND_PROVIDER_HEALTHY
        .with_label_values(&[provider])
        .set(if healthy { 1.0 } else { 0.0 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inc_relay_attempt_increments_counter() {
        let before = RELAY_ATTEMPTS_TOTAL
            .with_label_values(&["test-peer-attempt"])
            .get();
        inc_relay_attempt("test-peer-attempt");
        let after = RELAY_ATTEMPTS_TOTAL
            .with_label_values(&["test-peer-attempt"])
            .get();
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn inc_relay_success_increments_counter() {
        let before = RELAY_SUCCESSES_TOTAL
            .with_label_values(&["test-peer-success"])
            .get();
        inc_relay_success("test-peer-success");
        let after = RELAY_SUCCESSES_TOTAL
            .with_label_values(&["test-peer-success"])
            .get();
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn inc_relay_failure_increments_counter() {
        let before_t = RELAY_FAILURES_TOTAL
            .with_label_values(&["test-peer-fail", "transient"])
            .get();
        let before_p = RELAY_FAILURES_TOTAL
            .with_label_values(&["test-peer-fail", "permanent"])
            .get();
        inc_relay_failure("test-peer-fail", "transient");
        inc_relay_failure("test-peer-fail", "permanent");
        let after_t = RELAY_FAILURES_TOTAL
            .with_label_values(&["test-peer-fail", "transient"])
            .get();
        let after_p = RELAY_FAILURES_TOTAL
            .with_label_values(&["test-peer-fail", "permanent"])
            .get();
        assert_eq!(after_t, before_t + 1.0);
        assert_eq!(after_p, before_p + 1.0);
    }

    #[test]
    fn set_relay_peer_up_sets_gauge() {
        set_relay_peer_up("test-peer-gauge", true);
        assert_eq!(
            RELAY_PEER_UP.with_label_values(&["test-peer-gauge"]).get(),
            1.0
        );
        set_relay_peer_up("test-peer-gauge", false);
        assert_eq!(
            RELAY_PEER_UP.with_label_values(&["test-peer-gauge"]).get(),
            0.0
        );
    }

    #[test]
    fn inc_relay_enqueue_failure_increments_counter() {
        let before = RELAY_ENQUEUE_FAILURES_TOTAL.get();
        inc_relay_enqueue_failure();
        let after = RELAY_ENQUEUE_FAILURES_TOTAL.get();
        assert_eq!(after, before + 1.0);
    }

    // Oracle: set_outbound_provider_healthy sets gauge to 1.0 (healthy) and 0.0 (unhealthy).
    #[test]
    fn set_outbound_provider_healthy_sets_gauge() {
        set_outbound_provider_healthy("test-outbound-provider", true);
        assert_eq!(
            OUTBOUND_PROVIDER_HEALTHY
                .with_label_values(&["test-outbound-provider"])
                .get(),
            1.0
        );
        set_outbound_provider_healthy("test-outbound-provider", false);
        assert_eq!(
            OUTBOUND_PROVIDER_HEALTHY
                .with_label_values(&["test-outbound-provider"])
                .get(),
            0.0
        );
    }

    // Oracle: inc_outbound_send increments outbound_send_total.
    #[test]
    fn inc_outbound_send_increments_counter() {
        let before = OUTBOUND_SEND_TOTAL
            .with_label_values(&["test-provider", "ok"])
            .get();
        inc_outbound_send("test-provider", "ok");
        let after = OUTBOUND_SEND_TOTAL
            .with_label_values(&["test-provider", "ok"])
            .get();
        assert_eq!(after, before + 1.0);
    }
}
