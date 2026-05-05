//! Prometheus metrics for the mail (JMAP) server.

use std::sync::LazyLock;

use prometheus::{
    register_counter_vec, register_histogram_vec, register_int_gauge, register_int_gauge_vec,
};

/// Total JMAP method calls, labeled by method name (e.g. "Email/get").
pub static JMAP_REQUESTS_TOTAL: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "jmap_requests_total",
        "Total number of JMAP method calls, labeled by method",
        &["method"]
    )
    .expect("failed to register jmap_requests_total")
});

/// Per-method latency histogram for JMAP calls, in seconds.
pub static JMAP_REQUEST_DURATION_SECONDS: LazyLock<prometheus::HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec!(
            "jmap_request_duration_seconds",
            "Duration of JMAP method handling in seconds, labeled by method",
            &["method"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        .expect("failed to register jmap_request_duration_seconds")
    });

/// Number of results returned by the most recent Email/query call.
pub static EMAIL_QUERY_RESULTS: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "email_query_results",
        "Number of results returned by the last Email/query call"
    )
    .expect("failed to register email_query_results")
});

/// Readiness gauge per component: 1 = ready, 0 = not ready.
///
/// Labels: `component` in {"db"}.
/// Updated by the `/ready` handler on every probe.
pub static STOA_READY: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "stoa_ready",
        "Readiness of individual components: 1=ready, 0=not ready",
        &["component"]
    )
    .expect("failed to register stoa_ready")
});

/// Force-initialise all metric statics and return the Prometheus text payload.
pub fn gather_metrics() -> Vec<u8> {
    let _ = (
        &*JMAP_REQUESTS_TOTAL,
        &*JMAP_REQUEST_DURATION_SECONDS,
        &*EMAIL_QUERY_RESULTS,
        &*STOA_READY,
    );

    use prometheus::Encoder as _;
    let encoder = prometheus::TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap_or_default();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_present() {
        JMAP_REQUESTS_TOTAL
            .with_label_values(&["_test"])
            .inc_by(0.0);
        JMAP_REQUEST_DURATION_SECONDS
            .with_label_values(&["_test"])
            .observe(0.0);
        let output = String::from_utf8(gather_metrics()).unwrap();
        assert!(
            output.contains("jmap_requests_total"),
            "missing jmap_requests_total in:\n{output}"
        );
        assert!(
            output.contains("jmap_request_duration_seconds"),
            "missing jmap_request_duration_seconds in:\n{output}"
        );
        assert!(
            output.contains("email_query_results"),
            "missing email_query_results in:\n{output}"
        );
    }

    #[test]
    fn counter_increments() {
        JMAP_REQUESTS_TOTAL.with_label_values(&["Email/get"]).inc();
        let output = String::from_utf8(gather_metrics()).unwrap();
        assert!(
            output.contains("jmap_requests_total"),
            "missing jmap_requests_total after increment in:\n{output}"
        );
    }

    #[test]
    fn histogram_records_observation() {
        JMAP_REQUEST_DURATION_SECONDS
            .with_label_values(&["Mailbox/get"])
            .observe(0.042);
        let output = String::from_utf8(gather_metrics()).unwrap();
        assert!(
            output.contains("jmap_request_duration_seconds"),
            "missing histogram output in:\n{output}"
        );
    }

    #[test]
    fn stoa_ready_gauge_present() {
        STOA_READY.with_label_values(&["db"]).set(1);
        let output = String::from_utf8(gather_metrics()).unwrap();
        assert!(
            output.contains("stoa_ready"),
            "missing stoa_ready in:\n{output}"
        );
    }
}
