//! Circuit breaker state machine for external service calls (usenet-ipfs-8u4c).
//!
//! Protects callers from a slow or unreachable dependency by failing fast once
//! the error rate exceeds a threshold. Transitions:
//!
//! ```text
//! Closed ──(failures >= threshold)──► Open ──(probe interval elapsed)──► HalfOpen
//!   ▲                                                                         │
//!   └───────────────(probe succeeds)─────────────────────────────────────────┘
//!                                    Open ◄──(probe fails)───────────────────┘
//! ```
//!
//! `CircuitBreaker::allow_request` is the entry-point gating calls to the
//! external service. Callers MUST call `record_success` or `record_failure`
//! after each attempted call.
//!
//! Thread-safe: all mutable state is behind a `std::sync::Mutex`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Observable state of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbState {
    /// Normal operation — failures are being counted.
    Closed,
    /// Fast-fail mode — all requests are rejected until the probe interval elapses.
    Open,
    /// Recovery probe — one batch of requests is allowed through to test recovery.
    HalfOpen,
}

impl std::fmt::Display for CbState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CbState::Closed => write!(f, "closed"),
            CbState::Open => write!(f, "open"),
            CbState::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// Configuration for a `CircuitBreaker`.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures within `window` that triggers the Open state.
    pub failure_threshold: u32,
    /// Sliding window for counting failures.
    pub window: Duration,
    /// How long to wait in Open state before allowing a probe.
    pub probe_interval: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            window: Duration::from_secs(10),
            probe_interval: Duration::from_secs(30),
        }
    }
}

struct Inner {
    state: CbState,
    failure_count: u32,
    window_start: Instant,
    opened_at: Option<Instant>,
}

/// Thread-safe circuit breaker state machine.
///
/// Cheaply cloneable via `Arc`; all clones share the same state.
#[derive(Clone)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<Inner>>,
    config: CircuitBreakerConfig,
    on_state_change: Option<Arc<dyn Fn(CbState, CbState) + Send + Sync>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given config.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                state: CbState::Closed,
                failure_count: 0,
                window_start: Instant::now(),
                opened_at: None,
            })),
            config,
            on_state_change: None,
        }
    }

    /// Attach a callback invoked on every state transition.
    ///
    /// The callback receives `(old_state, new_state)` and must not block.
    pub fn with_state_change_callback<F>(mut self, f: F) -> Self
    where
        F: Fn(CbState, CbState) + Send + Sync + 'static,
    {
        self.on_state_change = Some(Arc::new(f));
        self
    }

    /// Returns the current observable state.
    pub fn state(&self) -> CbState {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    /// Returns `true` if a request should be allowed through to the dependency.
    ///
    /// - `Closed` → always true.
    /// - `Open` → true only if the probe interval has elapsed (transitions to `HalfOpen`).
    /// - `HalfOpen` → true (all requests treated as probes).
    pub fn allow_request(&self) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.state {
            CbState::Closed => true,
            CbState::Open => {
                let elapsed = g.opened_at.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
                if elapsed >= self.config.probe_interval {
                    let old = g.state;
                    g.state = CbState::HalfOpen;
                    drop(g);
                    self.notify(old, CbState::HalfOpen);
                    tracing::info!("circuit breaker: open → half-open (probe allowed)");
                    true
                } else {
                    false
                }
            }
            CbState::HalfOpen => true,
        }
    }

    /// Record a successful call. If in `HalfOpen`, closes the circuit.
    pub fn record_success(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.state == CbState::HalfOpen {
            let old = g.state;
            g.state = CbState::Closed;
            g.failure_count = 0;
            g.window_start = Instant::now();
            g.opened_at = None;
            drop(g);
            self.notify(old, CbState::Closed);
            tracing::info!("circuit breaker: half-open → closed (probe succeeded)");
        } else {
            // Reset the failure window on success to avoid stale counts.
            g.failure_count = 0;
            g.window_start = Instant::now();
        }
    }

    /// Record a failed call. If in `HalfOpen`, re-opens. If in `Closed` and
    /// the failure threshold is reached within the window, opens the circuit.
    pub fn record_failure(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.state {
            CbState::HalfOpen => {
                let old = g.state;
                g.state = CbState::Open;
                g.opened_at = Some(Instant::now());
                drop(g);
                self.notify(old, CbState::Open);
                tracing::warn!("circuit breaker: half-open → open (probe failed)");
            }
            CbState::Open => {
                // Already open; refresh the opened_at timer so the probe
                // interval is measured from the most recent failure.
                g.opened_at = Some(Instant::now());
            }
            CbState::Closed => {
                // Reset window if it has expired.
                if g.window_start.elapsed() > self.config.window {
                    g.failure_count = 0;
                    g.window_start = Instant::now();
                }
                g.failure_count += 1;
                if g.failure_count >= self.config.failure_threshold {
                    let old = g.state;
                    g.state = CbState::Open;
                    g.opened_at = Some(Instant::now());
                    drop(g);
                    self.notify(old, CbState::Open);
                    tracing::warn!(
                        threshold = self.config.failure_threshold,
                        "circuit breaker: closed → open (failure threshold reached)"
                    );
                }
            }
        }
    }

    fn notify(&self, old: CbState, new: CbState) {
        if let Some(cb) = &self.on_state_change {
            cb(old, new);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn default_cb() -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig::default())
    }

    fn fast_cb() -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            window: Duration::from_secs(60),
            // Large probe_interval so tests that check Open state cannot
            // accidentally transition to HalfOpen during assertion.
            probe_interval: Duration::from_secs(3600),
        })
    }

    #[test]
    fn starts_closed_allows_requests() {
        let cb = default_cb();
        assert_eq!(cb.state(), CbState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn opens_after_failure_threshold() {
        let cb = fast_cb();
        for _ in 0..3 {
            assert!(cb.allow_request());
            cb.record_failure();
        }
        assert_eq!(cb.state(), CbState::Open);
        assert!(!cb.allow_request(), "open circuit must reject requests");
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = fast_cb();
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // resets count
                             // Two more failures — should not open (counter was reset to 0)
        cb.record_failure();
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CbState::Closed,
            "two failures after reset must not open"
        );
    }

    #[test]
    fn transitions_to_half_open_after_probe_interval() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            window: Duration::from_secs(60),
            probe_interval: Duration::from_millis(1),
        });
        cb.record_failure();
        assert_eq!(cb.state(), CbState::Open);

        std::thread::sleep(Duration::from_millis(5));
        assert!(
            cb.allow_request(),
            "probe interval elapsed, must allow probe"
        );
        assert_eq!(cb.state(), CbState::HalfOpen);
    }

    #[test]
    fn closes_after_successful_probe() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            window: Duration::from_secs(60),
            probe_interval: Duration::from_millis(1),
        });
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        cb.allow_request(); // transition to HalfOpen
        cb.record_success();
        assert_eq!(cb.state(), CbState::Closed);
    }

    #[test]
    fn reopens_after_failed_probe() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            window: Duration::from_secs(60),
            probe_interval: Duration::from_millis(1),
        });
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        cb.allow_request(); // HalfOpen
        cb.record_failure(); // back to Open
        assert_eq!(cb.state(), CbState::Open);
    }

    #[test]
    fn state_change_callback_is_called() {
        let opens = Arc::new(AtomicU32::new(0));
        let opens_clone = Arc::clone(&opens);

        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            window: Duration::from_secs(60),
            probe_interval: Duration::from_millis(1),
        })
        .with_state_change_callback(move |_old, new| {
            if new == CbState::Open {
                opens_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        cb.record_failure();
        cb.record_failure(); // opens

        assert_eq!(
            opens.load(Ordering::Relaxed),
            1,
            "callback must fire on open"
        );
    }

    #[test]
    fn window_reset_allows_reopening() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            window: Duration::from_millis(10), // very short window
            probe_interval: Duration::from_secs(30),
        });
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(20)); // window expires
                                                       // New window: counter reset; need 3 more to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CbState::Closed,
            "two failures in new window must not open (threshold=3)"
        );
        cb.record_failure();
        assert_eq!(cb.state(), CbState::Open);
    }

    #[test]
    fn does_not_open_before_threshold() {
        let cb = fast_cb(); // threshold=3
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CbState::Closed, "2 < 3 must stay closed");
    }
}
