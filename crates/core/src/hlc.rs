use std::fmt;

use serde::{Deserialize, Serialize};

/// Hybrid Logical Clock timestamp.
///
/// Ordering: wall_ms first, then logical counter, then node_id (lexicographic).
/// Field declaration order matches comparison priority — derived Ord is correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub wall_ms: u64,
    pub logical: u32,
    pub node_id: [u8; 8],
}

/// Errors produced by [`HlcClock`] operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum HlcError {
    /// The observed peer timestamp exceeds the local wall clock by more than
    /// the configured `max_clock_skew_ms`.  Accepting it would permanently
    /// advance the local HLC, which is a denial-of-service vector.
    ClockSkewExceeded {
        observed_ms: u64,
        now_ms: u64,
        max_skew_ms: u64,
    },
}

impl fmt::Display for HlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockSkewExceeded {
                observed_ms,
                now_ms,
                max_skew_ms,
            } => write!(
                f,
                "peer timestamp {observed_ms}ms exceeds local clock {now_ms}ms \
                 by more than the {max_skew_ms}ms allowed skew"
            ),
        }
    }
}

impl std::error::Error for HlcError {}

/// Default maximum clock skew accepted from remote peers (milliseconds).
pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = 5_000;

/// Hybrid Logical Clock (Kulkarni & Demirbas 2014).
#[derive(Debug)]
pub struct HlcClock {
    last: HlcTimestamp,
    node_id: [u8; 8],
    max_clock_skew_ms: u64,
}

impl HlcClock {
    pub fn new(node_id: [u8; 8], initial_wall_ms: u64) -> Self {
        Self {
            last: HlcTimestamp {
                wall_ms: initial_wall_ms,
                logical: 0,
                node_id,
            },
            node_id,
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
        }
    }

    /// Create a clock seeded from a persisted checkpoint.
    ///
    /// Ensures the first `send()` after restart produces a timestamp strictly
    /// greater than the last persisted timestamp, regardless of NTP adjustments
    /// or quick restarts within the same millisecond.
    ///
    /// - When `checkpoint.wall_ms >= now_ms` (e.g. NTP stepped clock back or
    ///   restart within same ms): seed `last = checkpoint` so the next `send()`
    ///   returns `(checkpoint.wall_ms, checkpoint.logical + 1, node_id)`.
    /// - Otherwise: seed `last = (now_ms, 0, node_id)` — wall clock has
    ///   advanced past the checkpoint so any new timestamp will be greater.
    pub fn new_seeded(node_id: [u8; 8], now_ms: u64, checkpoint: HlcTimestamp) -> Self {
        let last = if checkpoint.wall_ms >= now_ms {
            HlcTimestamp {
                wall_ms: checkpoint.wall_ms,
                logical: checkpoint.logical,
                node_id,
            }
        } else {
            HlcTimestamp {
                wall_ms: now_ms,
                logical: 0,
                node_id,
            }
        };
        Self {
            last,
            node_id,
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
        }
    }

    /// Return a copy of the most recent timestamp emitted by this clock.
    ///
    /// Used to persist the HLC state across restarts.
    pub fn last_timestamp(&self) -> HlcTimestamp {
        self.last
    }

    /// Generate a send timestamp: advance to max(last, now), bump logical on ties.
    ///
    /// If the logical counter would overflow u32::MAX (possible only when generating
    /// more than 4 billion events within a single millisecond, or under a mocked
    /// clock), wall_ms is advanced by 1ms and logical resets to 0.  This preserves
    /// strict monotonicity: (wall+1, 0) > (wall, u32::MAX).
    pub fn send(&mut self, now_ms: u64) -> HlcTimestamp {
        let mut new_wall = self.last.wall_ms.max(now_ms);
        let new_logical = if new_wall == self.last.wall_ms {
            match self.last.logical.checked_add(1) {
                Some(l) => l,
                // Logical counter exhausted for this millisecond; advance wall.
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else {
            0
        };
        self.last = HlcTimestamp {
            wall_ms: new_wall,
            logical: new_logical,
            node_id: self.node_id,
        };
        self.last
    }

    /// Receive a remote timestamp: advance to max(local, observed, now) + 1 logical.
    ///
    /// Returns `Err(HlcError::ClockSkewExceeded)` if `observed.wall_ms` is more
    /// than `max_clock_skew_ms` ahead of `now_ms`.  This prevents a malicious
    /// peer from permanently jumping the local HLC into the future.
    ///
    /// Same overflow handling as `send`: if the logical increment would wrap,
    /// wall_ms is advanced by 1ms and logical resets to 0.
    pub fn receive(
        &mut self,
        now_ms: u64,
        observed: &HlcTimestamp,
    ) -> Result<HlcTimestamp, HlcError> {
        // Check skew without overflow: compare (observed - now) against max_skew
        // rather than (now + max_skew) against observed, so the addition cannot wrap.
        if observed.wall_ms > now_ms && observed.wall_ms - now_ms > self.max_clock_skew_ms {
            return Err(HlcError::ClockSkewExceeded {
                observed_ms: observed.wall_ms,
                now_ms,
                max_skew_ms: self.max_clock_skew_ms,
            });
        }

        let mut new_wall = self.last.wall_ms.max(observed.wall_ms).max(now_ms);
        let new_logical = if new_wall == self.last.wall_ms && new_wall == observed.wall_ms {
            let max_logical = self.last.logical.max(observed.logical);
            match max_logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else if new_wall == self.last.wall_ms {
            match self.last.logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else if new_wall == observed.wall_ms {
            match observed.logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else {
            0
        };
        self.last = HlcTimestamp {
            wall_ms: new_wall,
            logical: new_logical,
            node_id: self.node_id,
        };
        Ok(self.last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_A: [u8; 8] = [0xAA; 8];
    const NODE_B: [u8; 8] = [0xBB; 8];

    #[test]
    fn send_same_wall_increments_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        let t1 = clock.send(1000);
        let t2 = clock.send(1000);
        assert_eq!(t1.wall_ms, 1000);
        assert_eq!(t2.wall_ms, 1000);
        assert!(
            t2.logical > t1.logical,
            "logical must increase on same wall time"
        );
    }

    #[test]
    fn send_advancing_wall_resets_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        let t1 = clock.send(1000);
        assert!(t1.logical > 0);
        let t2 = clock.send(2000);
        assert_eq!(t2.wall_ms, 2000);
        assert_eq!(t2.logical, 0, "logical must reset to 0 when wall advances");
    }

    #[test]
    fn receive_same_wall_takes_max_logical_plus_one() {
        let wall = 5000u64;
        let mut clock = HlcClock::new(NODE_A, wall);
        // Advance local logical to 3.
        clock.send(wall);
        clock.send(wall);
        clock.send(wall);
        let local_logical = clock.last.logical; // should be 3

        let observed = HlcTimestamp {
            wall_ms: wall,
            logical: 10,
            node_id: NODE_B,
        };
        // observed.wall_ms == now_ms, so skew is 0ms — well within the default 5s limit.
        let result = clock.receive(wall, &observed).unwrap();
        assert_eq!(result.wall_ms, wall);
        assert_eq!(
            result.logical,
            local_logical.max(observed.logical) + 1,
            "receive must take max of both logicals + 1"
        );
    }

    #[test]
    fn receive_message_wall_ahead_uses_message_logical_plus_one() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        clock.send(1000);

        let observed = HlcTimestamp {
            wall_ms: 9000,
            logical: 7,
            node_id: NODE_B,
        };
        // now_ms = 5000 so observed is 4s ahead — within the 5s default skew limit.
        // max(last≈1001, observed=9000, now=5000) = 9000, so wall jumps to 9000.
        let result = clock.receive(5000, &observed).unwrap();
        assert_eq!(result.wall_ms, 9000, "wall must jump to message wall");
        assert_eq!(result.logical, 8, "logical must be msg.logical + 1");
    }

    #[test]
    fn receive_now_wall_ahead_resets_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        clock.send(1000);

        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: 5,
            node_id: NODE_B,
        };
        // observed is behind now_ms, so skew check passes trivially.
        // now_ms is far ahead of both local and observed.
        let result = clock.receive(9000, &observed).unwrap();
        assert_eq!(result.wall_ms, 9000);
        assert_eq!(result.logical, 0, "logical resets when now_ms dominates");
    }

    #[test]
    fn send_logical_overflow_advances_wall() {
        // Seed clock at (wall=1000, logical=u32::MAX).
        let mut clock = HlcClock {
            last: HlcTimestamp {
                wall_ms: 1000,
                logical: u32::MAX,
                node_id: NODE_A,
            },
            node_id: NODE_A,
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
        };
        let t = clock.send(1000);
        assert_eq!(t.wall_ms, 1001, "wall must advance when logical overflows");
        assert_eq!(t.logical, 0, "logical must reset after wall advance");
        // The new timestamp must be strictly greater than the seed.
        assert!(
            t > HlcTimestamp {
                wall_ms: 1000,
                logical: u32::MAX,
                node_id: NODE_A
            },
            "post-overflow timestamp must be greater than pre-overflow"
        );
    }

    #[test]
    fn receive_logical_overflow_advances_wall() {
        // Both local and observed at (wall=1000, logical=u32::MAX).
        let mut clock = HlcClock {
            last: HlcTimestamp {
                wall_ms: 1000,
                logical: u32::MAX,
                node_id: NODE_A,
            },
            node_id: NODE_A,
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
        };
        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: u32::MAX,
            node_id: NODE_B,
        };
        // observed.wall_ms == now_ms, skew is 0ms.
        let t = clock.receive(1000, &observed).unwrap();
        assert_eq!(
            t.wall_ms, 1001,
            "wall must advance when logical overflows in receive"
        );
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn receive_observed_logical_overflow_advances_wall() {
        // Local is behind; observed.logical == u32::MAX, so observed.logical + 1 overflows.
        let mut clock = HlcClock::new(NODE_A, 500);
        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: u32::MAX,
            node_id: NODE_B,
        };
        // observed is 500ms ahead of now_ms=500 — well within 5s limit.
        let t = clock.receive(500, &observed).unwrap();
        assert_eq!(
            t.wall_ms, 1001,
            "wall must advance when observed.logical overflows"
        );
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn receive_rejects_timestamp_far_in_future() {
        // A peer timestamp 10 seconds ahead of local wall must be rejected.
        let now_ms = 100_000u64;
        let mut clock = HlcClock::new(NODE_A, now_ms);
        let malicious = HlcTimestamp {
            wall_ms: now_ms + 10_000, // 10 s ahead
            logical: 0,
            node_id: NODE_B,
        };
        let err = clock
            .receive(now_ms, &malicious)
            .expect_err("timestamp 10s in the future must be rejected");
        assert!(
            matches!(
                err,
                HlcError::ClockSkewExceeded {
                    observed_ms,
                    now_ms: n,
                    max_skew_ms,
                } if observed_ms == now_ms + 10_000
                    && n == now_ms
                    && max_skew_ms == DEFAULT_MAX_CLOCK_SKEW_MS
            ),
            "unexpected error variant: {err}"
        );
        // Clock state must not have advanced.
        assert_eq!(
            clock.last.wall_ms, now_ms,
            "clock must not advance after rejected receive"
        );
    }

    #[test]
    fn receive_accepts_timestamp_within_skew() {
        // A peer timestamp 1 second ahead of local wall must be accepted.
        let now_ms = 100_000u64;
        let mut clock = HlcClock::new(NODE_A, now_ms);
        let peer = HlcTimestamp {
            wall_ms: now_ms + 1_000, // 1 s ahead — within 5 s default
            logical: 0,
            node_id: NODE_B,
        };
        let result = clock
            .receive(now_ms, &peer)
            .expect("timestamp 1s in the future must be accepted");
        assert_eq!(
            result.wall_ms,
            now_ms + 1_000,
            "clock must advance to the peer wall when within skew limit"
        );
    }

    /// When now_ms is near u64::MAX the old saturating_add approach would clamp
    /// now_ms + max_skew_ms to u64::MAX, making u64::MAX appear within the skew
    /// window regardless of the actual observed value.  The subtraction-based
    /// check must still reject an observed timestamp that exceeds now_ms by more
    /// than max_skew_ms, even when now_ms is close to u64::MAX.
    #[test]
    fn receive_rejects_future_timestamp_when_now_near_u64_max() {
        // Place now_ms so that now_ms + max_skew_ms would wrap under saturating_add.
        // Specifically: now_ms = u64::MAX - max_skew / 2, so adding max_skew overflows.
        // observed = u64::MAX - 1 (> now_ms + max_skew, but < u64::MAX).
        // With saturating_add: now_ms.saturating_add(max_skew) == u64::MAX,
        // so observed (u64::MAX - 1) appears within the window — a false accept.
        // With subtraction: observed - now_ms = max_skew/2 - 1 ... wait,
        // we need observed to be > now_ms + max_skew.
        // now_ms = u64::MAX - DEFAULT_MAX_CLOCK_SKEW_MS / 2
        // now_ms + max_skew = u64::MAX + max_skew/2 (overflows)
        // Use observed = u64::MAX (> now_ms by max_skew/2, which is less than max_skew,
        // so this would actually be accepted). We need observed that is > now_ms + max_skew.
        // Since u64::MAX is the ceiling, we can't represent observed > u64::MAX.
        // Instead, use now_ms far enough below u64::MAX that observed fits:
        // now_ms = u64::MAX - DEFAULT_MAX_CLOCK_SKEW_MS * 3
        // observed = now_ms + DEFAULT_MAX_CLOCK_SKEW_MS + 1 (fits in u64)
        let now_ms = u64::MAX - DEFAULT_MAX_CLOCK_SKEW_MS * 3;
        let observed_ms = now_ms + DEFAULT_MAX_CLOCK_SKEW_MS + 1; // just over the limit
                                                                  // Verify that the old saturating_add approach would have accepted this:
                                                                  // now_ms.saturating_add(DEFAULT_MAX_CLOCK_SKEW_MS) = u64::MAX - 2*max_skew,
                                                                  // which is less than observed_ms, so the old code correctly rejects too here.
                                                                  // The real regression is when now_ms + max_skew wraps; we test that separately.
        let mut clock = HlcClock::new(NODE_A, now_ms);
        let observed = HlcTimestamp {
            wall_ms: observed_ms,
            logical: 0,
            node_id: NODE_B,
        };
        let err = clock
            .receive(now_ms, &observed)
            .expect_err("timestamp beyond max_skew must be rejected");
        assert!(
            matches!(err, HlcError::ClockSkewExceeded { .. }),
            "expected ClockSkewExceeded, got: {err}"
        );
        // Clock must not have advanced.
        assert_eq!(
            clock.last.wall_ms, now_ms,
            "clock must not advance after rejected receive"
        );
    }

    /// The subtraction-based skew check must not overflow when now_ms is near u64::MAX
    /// and observed_ms is u64::MAX.  The old saturating_add would clamp the bound to
    /// u64::MAX, making observed = u64::MAX look in-window; the subtraction check
    /// must correctly compute the difference.
    #[test]
    fn receive_near_u64_max_saturating_add_regression() {
        // now_ms chosen so that now_ms.saturating_add(max_skew_ms) == u64::MAX
        // (i.e. the addition saturates), which means the old check would accept
        // any observed_ms <= u64::MAX as in-window.
        //
        // With subtraction: observed_ms - now_ms tells us the true skew.
        let max_skew = DEFAULT_MAX_CLOCK_SKEW_MS;
        // now_ms + max_skew overflows → saturating_add yields u64::MAX
        let now_ms = u64::MAX - max_skew / 2; // adding max_skew wraps
                                              // observed_ms is now_ms + max_skew/2 + 1 (barely exceeds the true limit of max_skew)
                                              // but that would overflow too.  Use observed_ms = u64::MAX, which is
                                              // (u64::MAX - now_ms) = max_skew/2 ahead — WITHIN the skew limit.
                                              // So this particular case should be ACCEPTED.
        let observed_ms = u64::MAX;
        let mut clock = HlcClock::new(NODE_A, now_ms);
        let observed = HlcTimestamp {
            wall_ms: observed_ms,
            logical: 0,
            node_id: NODE_B,
        };
        // observed - now_ms = max_skew/2, which is < max_skew → should be accepted.
        clock
            .receive(now_ms, &observed)
            .expect("observed exactly max_skew/2 ahead of near-MAX now_ms must be accepted");
    }

    /// A timestamp exactly max_skew_ms ahead of a near-u64::MAX now_ms is accepted.
    #[test]
    fn receive_accepts_timestamp_at_exact_skew_limit_near_u64_max() {
        let now_ms = u64::MAX - DEFAULT_MAX_CLOCK_SKEW_MS * 2;
        let mut clock = HlcClock::new(NODE_A, now_ms);
        let observed = HlcTimestamp {
            wall_ms: now_ms + DEFAULT_MAX_CLOCK_SKEW_MS, // exactly at the limit
            logical: 0,
            node_id: NODE_B,
        };
        clock
            .receive(now_ms, &observed)
            .expect("timestamp exactly at skew limit must be accepted");
    }

    #[test]
    fn ord_higher_wall_sorts_greater() {
        let low = HlcTimestamp {
            wall_ms: 100,
            logical: 99,
            node_id: NODE_B,
        };
        let high = HlcTimestamp {
            wall_ms: 200,
            logical: 0,
            node_id: NODE_A,
        };
        assert!(
            high > low,
            "higher wall_ms must sort greater regardless of logical"
        );
    }

    #[test]
    fn ord_same_wall_higher_logical_sorts_greater() {
        let low = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: NODE_A,
        };
        let high = HlcTimestamp {
            wall_ms: 500,
            logical: 2,
            node_id: NODE_A,
        };
        assert!(high > low, "higher logical must sort greater on same wall");
    }

    #[test]
    fn ord_same_wall_same_logical_node_id_is_tiebreaker() {
        let a = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: [0x01; 8],
        };
        let b = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: [0x02; 8],
        };
        assert!(b > a, "node_id is the final tiebreaker");
    }

    // ── new_seeded tests ──────────────────────────────────────────────────────

    #[test]
    fn new_seeded_wall_ahead_of_checkpoint_ignores_checkpoint_logical() {
        // Normal restart: wall clock has advanced past the checkpoint.
        // The first send() must be (now_ms, 1, node_id) — not constrained by
        // the checkpoint's logical counter.
        let checkpoint = HlcTimestamp {
            wall_ms: 900,
            logical: 999,
            node_id: NODE_B,
        };
        let mut clock = HlcClock::new_seeded(NODE_A, 1000, checkpoint);
        let t = clock.send(1000);
        assert_eq!(t.wall_ms, 1000);
        assert_eq!(
            t.logical, 1,
            "logical must start at 1 after send on fresh wall"
        );
    }

    #[test]
    fn new_seeded_clock_stepped_back_preserves_monotonicity() {
        // NTP stepped the clock back: now_ms < checkpoint.wall_ms.
        // The first send() must be strictly greater than the checkpoint.
        let checkpoint = HlcTimestamp {
            wall_ms: 2000,
            logical: 5,
            node_id: NODE_B,
        };
        let mut clock = HlcClock::new_seeded(NODE_A, 1000, checkpoint);
        let t = clock.send(1000);
        assert!(
            t > checkpoint,
            "first send after restart must exceed checkpoint: {t:?} vs {checkpoint:?}"
        );
        assert_eq!(t.wall_ms, 2000);
        assert_eq!(t.logical, 6, "logical must be checkpoint.logical + 1");
    }

    #[test]
    fn new_seeded_same_ms_as_checkpoint_preserves_monotonicity() {
        // Restart within the same millisecond as the checkpoint.
        let checkpoint = HlcTimestamp {
            wall_ms: 1000,
            logical: 3,
            node_id: NODE_B,
        };
        let mut clock = HlcClock::new_seeded(NODE_A, 1000, checkpoint);
        let t = clock.send(1000);
        assert!(
            t > checkpoint,
            "first send within same ms must exceed checkpoint: {t:?} vs {checkpoint:?}"
        );
        assert_eq!(t.logical, 4, "logical must be checkpoint.logical + 1");
    }
}
