use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::config::SmtpRelayPeerConfig;

/// Per-peer state for one configured SMTP relay.
#[derive(Debug)]
pub struct PeerStatus {
    pub host_port: String,
    pub is_up: bool,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
}

/// Shared health state for all configured SMTP relay peers.
/// Tracks up/down state and provides round-robin peer selection.
pub struct PeerHealthState {
    peers: Vec<(SmtpRelayPeerConfig, PeerStatus)>,
    rr_index: usize,
    down_backoff: Duration,
}

impl PeerHealthState {
    /// Create health state for the given peer list.
    /// `down_backoff`: how long a peer stays in down state before being retried.
    pub fn new(peers: Vec<SmtpRelayPeerConfig>, down_backoff: Duration) -> Self {
        let statuses = peers
            .into_iter()
            .map(|cfg| {
                let host_port = cfg.host_port();
                (
                    cfg,
                    PeerStatus {
                        host_port,
                        is_up: true,
                        last_success: None,
                        last_failure: None,
                        attempt_count: 0,
                        success_count: 0,
                        failure_count: 0,
                    },
                )
            })
            .collect();
        PeerHealthState {
            peers: statuses,
            rr_index: 0,
            down_backoff,
        }
    }

    /// Mark a peer as up after successful delivery.
    pub fn mark_up(&mut self, idx: usize) {
        if let Some((cfg, status)) = self.peers.get_mut(idx) {
            let was_down = !status.is_up;
            status.is_up = true;
            status.last_success = Some(Instant::now());
            status.success_count += 1;
            if was_down {
                info!(peer = %cfg.host_port(), "relay peer recovered: down → up");
            }
        }
    }

    /// Mark a peer as down after a failed delivery.
    pub fn mark_down(&mut self, idx: usize) {
        if let Some((cfg, status)) = self.peers.get_mut(idx) {
            let was_up = status.is_up;
            status.is_up = false;
            status.last_failure = Some(Instant::now());
            status.failure_count += 1;
            if was_up {
                warn!(peer = %cfg.host_port(), "relay peer marked down: up → down");
            }
        }
    }

    /// Select the next peer for delivery and record the attempt atomically.
    ///
    /// A peer is eligible if:
    /// - it is marked up, OR
    /// - it has never failed (`last_failure` is `None`), OR
    /// - its last failure was more than `down_backoff` ago
    ///
    /// On success, advances the round-robin cursor and increments `attempt_count`
    /// for the chosen peer in one step, so callers cannot forget to record the
    /// attempt.  Returns `(index, &SmtpRelayPeerConfig)` or `None` if no peers
    /// are eligible.
    ///
    /// ## Round-robin design
    ///
    /// `rr_index` is tracked in *full peer list space* (0..n), not in eligible
    /// list space.  This ensures that when a downed peer recovers, the cursor
    /// position is still meaningful — we resume where the full list left off,
    /// not some position relative to a smaller eligible subset.
    ///
    /// Selection: build the eligible index list, then find the first eligible
    /// index `>= rr_index`.  If none exist at or after `rr_index`, wrap to
    /// index 0 of the eligible list (i.e. `unwrap_or(0)` returns position 0 in
    /// the *eligible* list, which is the smallest eligible peer index overall).
    ///
    /// After selecting `chosen_idx`, `rr_index` advances to `(chosen_idx + 1) % n`
    /// so the next call starts scanning just past the chosen peer in full-list
    /// space, distributing load even if the eligible set is sparse.
    pub fn select_peer(&mut self) -> Option<(usize, &SmtpRelayPeerConfig)> {
        let now = Instant::now();
        let n = self.peers.len();
        if n == 0 {
            return None;
        }

        let eligible: Vec<usize> = (0..n)
            .filter(|&i| {
                let status = &self.peers[i].1;
                status.is_up
                    || status.last_failure.is_none()
                    || status
                        .last_failure
                        .is_some_and(|t| now.duration_since(t) >= self.down_backoff)
            })
            .collect();

        if eligible.is_empty() {
            return None;
        }

        // Round-robin: find the next eligible index at or after rr_index, wrapping around.
        let start = self.rr_index % n;
        let chosen_pos = eligible.iter().position(|&i| i >= start).unwrap_or(0);
        let chosen_idx = eligible[chosen_pos];

        // Advance rr_index and record the attempt atomically.
        self.rr_index = (chosen_idx + 1) % n;
        self.peers[chosen_idx].1.attempt_count += 1;

        Some((chosen_idx, &self.peers[chosen_idx].0))
    }

    /// All peer statuses (for metrics export).
    pub fn all_statuses(&self) -> impl Iterator<Item = &PeerStatus> {
        self.peers.iter().map(|(_, s)| s)
    }

    /// Number of configured peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// True if no peers configured.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Returns `true` if at least one peer is currently eligible for delivery
    /// (either marked up or its backoff window has elapsed).
    ///
    /// Used by [`SmtpRelayMailer::healthy`] to implement the
    /// [`OutboundMailer::healthy`] contract without consuming the selection
    /// cursor.
    pub fn has_healthy_peer(&self) -> bool {
        if self.peers.is_empty() {
            return false;
        }
        let now = Instant::now();
        self.peers.iter().any(|(_, status)| {
            status.is_up
                || status.last_failure.is_none()
                || status
                    .last_failure
                    .is_some_and(|t| now.duration_since(t) >= self.down_backoff)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpRelayPeerConfig;
    use std::time::Duration;

    fn make_peer(host: &str) -> SmtpRelayPeerConfig {
        SmtpRelayPeerConfig {
            host: host.to_string(),
            port: 587,
            tls: true,
            username: None,
            password: None,
        }
    }

    #[test]
    fn no_peers_returns_none() {
        let mut state = PeerHealthState::new(vec![], Duration::from_secs(300));
        assert!(state.select_peer().is_none());
    }

    #[test]
    fn single_peer_starts_up_returns_it() {
        let mut state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        let result = state.select_peer();
        assert!(result.is_some());
        let (idx, cfg) = result.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(cfg.host, "smtp1.example.com");
    }

    #[test]
    fn single_peer_marked_down_returns_none_within_backoff() {
        let backoff = Duration::from_secs(300);
        let mut state = PeerHealthState::new(vec![make_peer("smtp1.example.com")], backoff);
        state.mark_down(0);
        assert!(state.select_peer().is_none());
    }

    #[test]
    fn single_peer_marked_down_then_backoff_elapsed_returns_it() {
        let backoff = Duration::from_millis(1);
        let mut state = PeerHealthState::new(vec![make_peer("smtp1.example.com")], backoff);
        state.mark_down(0);
        std::thread::sleep(Duration::from_millis(5));
        let result = state.select_peer();
        assert!(result.is_some(), "should return peer after backoff elapsed");
    }

    #[test]
    fn two_peers_first_down_returns_second() {
        let mut state = PeerHealthState::new(
            vec![
                make_peer("smtp1.example.com"),
                make_peer("smtp2.example.com"),
            ],
            Duration::from_secs(300),
        );
        state.mark_down(0);
        let result = state.select_peer();
        assert!(result.is_some());
        let (idx, cfg) = result.unwrap();
        assert_eq!(idx, 1, "should skip down peer 0");
        assert_eq!(cfg.host, "smtp2.example.com");
    }

    #[test]
    fn two_peers_both_up_round_robins() {
        let mut state = PeerHealthState::new(
            vec![
                make_peer("smtp1.example.com"),
                make_peer("smtp2.example.com"),
            ],
            Duration::from_secs(300),
        );
        let (idx1, _) = state.select_peer().unwrap();
        let (idx2, _) = state.select_peer().unwrap();
        assert_ne!(idx1, idx2, "round-robin should alternate between two peers");
        let (idx3, _) = state.select_peer().unwrap();
        assert_eq!(idx3, idx1, "should wrap around to first peer");
    }

    #[test]
    fn mark_up_increments_success_count() {
        let mut state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        state.mark_up(0);
        let status = state.all_statuses().next().unwrap();
        assert_eq!(status.success_count, 1);
        assert!(status.is_up);
        assert!(status.last_success.is_some());
    }

    #[test]
    fn mark_down_increments_failure_count() {
        let mut state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        state.mark_down(0);
        let status = state.all_statuses().next().unwrap();
        assert_eq!(status.failure_count, 1);
        assert!(!status.is_up);
    }

    #[test]
    fn select_peer_increments_attempt_count() {
        let mut state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        state.select_peer();
        state.select_peer();
        let status = state.all_statuses().next().unwrap();
        assert_eq!(
            status.attempt_count, 2,
            "select_peer must increment attempt_count"
        );
    }

    // Oracle: has_healthy_peer with no peers returns false.
    #[test]
    fn has_healthy_peer_empty_is_false() {
        let state = PeerHealthState::new(vec![], Duration::from_secs(300));
        assert!(!state.has_healthy_peer());
    }

    // Oracle: has_healthy_peer with one up peer returns true.
    #[test]
    fn has_healthy_peer_one_up_is_true() {
        let state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        assert!(state.has_healthy_peer());
    }

    // Oracle: has_healthy_peer after marking sole peer down within backoff returns false.
    #[test]
    fn has_healthy_peer_all_down_within_backoff_is_false() {
        let mut state = PeerHealthState::new(
            vec![make_peer("smtp1.example.com")],
            Duration::from_secs(300),
        );
        state.mark_down(0);
        assert!(!state.has_healthy_peer());
    }

    // Oracle: has_healthy_peer after backoff elapsed returns true again.
    #[test]
    fn has_healthy_peer_backoff_elapsed_is_true() {
        let backoff = Duration::from_millis(1);
        let mut state = PeerHealthState::new(vec![make_peer("smtp1.example.com")], backoff);
        state.mark_down(0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(state.has_healthy_peer());
    }
}
