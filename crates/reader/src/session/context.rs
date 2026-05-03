use std::net::SocketAddr;

use stoa_core::article::GroupName;

use crate::session::{commands::list::GroupInfo, state::SessionState};

/// Jointly-held group-selection state.
///
/// `GroupSelected` state requires both a group name and an article pointer.
/// Keeping them together ensures they are set and cleared atomically — the
/// type system makes it impossible to have a group without an article pointer
/// or an article pointer without a group.
#[derive(Debug)]
pub struct SelectedGroup {
    /// Currently selected newsgroup.
    pub name: GroupName,
    /// Article pointer within the group per RFC 3977 §6.1.1.
    /// `None` for an empty group (no articles) or before any NEXT/LAST/ARTICLE.
    /// `Some(n)` once an article has been addressed.
    pub article_number: Option<u64>,
}

/// All per-connection state for one NNTP session.
///
/// Passed by mutable reference to every command handler.
#[derive(Debug)]
pub struct SessionContext {
    /// Current session state (auth/group transitions).
    pub state: SessionState,
    /// Authenticated username, if auth was performed.
    pub authenticated_user: Option<String>,
    /// Whether the connection is TLS-protected.
    ///
    /// True for NNTPS connections (implicit TLS, port 563) and for plain
    /// connections that have completed a STARTTLS upgrade (RFC 4642).
    /// False for unupgraded plain connections (port 119).
    pub tls_active: bool,
    /// SHA-256 fingerprint of the client's TLS certificate, if one was
    /// presented during the handshake.
    ///
    /// Format: `"sha256:<64-lowercase-hex-chars>"`.  `None` on plain
    /// connections or when the client did not present a certificate.
    /// Used by the AUTHINFO USER handler for password-free cert-based auth.
    pub client_cert_fingerprint: Option<String>,
    /// Raw DER bytes of the client's TLS leaf certificate.
    ///
    /// Stored alongside `client_cert_fingerprint` so that the AUTHINFO USER
    /// handler can pass the cert to `TrustedIssuerStore::verify_and_extract_cn`
    /// after fingerprint-based auth has been attempted.  `None` on plain
    /// connections or when the client did not present a certificate.
    pub client_cert_der: Option<Vec<u8>>,
    /// Username received from AUTHINFO USER, waiting for AUTHINFO PASS.
    pub pending_auth_user: Option<String>,
    /// Currently selected group and article pointer (atomically maintained).
    ///
    /// `None` when no group is selected (Authenticating or Active state).
    /// `Some(sg)` when a GROUP command has succeeded (GroupSelected state).
    /// Setting `state = GroupSelected` and `selected_group = Some(...)` must
    /// always happen together — do not set one without the other.
    pub selected_group: Option<SelectedGroup>,
    /// Remote peer address for logging.
    pub peer_addr: SocketAddr,
    /// Whether posting is permitted on this server.
    pub posting_allowed: bool,
    /// Known newsgroups served by this instance.
    ///
    /// Populated at server startup from configuration. Empty until storage
    /// integration is wired in by a later epic.
    pub known_groups: Vec<GroupInfo>,
    /// Count of consecutive AUTHINFO PASS failures this session.
    ///
    /// Incremented on each 481 response. Reset to 0 on a successful 281.
    /// When it reaches `MAX_AUTH_FAILURES` the session is closed with 400
    /// before any further response is sent.
    pub auth_failure_count: u32,
    /// Whether this session authenticated as the configured SMTP drain user.
    ///
    /// When `true`, the POST pipeline trusts the `X-Stoa-Injection-Source`
    /// header and uses its value to set article peerability.  When `false`
    /// (all normal user sessions), the header is stripped and the source is
    /// always `NntpPost` to prevent forgery.
    pub is_drain_session: bool,
    /// Whether a STARTTLS upgrade is available on this connection.
    ///
    /// Set to `true` when TLS cert/key are configured and the connection is
    /// not already TLS-protected.  Advertised in CAPABILITIES on plain
    /// connections.  Always `false` on NNTPS connections.
    pub starttls_available: bool,
    /// Whether the full-text search index is available.
    ///
    /// Set to `true` when `ServerStores::search_index` is `Some`.  Only when
    /// this is `true` is SEARCH advertised in CAPABILITIES.  RFC 3977 §5.2
    /// requires that capabilities advertised must be usable in the current
    /// state — advertising SEARCH when the index is absent misleads clients.
    pub search_available: bool,
}

/// Maximum consecutive AUTHINFO PASS failures before the connection is dropped.
pub const MAX_AUTH_FAILURES: u32 = 5;

/// Named boolean flags for `SessionContext::new`.
///
/// Replacing three adjacent `bool` parameters removes call-site ambiguity —
/// the field names serve as self-documenting labels at every construction site.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionFlags {
    /// If `true`, start in `Authenticating` state and require credentials
    /// before any newsreading commands are accepted.
    pub auth_required: bool,
    /// If `true`, the `POST` command is available on this connection.
    pub posting_allowed: bool,
    /// If `true`, the connection is already TLS-protected (NNTPS implicit TLS
    /// or a completed STARTTLS upgrade).
    pub tls_active: bool,
}

impl SessionContext {
    /// Create a new session context for an incoming connection.
    pub fn new(peer_addr: SocketAddr, flags: SessionFlags) -> Self {
        Self {
            state: if flags.auth_required {
                SessionState::Authenticating
            } else {
                SessionState::Active
            },
            authenticated_user: None,
            tls_active: flags.tls_active,
            client_cert_fingerprint: None,
            client_cert_der: None,
            pending_auth_user: None,
            selected_group: None,
            peer_addr,
            posting_allowed: flags.posting_allowed,
            known_groups: vec![],
            auth_failure_count: 0,
            is_drain_session: false,
            starttls_available: false,
            search_available: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[test]
    fn test_initial_state_auth_required() {
        let ctx = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: true,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert_eq!(ctx.state, SessionState::Authenticating);
    }

    #[test]
    fn test_initial_state_no_auth() {
        let ctx = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert_eq!(ctx.state, SessionState::Active);
    }

    #[test]
    fn test_initial_no_group() {
        let ctx = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert!(ctx.selected_group.is_none());
    }

    #[test]
    fn test_posting_allowed_flag() {
        let ctx_allowed = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert!(ctx_allowed.posting_allowed);
        let ctx_denied = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: false,
                tls_active: false,
            },
        );
        assert!(!ctx_denied.posting_allowed);
    }

    #[test]
    fn test_tls_active_flag() {
        let ctx_plain = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: false,
            },
        );
        assert!(!ctx_plain.tls_active);
        let ctx_tls = SessionContext::new(
            test_addr(),
            SessionFlags {
                auth_required: false,
                posting_allowed: true,
                tls_active: true,
            },
        );
        assert!(ctx_tls.tls_active);
    }
}
