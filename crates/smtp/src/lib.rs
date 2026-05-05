pub mod auth;
pub mod config;
pub mod dns_cache;
pub mod metrics;
pub mod mta_sts_dns;
pub mod mta_sts_error;
pub mod mta_sts_fetcher;
pub mod mta_sts_mx;
pub mod mta_sts_policy;
pub mod nntp_client;
pub mod outbound_mailer;
pub mod queue;
pub mod relay_client;
pub mod relay_error;
pub mod relay_health;
pub mod relay_queue;
pub mod routing;
pub mod routing_mailer;
pub mod server;
#[cfg(feature = "ses")]
pub mod ses_mailer;
pub mod session;
pub mod sieve_admin;
pub mod store;
pub mod tls;
pub mod tlsrpt;

#[cfg(test)]
pub mod test_support;

pub use mta_sts_dns::{lookup_mta_sts_txt, MtaStsTxtRecord};
pub use mta_sts_error::MtaStsError;
pub use mta_sts_fetcher::fetch_mta_sts_policy_body;
pub use mta_sts_mx::{check_mx_against_policy, mx_matches_pattern};
pub use mta_sts_policy::{parse_mta_sts_policy, MtaStsPolicy};
pub use outbound_mailer::{
    MessageType, OutboundEnvelope, OutboundError, OutboundMailer, SendReceipt, SmtpRelayMailer,
};
pub use relay_client::{deliver_via_relay, MtaStsEnforcer, PeerTlsStatus, RelayEnvelope};
pub use relay_error::SmtpRelayError;
pub use relay_health::PeerHealthState;
pub use relay_queue::SmtpRelayQueue;
pub use routing_mailer::{Route, RoutingMailer, Selector};
#[cfg(feature = "ses")]
pub use ses_mailer::SesMailer;
pub use tlsrpt::{TlsrptFailureRecord, TlsrptFailureType, TlsrptRecorder};
