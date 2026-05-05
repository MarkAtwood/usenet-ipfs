use std::net::IpAddr;

use mail_auth::{
    dmarc::{verify::DmarcParameters, Policy},
    spf::verify::SpfParameters,
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, MessageAuthenticator,
    Parameters, SpfResult,
};
use tracing::debug;

use crate::dns_cache::DnsCache;

/// The result of running the inbound authentication pipeline on one message.
#[derive(Debug)]
pub struct InboundAuthResult {
    /// Value for the `Authentication-Results:` header (the whole header value,
    /// not just the result token — includes the authserv-id prefix).
    pub header: String,
    /// `true` when DMARC policy is `reject`, SPF failed, and DKIM failed.
    /// The session should return 550 and not enqueue the message.
    pub dmarc_reject: bool,
    /// RFC 5183 Sieve environment values derived from authentication results.
    ///
    /// Populated before calling the Sieve evaluator so scripts can branch on
    /// `vnd.stoa.dkim-result`, `vnd.stoa.spf-result`, etc.
    pub sieve_env: stoa_sieve_native::SieveEnv,
}

/// Run the full inbound authentication pipeline:
/// DKIM → SPF (MAIL FROM) → DMARC → ARC.
///
/// Always returns an `InboundAuthResult`; errors from individual checks
/// produce `TempError` or `PermError` results in the header but never
/// propagate as Rust errors — RFC 7601 mandates that unverifiable checks
/// produce a result, not a rejection.
pub async fn verify_inbound(
    authenticator: &MessageAuthenticator,
    cache: &DnsCache,
    raw_message: &[u8],
    client_ip: IpAddr,
    ehlo_domain: &str,
    mail_from: &str,
    hostname: &str,
) -> InboundAuthResult {
    // Parse the message.  If it cannot be parsed at all we can still produce
    // a result (permerror) and continue — we will not reject.
    let Some(msg) = AuthenticatedMessage::parse(raw_message) else {
        return InboundAuthResult {
            header: format!("{hostname}; auth=permerror (message parse failed)"),
            dmarc_reject: false,
            sieve_env: stoa_sieve_native::SieveEnv::new(),
        };
    };

    // DKIM: verify all DKIM-Signature headers present in the message.
    let dkim_results = authenticator
        .verify_dkim(
            Parameters::new(&msg)
                .with_txt_cache(&cache.txt)
                .with_mx_cache(&cache.mx)
                .with_ipv4_cache(&cache.ipv4)
                .with_ipv6_cache(&cache.ipv6)
                .with_ptr_cache(&cache.ptr),
        )
        .await;

    // SPF: check MAIL FROM identity against the connecting IP.
    let spf_result = authenticator
        .verify_spf(
            Parameters::new(SpfParameters::verify_mail_from(
                client_ip,
                ehlo_domain,
                hostname,
                mail_from,
            ))
            .with_txt_cache(&cache.txt)
            .with_mx_cache(&cache.mx)
            .with_ipv4_cache(&cache.ipv4)
            .with_ipv6_cache(&cache.ipv6)
            .with_ptr_cache(&cache.ptr),
        )
        .await;

    // DMARC: check From: domain against SPF and DKIM results.
    let rfc5321_domain = mail_from
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(ehlo_domain);
    let dmarc_result: mail_auth::DmarcOutput = authenticator
        .verify_dmarc(
            Parameters::new(DmarcParameters::new(
                &msg,
                &dkim_results,
                rfc5321_domain,
                &spf_result,
            ))
            .with_txt_cache(&cache.txt)
            .with_mx_cache(&cache.mx)
            .with_ipv4_cache(&cache.ipv4)
            .with_ipv6_cache(&cache.ipv6)
            .with_ptr_cache(&cache.ptr),
        )
        .await;

    // ARC: validate forwarded-mail chain for mailing lists.
    let arc_result = authenticator
        .verify_arc(
            Parameters::new(&msg)
                .with_txt_cache(&cache.txt)
                .with_mx_cache(&cache.mx)
                .with_ipv4_cache(&cache.ipv4)
                .with_ipv6_cache(&cache.ipv6)
                .with_ptr_cache(&cache.ptr),
        )
        .await;

    // Determine whether DMARC mandates rejection.
    // We only reject when policy=reject AND both SPF and DKIM fail — a passing
    // ARC chain in verify_arc is not yet considered here (v1 simplification;
    // a valid ARC chain should excuse DMARC failure for list mail, but that
    // requires policy-level ARC bypass logic added in a later epic).
    let dmarc_reject = matches!(dmarc_result.policy(), Policy::Reject)
        && matches!(dmarc_result.dkim_result(), DmarcResult::Fail(_))
        && matches!(dmarc_result.spf_result(), DmarcResult::Fail(_));

    // Build the Authentication-Results header value.
    let header_from = msg.from.first().map(String::as_str).unwrap_or("");
    let auth_header = AuthenticationResults::new(hostname)
        .with_dkim_results(&dkim_results, header_from)
        .with_spf_mailfrom_result(&spf_result, client_ip, mail_from, ehlo_domain)
        .with_dmarc_result(&dmarc_result)
        .with_arc_result(&arc_result, client_ip)
        .to_string();

    // Build RFC 5183 Sieve environment values from authentication results.
    let sieve_env = build_sieve_env(hostname, &dkim_results, &spf_result, &dmarc_result);

    debug!(
        spf = ?spf_result.result(),
        dmarc_reject,
        "inbound auth complete"
    );

    InboundAuthResult {
        header: auth_header,
        dmarc_reject,
        sieve_env,
    }
}

/// Build a [`stoa_sieve_native::SieveEnv`] from inbound authentication results.
///
/// Exposes standard RFC 5183 values and `vnd.stoa.*` extension values.
///
/// | Name                    | Values                                  |
/// |-------------------------|-----------------------------------------|
/// | domain / host           | server hostname                         |
/// | location                | `"MTA"`                                 |
/// | phase                   | `"during"`                              |
/// | vnd.stoa.dkim-result    | `pass` / `fail` / `none`                |
/// | vnd.stoa.dkim-domain    | d= value or empty string                |
/// | vnd.stoa.spf-result     | `pass` / `fail` / `softfail` / `neutral` / `none` |
/// | vnd.stoa.dmarc-result   | `pass` / `fail` / `none`                |
/// | vnd.stoa.dmarc-policy   | `reject` / `quarantine` / `none`        |
fn build_sieve_env(
    hostname: &str,
    dkim_results: &[mail_auth::DkimOutput<'_>],
    spf_result: &mail_auth::SpfOutput,
    dmarc_result: &mail_auth::DmarcOutput,
) -> stoa_sieve_native::SieveEnv {
    let mut env = stoa_sieve_native::SieveEnv::new();

    // Standard RFC 5183 values.
    env.set("domain", hostname);
    env.set("host", hostname);
    env.set("location", "MTA");
    env.set("phase", "during");

    // vnd.stoa.dkim-result: use the first passing DKIM result; if none passed,
    // use "fail" if any signature was present, or "none" if absent.
    let first_pass = dkim_results
        .iter()
        .find(|r| *r.result() == DkimResult::Pass);
    if let Some(pass) = first_pass {
        env.set("vnd.stoa.dkim-result", "pass");
        // d= value from the DKIM signature; empty string if absent.
        let domain = pass.signature().map(|s| s.d.as_str()).unwrap_or("");
        env.set("vnd.stoa.dkim-domain", domain);
    } else if dkim_results.is_empty() {
        env.set("vnd.stoa.dkim-result", "none");
        env.set("vnd.stoa.dkim-domain", "");
    } else {
        env.set("vnd.stoa.dkim-result", "fail");
        // Use the domain from the first failed signature if available.
        let domain = dkim_results[0]
            .signature()
            .map(|s| s.d.as_str())
            .unwrap_or("");
        env.set("vnd.stoa.dkim-domain", domain);
    }

    // vnd.stoa.spf-result: map SpfResult variants to lowercase strings.
    let spf_str = match spf_result.result() {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::None | SpfResult::TempError | SpfResult::PermError => "none",
    };
    env.set("vnd.stoa.spf-result", spf_str);

    // vnd.stoa.dmarc-result and vnd.stoa.dmarc-policy.
    let (dmarc_res_str, dmarc_policy_str) = match dmarc_result.dkim_result() {
        DmarcResult::Pass => (
            "pass",
            match dmarc_result.policy() {
                Policy::Reject => "reject",
                Policy::Quarantine => "quarantine",
                _ => "none",
            },
        ),
        DmarcResult::None => ("none", "none"),
        _ => match dmarc_result.spf_result() {
            DmarcResult::Pass => (
                "pass",
                match dmarc_result.policy() {
                    Policy::Reject => "reject",
                    Policy::Quarantine => "quarantine",
                    _ => "none",
                },
            ),
            _ => (
                "fail",
                match dmarc_result.policy() {
                    Policy::Reject => "reject",
                    Policy::Quarantine => "quarantine",
                    _ => "none",
                },
            ),
        },
    };
    env.set("vnd.stoa.dmarc-result", dmarc_res_str);
    env.set("vnd.stoa.dmarc-policy", dmarc_policy_str);

    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::DnsCache;
    use std::net::Ipv4Addr;

    // Build a minimal RFC 5322 message with no DKIM signatures and a From
    // domain that has no DMARC record.  Under cargo test the mail-auth crate
    // uses mock_resolve() which returns DnsRecordNotFound for every lookup, so
    // all checks will produce None / TempError results — never reject.
    fn simple_message() -> Vec<u8> {
        b"From: sender@example.com\r\n\
          To: recipient@example.com\r\n\
          Subject: Hello\r\n\
          Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
          Message-ID: <test@example.com>\r\n\
          \r\n\
          Body text.\r\n"
            .to_vec()
    }

    fn make_auth() -> MessageAuthenticator {
        // `new_cloudflare()` creates a resolver pointing at 1.1.1.1, but
        // under `#[cfg(test)]` mail-auth's dns helpers call mock_resolve()
        // (returning NXDomain) before any real network I/O occurs.
        MessageAuthenticator::new_cloudflare().expect("resolver creation must not fail")
    }

    #[tokio::test]
    async fn plain_message_never_rejected() {
        let auth = make_auth();
        let cache = DnsCache::new();
        let msg = simple_message();
        let result = verify_inbound(
            &auth,
            &cache,
            &msg,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "client.example.com",
            "sender@example.com",
            "mx.example.com",
        )
        .await;

        assert!(
            !result.dmarc_reject,
            "plain message with no DMARC record must not be rejected"
        );
        // The Authentication-Results header value must start with the authserv-id.
        assert!(
            result.header.contains("mx.example.com"),
            "header must include authserv-id: {}",
            result.header
        );
    }

    #[tokio::test]
    async fn unparseable_message_returns_permerror() {
        let auth = make_auth();
        let cache = DnsCache::new();
        // A zero-length message cannot be parsed.
        let result = verify_inbound(
            &auth,
            &cache,
            b"",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "client.example.com",
            "sender@example.com",
            "mx.example.com",
        )
        .await;
        assert!(!result.dmarc_reject);
        assert!(
            result.header.contains("permerror"),
            "expected permerror in header: {}",
            result.header
        );
    }
}
