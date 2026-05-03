use std::fmt;

/// Typed errors for MTA-STS policy lookup, fetch, parse, and enforcement.
#[derive(Debug)]
#[non_exhaustive]
pub enum MtaStsError {
    /// DNS/network failure while resolving or querying `_mta-sts.<domain>`.
    DnsLookupFailed { message: String },
    /// Multiple STSv1 TXT records found; RFC 8461 §3.1 requires exactly one.
    DnsTxtMultipleRecords,
    /// TXT record is missing the required `id=` field.
    DnsTxtMissingId,
    /// TXT record `id=` value exceeds 32 characters.
    DnsTxtIdTooLong,
    /// TXT record `id=` value contains non-alphanumeric characters.
    DnsTxtIdInvalid,
    /// HTTPS fetch of policy file failed (network, cert, timeout, or other I/O error).
    PolicyFetchFailed { message: String },
    /// Policy fetch returned a redirect response; RFC 8461 §3.3 forbids following redirects.
    PolicyFetchRedirectForbidden,
    /// Policy fetch returned a non-2xx HTTP status code.
    PolicyFetchHttpError { status: u16 },
    /// Policy fetch response body exceeded the configured size limit.
    PolicyFetchTooLarge,
    /// Policy file body failed to parse (missing field, bad value, oversized body).
    PolicyParseFailed { message: String },
    /// Connecting MX hostname does not match any pattern in the policy.
    MxNotMatched { mx: String },
}

impl fmt::Display for MtaStsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MTA-STS: ")?;
        match self {
            MtaStsError::DnsLookupFailed { message } => {
                write!(f, "DNS lookup failed: {}", message)
            }
            MtaStsError::DnsTxtMultipleRecords => {
                write!(f, "multiple STSv1 TXT records found")
            }
            MtaStsError::DnsTxtMissingId => {
                write!(f, "TXT record missing id= field")
            }
            MtaStsError::DnsTxtIdTooLong => {
                write!(f, "TXT record id= exceeds 32 characters")
            }
            MtaStsError::DnsTxtIdInvalid => {
                write!(f, "TXT record id= contains non-alphanumeric characters")
            }
            MtaStsError::PolicyFetchFailed { message } => {
                write!(f, "policy fetch failed: {}", message)
            }
            MtaStsError::PolicyFetchRedirectForbidden => {
                write!(f, "policy fetch redirect not allowed (RFC 8461 §3.3)")
            }
            MtaStsError::PolicyFetchHttpError { status } => {
                write!(f, "policy fetch HTTP {}", status)
            }
            MtaStsError::PolicyFetchTooLarge => {
                write!(f, "policy fetch response body too large")
            }
            MtaStsError::PolicyParseFailed { message } => {
                write!(f, "policy parse error: {}", message)
            }
            MtaStsError::MxNotMatched { mx } => {
                write!(f, "MX hostname '{}' not in policy", mx)
            }
        }
    }
}

impl std::error::Error for MtaStsError {}
