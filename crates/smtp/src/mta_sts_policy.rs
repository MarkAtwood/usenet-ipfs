use crate::config::MtaStsMode;
use crate::MtaStsError;

/// A parsed MTA-STS policy (RFC 8461 §3.2).
#[derive(Debug)]
pub struct MtaStsPolicy {
    pub mode: MtaStsMode,
    pub mx_patterns: Vec<String>,
    pub max_age: u32,
}

/// Parse an MTA-STS policy file body (RFC 8461 §3.2).
///
/// Returns `Err(PolicyParseFailed)` for any violation of the spec.
pub fn parse_mta_sts_policy(
    body: &str,
    max_body_bytes: usize,
) -> Result<MtaStsPolicy, MtaStsError> {
    if body.len() > max_body_bytes {
        return Err(MtaStsError::PolicyParseFailed { message: "policy body too large".into() });
    }

    // Split on both CRLF and bare LF; filter out blank / whitespace-only lines.
    let lines: Vec<&str> = body
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .collect();

    if lines.is_empty() {
        return Err(MtaStsError::PolicyParseFailed { message: "first line must be 'version: STSv1'".into() });
    }

    // RFC 8461 §3.2: first non-empty line MUST be "version: STSv1" (case-sensitive).
    if lines[0] != "version: STSv1" {
        return Err(MtaStsError::PolicyParseFailed { message: "first line must be 'version: STSv1'".into() });
    }

    let mut mode: Option<MtaStsMode> = None;
    let mut mx_patterns: Vec<String> = Vec::new();
    let mut max_age: Option<u32> = None;

    for line in &lines[1..] {
        // Key and value are separated by ": " (colon-space).
        // RFC 8461 §3.2: "Each tag-value pair is terminated by a CRLF".
        // Unknown keys are silently ignored.
        let Some((key, value)) = line.split_once(": ") else {
            // Malformed or unknown — skip per RFC 8461 §3.2.
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "mode" => {
                if mode.is_some() {
                    return Err(MtaStsError::PolicyParseFailed { message: "duplicate 'mode' field".into() });
                }
                let parsed = match value {
                    "none" => MtaStsMode::None,
                    "testing" => MtaStsMode::Testing,
                    "enforce" => MtaStsMode::Enforce,
                    other => {
                        return Err(MtaStsError::PolicyParseFailed { message: format!(
                            "unknown mode value: {}",
                            other
                        ) });
                    }
                };
                mode = Some(parsed);
            }
            "mx" => {
                let pattern = value.to_owned();
                // RFC 8461 §4.1: a wildcard pattern must be "*.label[.label...]".
                // Bare "*." has an empty suffix and would match any single-label
                // hostname ending in a dot — reject it as malformed.
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    if suffix.is_empty() {
                        return Err(MtaStsError::PolicyParseFailed { message: "invalid mx pattern: '*.' requires a non-empty suffix".into() });
                    }
                }
                mx_patterns.push(pattern);
            }
            "max_age" => {
                if max_age.is_some() {
                    return Err(MtaStsError::PolicyParseFailed { message: "duplicate 'max_age' field".into() });
                }
                let parsed: u32 = value.parse().map_err(|_| {
                    MtaStsError::PolicyParseFailed { message: format!("max_age is not a valid u32: {}", value) }
                })?;
                if parsed > 31_557_600 {
                    return Err(MtaStsError::PolicyParseFailed { message: format!(
                        "max_age {} exceeds maximum 31557600",
                        parsed
                    ) });
                }
                max_age = Some(parsed);
            }
            _ => {
                // Unknown field — silently ignore per RFC 8461 §3.2.
            }
        }
    }

    let mode = mode.ok_or_else(|| MtaStsError::PolicyParseFailed { message: "missing 'mode' field".into() })?;
    // RFC 8461 §3.2: mx is required only for "enforce" and "testing" modes.
    // For "none", the mx list is irrelevant and may be omitted.
    if matches!(mode, MtaStsMode::Enforce | MtaStsMode::Testing) && mx_patterns.is_empty() {
        return Err(MtaStsError::PolicyParseFailed { message: "at least one 'mx' field is required for enforce/testing mode".into() });
    }
    let max_age =
        max_age.ok_or_else(|| MtaStsError::PolicyParseFailed { message: "missing 'max_age' field".into() })?;

    Ok(MtaStsPolicy {
        mode,
        mx_patterns,
        max_age,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference policy body taken from RFC 8461 §3.3 example.
    const EXAMPLE_POLICY: &str =
        "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n";

    #[test]
    fn parse_rfc_example_policy() {
        let p = parse_mta_sts_policy(EXAMPLE_POLICY, 65_536).expect("valid policy");
        assert_eq!(p.mode, MtaStsMode::Enforce);
        assert_eq!(p.mx_patterns, vec!["mail.example.com"]);
        assert_eq!(p.max_age, 86400);
    }

    #[test]
    fn parse_lf_only_line_endings() {
        let body = "version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 3600\n";
        let p = parse_mta_sts_policy(body, 65_536).expect("LF-only endings should work");
        assert_eq!(p.mode, MtaStsMode::Testing);
        assert_eq!(p.max_age, 3600);
    }

    #[test]
    fn parse_none_mode() {
        let body = "version: STSv1\nmode: none\nmx: mx.example.org\nmax_age: 0\n";
        let p = parse_mta_sts_policy(body, 65_536).expect("mode=none, max_age=0 are valid");
        assert_eq!(p.mode, MtaStsMode::None);
        assert_eq!(p.max_age, 0);
    }

    #[test]
    fn parse_multiple_mx_patterns() {
        let body = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmx: *.fallback.example.com\nmax_age: 86400\n";
        let p = parse_mta_sts_policy(body, 65_536).expect("multiple mx lines are valid");
        assert_eq!(p.mx_patterns.len(), 3);
        assert_eq!(p.mx_patterns[0], "mx1.example.com");
        assert_eq!(p.mx_patterns[2], "*.fallback.example.com");
    }

    #[test]
    fn unknown_fields_are_silently_ignored() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\nfuture_field: some_value\n";
        parse_mta_sts_policy(body, 65_536).expect("unknown fields must be ignored");
    }

    #[test]
    fn max_age_at_boundary() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 31557600\n";
        let p = parse_mta_sts_policy(body, 65_536).expect("max_age=31557600 is valid");
        assert_eq!(p.max_age, 31_557_600);
    }

    #[test]
    fn body_too_large_rejected() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 10).expect_err("body too large should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn wrong_version_rejected() {
        let body = "version: STSv2\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("wrong version should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    #[test]
    fn version_case_sensitive_rejected() {
        let body = "version: stsv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("lowercase version should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    #[test]
    fn missing_mode_rejected() {
        let body = "version: STSv1\nmx: mx.example.com\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("missing mode should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
        assert!(err.to_string().contains("mode"));
    }

    #[test]
    fn missing_mx_rejected() {
        let body = "version: STSv1\nmode: enforce\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("missing mx should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
        assert!(err.to_string().contains("mx"));
    }

    #[test]
    fn missing_max_age_rejected() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("missing max_age should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
        assert!(err.to_string().contains("max_age"));
    }

    #[test]
    fn invalid_mode_value_rejected() {
        let body = "version: STSv1\nmode: strict\nmx: mx.example.com\nmax_age: 86400\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("unknown mode should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    #[test]
    fn max_age_too_large_rejected() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 31557601\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("max_age > 31557600 should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    #[test]
    fn max_age_non_numeric_rejected() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: forever\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("non-numeric max_age should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    #[test]
    fn empty_body_rejected() {
        let err = parse_mta_sts_policy("", 65_536).expect_err("empty body should fail");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }

    // RFC 8461 §3.2 recommends max policy body ≤ 64 KiB.
    // A body whose length equals max_body_bytes must be accepted.
    // Oracle: construct a body of exactly 65 536 bytes with a valid header
    // followed by an unknown field padded to fill the limit.
    #[test]
    fn body_exactly_at_limit_accepted() {
        let prefix = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n";
        // Line format: "future_field: " (15 chars) + N 'x's + "\n" (1 char).
        let value_len = 65_536 - prefix.len() - 15;
        let padding = format!("future_field: {}\n", "x".repeat(value_len));
        let body = format!("{prefix}{padding}");
        assert_eq!(
            body.len(),
            65_536,
            "test setup: body must be exactly 65536 bytes"
        );
        parse_mta_sts_policy(&body, 65_536).expect("body at limit must be accepted");
    }

    // Duplicate mode field → PolicyParseFailed.
    // Oracle: a crafted body "mode: enforce … mode: none" must not silently
    // downgrade enforcement.  RFC 8461 §3.2 does not permit repeated fields.
    #[test]
    fn duplicate_mode_field_rejected() {
        let body =
            "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\nmode: none\n";
        let err = parse_mta_sts_policy(body, 65_536).expect_err("duplicate mode must be rejected");
        assert!(
            matches!(err, MtaStsError::PolicyParseFailed { .. }),
            "unexpected error: {err}"
        );
    }

    // Duplicate max_age field → PolicyParseFailed.
    // Oracle: same rationale as duplicate mode — last-wins silently alters policy.
    #[test]
    fn duplicate_max_age_field_rejected() {
        let body =
            "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\nmax_age: 0\n";
        let err =
            parse_mta_sts_policy(body, 65_536).expect_err("duplicate max_age must be rejected");
        assert!(
            matches!(err, MtaStsError::PolicyParseFailed { .. }),
            "unexpected error: {err}"
        );
    }

    // A body one byte over the 64 KiB limit must be rejected.
    // Oracle: pass a body of length 65 537 with max_body_bytes = 65 536.
    #[test]
    fn body_one_byte_over_limit_rejected() {
        let prefix = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n";
        let value_len = 65_537 - prefix.len() - 15;
        let padding = format!("future_field: {}\n", "x".repeat(value_len));
        let body = format!("{prefix}{padding}");
        assert_eq!(
            body.len(),
            65_537,
            "test setup: body must be exactly 65537 bytes"
        );
        let err =
            parse_mta_sts_policy(&body, 65_536).expect_err("body over limit must be rejected");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
        assert!(err.to_string().contains("too large"));
    }

    // RFC 8461 §3.2: "mx" is required only for "enforce" and "testing" modes.
    // A "none" policy with no mx lines is valid — it signals "stop enforcing".
    #[test]
    fn parse_none_mode_no_mx_accepted() {
        let body = "version: STSv1\nmode: none\nmax_age: 0\n";
        let p = parse_mta_sts_policy(body, 65_536)
            .expect("mode=none with no mx lines is valid per RFC 8461 §3.2");
        assert_eq!(p.mode, MtaStsMode::None);
        assert!(p.mx_patterns.is_empty());
    }

    // A bare "*." wildcard has an empty suffix and is not a valid MX pattern
    // per RFC 8461 §4.1 (wildcard must be "*.label[.label...]").
    #[test]
    fn bare_wildcard_mx_pattern_rejected() {
        let body = "version: STSv1\nmode: enforce\nmx: *.\nmax_age: 86400\n";
        let err =
            parse_mta_sts_policy(body, 65_536).expect_err("bare '*.' mx pattern must be rejected");
        assert!(matches!(err, MtaStsError::PolicyParseFailed { .. }));
    }
}
