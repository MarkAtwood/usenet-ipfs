use serde::{Deserialize, Serialize};

/// RFC 8460 §4.3 failure-type values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsrptFailureType {
    StarttlsNotSupported,
    CertificateHostMismatch,
    CertificateExpired,
    CertificateNotTrusted,
    ValidationFailure,
    TlsaInvalid,
    DnssecInvalid,
    DaneRequired,
    StsPolicyFetchError,
    StsPolicyInvalid,
    StsWebpkiInvalid,
}

/// A single RFC 8460 failure record for one delivery attempt.
#[derive(Debug, Clone, Serialize)]
pub struct TlsrptFailureRecord {
    pub result_type: TlsrptFailureType,
    pub sending_mta_ip: Option<String>,
    pub receiving_mx_hostname: Option<String>,
    pub receiving_mx_helo: Option<String>,
    pub receiving_ip: Option<String>,
    pub failed_session_count: u64,
    pub additional_information: Option<String>,
    pub failure_reason_code: Option<String>,
}

/// Accumulates TLSRPT failure records per recipient domain.
/// Thread-safe via Mutex. No I/O — accumulation only.
pub struct TlsrptRecorder {
    records: std::sync::Mutex<std::collections::HashMap<String, Vec<TlsrptFailureRecord>>>,
}

impl TlsrptRecorder {
    pub fn new() -> Self {
        TlsrptRecorder {
            records: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record a TLS failure for a delivery attempt to `recipient_domain`.
    pub fn record_failure(
        &self,
        recipient_domain: &str,
        failure_type: TlsrptFailureType,
        receiving_mx: Option<&str>,
        additional_info: Option<&str>,
    ) {
        let record = TlsrptFailureRecord {
            result_type: failure_type,
            sending_mta_ip: None,
            receiving_mx_hostname: receiving_mx.map(str::to_owned),
            receiving_mx_helo: None,
            receiving_ip: None,
            failed_session_count: 1,
            additional_information: additional_info.map(str::to_owned),
            failure_reason_code: None,
        };
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(recipient_domain.to_owned())
            .or_default()
            .push(record);
    }

    /// Get all accumulated records (for testing / report generation).
    pub fn get_records(&self) -> std::collections::HashMap<String, Vec<TlsrptFailureRecord>> {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Default for TlsrptRecorder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T1: record_failure accumulates under the correct domain key.
    // Oracle: get_records must return exactly one entry for the domain with
    // one record whose result_type matches what was passed.
    #[test]
    fn record_failure_stores_under_domain() {
        let rec = TlsrptRecorder::new();
        rec.record_failure(
            "example.com",
            TlsrptFailureType::StarttlsNotSupported,
            Some("mx.example.com"),
            None,
        );
        let records = rec.get_records();
        let entries = records.get("example.com").expect("domain must be present");
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].result_type,
            TlsrptFailureType::StarttlsNotSupported
        ));
        assert_eq!(
            entries[0].receiving_mx_hostname.as_deref(),
            Some("mx.example.com")
        );
    }

    // T2: multiple failures for the same domain are appended, not replaced.
    // Oracle: after two record_failure calls for the same domain,
    // get_records must return a Vec with two entries.
    #[test]
    fn multiple_failures_same_domain_appended() {
        let rec = TlsrptRecorder::new();
        rec.record_failure(
            "example.com",
            TlsrptFailureType::CertificateExpired,
            None,
            None,
        );
        rec.record_failure(
            "example.com",
            TlsrptFailureType::CertificateNotTrusted,
            None,
            None,
        );
        let records = rec.get_records();
        let entries = records.get("example.com").expect("domain must be present");
        assert_eq!(entries.len(), 2);
    }

    // T3: failures for different domains are stored independently.
    // Oracle: two domains → two separate Vec entries in get_records.
    #[test]
    fn failures_different_domains_stored_independently() {
        let rec = TlsrptRecorder::new();
        rec.record_failure(
            "a.example.com",
            TlsrptFailureType::StsPolicyFetchError,
            None,
            None,
        );
        rec.record_failure(
            "b.example.com",
            TlsrptFailureType::StsWebpkiInvalid,
            None,
            None,
        );
        let records = rec.get_records();
        assert_eq!(records.len(), 2);
        assert!(records.contains_key("a.example.com"));
        assert!(records.contains_key("b.example.com"));
    }

    // T4: new recorder has no records.
    // Oracle: get_records on a fresh TlsrptRecorder returns an empty map.
    #[test]
    fn new_recorder_is_empty() {
        let rec = TlsrptRecorder::new();
        assert!(rec.get_records().is_empty());
    }

    // T5: failure_type serialises to kebab-case per RFC 8460 §4.3.
    // Oracle: serde_json must produce the exact strings mandated by the RFC.
    #[test]
    fn failure_type_serialises_to_kebab_case() {
        let pairs = [
            (
                TlsrptFailureType::StarttlsNotSupported,
                "starttls-not-supported",
            ),
            (
                TlsrptFailureType::CertificateHostMismatch,
                "certificate-host-mismatch",
            ),
            (TlsrptFailureType::CertificateExpired, "certificate-expired"),
            (
                TlsrptFailureType::CertificateNotTrusted,
                "certificate-not-trusted",
            ),
            (TlsrptFailureType::ValidationFailure, "validation-failure"),
            (TlsrptFailureType::TlsaInvalid, "tlsa-invalid"),
            (TlsrptFailureType::DnssecInvalid, "dnssec-invalid"),
            (TlsrptFailureType::DaneRequired, "dane-required"),
            (
                TlsrptFailureType::StsPolicyFetchError,
                "sts-policy-fetch-error",
            ),
            (TlsrptFailureType::StsPolicyInvalid, "sts-policy-invalid"),
            (TlsrptFailureType::StsWebpkiInvalid, "sts-webpki-invalid"),
        ];
        for (variant, expected) in pairs {
            let json = serde_json::to_string(&variant).expect("serialise");
            assert_eq!(json, format!("\"{expected}\""), "wrong JSON for {expected}");
        }
    }

    // T6: additional_information is stored when provided.
    // Oracle: the field in the stored record must match the input.
    #[test]
    fn additional_information_stored() {
        let rec = TlsrptRecorder::new();
        rec.record_failure(
            "example.com",
            TlsrptFailureType::ValidationFailure,
            None,
            Some("certificate revoked"),
        );
        let records = rec.get_records();
        let entry = &records["example.com"][0];
        assert_eq!(
            entry.additional_information.as_deref(),
            Some("certificate revoked")
        );
    }
}
