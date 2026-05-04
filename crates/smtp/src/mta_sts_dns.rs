use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::TokioResolver;

use crate::MtaStsError;

/// The parsed content of a valid `_mta-sts.<domain>` TXT record.
#[derive(Debug, Clone)]
pub struct MtaStsTxtRecord {
    /// The `id=` value extracted from the TXT record (≤32 alphanumeric chars).
    pub policy_id: String,
}

/// Look up the MTA-STS DNS TXT record for `_mta-sts.<domain>`.
///
/// Returns `Ok(None)` if no STSv1 record exists.
/// Returns `Ok(Some(record))` if exactly one valid STSv1 record is found.
/// Returns `Err(MtaStsError::DnsTxtMultipleRecords)` if multiple STSv1 records are present.
/// Returns `Err(MtaStsError::DnsTxtMissingId / DnsTxtIdTooLong / DnsTxtIdInvalid)` if malformed.
pub async fn lookup_mta_sts_txt(
    resolver: &TokioResolver,
    domain: &str,
) -> Result<Option<MtaStsTxtRecord>, MtaStsError> {
    let name = format!("_mta-sts.{}.", domain.trim_end_matches('.'));

    let txt_lookup = match resolver.txt_lookup(name.as_str()).await {
        Ok(lookup) => lookup,
        Err(e) => {
            if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) {
                return Ok(None);
            }
            return Err(MtaStsError::DnsLookupFailed {
                message: format!("{e}"),
            });
        }
    };

    // Collect all TXT strings, joining multi-part character-strings within
    // each RR per RFC 7208 §3 (contiguous concatenation, no separator).
    let all_txt: Vec<String> = txt_lookup
        .iter()
        .map(|rdata| {
            rdata
                .txt_data()
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<String>()
        })
        .collect();

    // Filter to records where the first tag is v=STSv1 (RFC 8461 §3.1:
    // "If the first tag of a TXT record is not v=STSv1, the record MUST be ignored").
    let sts_records: Vec<&String> = all_txt
        .iter()
        .filter(|s| {
            s.split(';')
                .next()
                .map(|t| t.trim() == "v=STSv1")
                .unwrap_or(false)
        })
        .collect();

    match sts_records.len() {
        0 => return Ok(None),
        1 => {}
        _ => {
            return Err(MtaStsError::DnsTxtMultipleRecords);
        }
    }

    let record_text = sts_records[0];

    parse_sts_record(record_text)
}

/// Parse a single `_mta-sts` TXT record string (already confirmed to be an STSv1 record).
///
/// Returns `Ok(None)` when the first tag is not `v=STSv1`.
/// Returns `Ok(Some(record))` on success, or `Err` for any validation failure.
fn parse_sts_record(text: &str) -> Result<Option<MtaStsTxtRecord>, MtaStsError> {
    // RFC 8461 §3.1: first tag MUST be v=STSv1.
    if text
        .split(';')
        .next()
        .map(|t| t.trim() != "v=STSv1")
        .unwrap_or(true)
    {
        return Ok(None);
    }

    let mut policy_id: Option<String> = None;
    for pair in text.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("id=") {
            policy_id = Some(value.trim().to_owned());
        }
    }

    let id = match policy_id {
        Some(id) => id,
        None => {
            return Err(MtaStsError::DnsTxtMissingId);
        }
    };

    if id.is_empty() {
        return Err(MtaStsError::DnsTxtMissingId);
    }

    if id.len() > 32 {
        return Err(MtaStsError::DnsTxtIdTooLong);
    }

    if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(MtaStsError::DnsTxtIdInvalid);
    }

    Ok(Some(MtaStsTxtRecord { policy_id: id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // T1: well-formed record parses correctly.
    // Oracle: RFC 8461 §3.1 example — "v=STSv1; id=20160831085700Z"
    #[test]
    fn parse_valid_record() {
        let rec = parse_sts_record("v=STSv1; id=20160831085700Z")
            .expect("should not error")
            .expect("should be Some");
        assert_eq!(rec.policy_id, "20160831085700Z");
    }

    // T2: record without v=STSv1 is not an STS record → Ok(None).
    // Oracle: absence of the version tag means the record is not STSv1
    // (RFC 8461 §3.1 — version field MUST be present and case-sensitive).
    #[test]
    fn parse_non_sts_record_returns_none() {
        let result = parse_sts_record("v=spf1 include:example.com ~all").expect("should not error");
        assert!(result.is_none());
    }

    // T3: record missing the id field returns DnsTxtMissingId.
    // Oracle: RFC 8461 §3.1 — id field is REQUIRED.
    #[test]
    fn parse_missing_id_returns_error() {
        let err = parse_sts_record("v=STSv1").expect_err("should error on missing id");
        assert!(matches!(err, MtaStsError::DnsTxtMissingId));
    }

    // T4: id longer than 32 characters returns DnsTxtIdTooLong.
    // Oracle: RFC 8461 §3.1 — "id" value MUST be 1..32 chars.
    #[test]
    fn parse_id_too_long_returns_error() {
        let long_id = "A".repeat(33);
        let text = format!("v=STSv1; id={long_id}");
        let err = parse_sts_record(&text).expect_err("should error on long id");
        assert!(matches!(err, MtaStsError::DnsTxtIdTooLong));
    }

    // T5: id with non-alphanumeric characters returns DnsTxtIdInvalid.
    // Oracle: RFC 8461 §3.1 — id MUST match [a-zA-Z0-9]{1,32}.
    #[test]
    fn parse_invalid_id_chars_returns_error() {
        let err =
            parse_sts_record("v=STSv1; id=bad-id!").expect_err("should error on invalid id chars");
        assert!(matches!(err, MtaStsError::DnsTxtIdInvalid));
    }

    // T6: id of exactly 32 alphanumeric chars is accepted.
    // Oracle: RFC 8461 §3.1 — upper bound is 32 chars inclusive.
    #[test]
    fn parse_id_exactly_32_chars_accepted() {
        let id32 = "A".repeat(32);
        let text = format!("v=STSv1; id={id32}");
        let rec = parse_sts_record(&text)
            .expect("should not error")
            .expect("should be Some");
        assert_eq!(rec.policy_id, id32);
    }

    // --- select_sts_record: multi-record tests ---
    //
    // select_sts_record mirrors the filter+match logic used by lookup_mta_sts_txt
    // on the full list of TXT strings for a name.  These tests exercise it
    // without requiring a live DNS resolver (RFC 8461 §3.1).

    fn select_sts_record(records: &[&str]) -> Result<Option<MtaStsTxtRecord>, MtaStsError> {
        let sts: Vec<&&str> = records
            .iter()
            .filter(|s| {
                s.split(';')
                    .next()
                    .map(|t| t.trim() == "v=STSv1")
                    .unwrap_or(false)
            })
            .collect();
        match sts.len() {
            0 => Ok(None),
            1 => parse_sts_record(sts[0]),
            _ => Err(MtaStsError::DnsTxtMultipleRecords),
        }
    }

    // T7: zero TXT records → Ok(None).
    // Oracle: RFC 8461 §3.1 — no _mta-sts record means policy is absent.
    #[test]
    fn no_txt_records_returns_none() {
        let result = select_sts_record(&[]).expect("should not error");
        assert!(result.is_none());
    }

    // T8: one non-STSv1 TXT record → Ok(None).
    // Oracle: SPF and other TXT records must not be treated as MTA-STS records.
    #[test]
    fn only_non_sts_records_returns_none() {
        let result =
            select_sts_record(&["v=spf1 include:example.com ~all"]).expect("should not error");
        assert!(result.is_none());
    }

    // T9: exactly one valid STSv1 record → Ok(Some(record)).
    // Oracle: RFC 8461 §3.1 example "v=STSv1; id=20160831085359Z".
    #[test]
    fn one_valid_sts_record_returns_some() {
        let rec = select_sts_record(&["v=STSv1; id=20160831085359Z"])
            .expect("should not error")
            .expect("should be Some");
        assert_eq!(rec.policy_id, "20160831085359Z");
    }

    // T10: multiple STSv1 records → DnsTxtMultipleRecords (RFC 8461 §3.1 — ambiguous).
    // Oracle: "If multiple TXT records for _mta-sts are returned by the DNS,
    // the MTA MUST treat this as a misconfiguration" (RFC 8461 §3.1).
    #[test]
    fn multiple_sts_records_returns_error() {
        let err =
            select_sts_record(&["v=STSv1; id=20160831085359Z", "v=STSv1; id=20171001000000Z"])
                .expect_err("multiple STSv1 records must error");
        assert!(
            matches!(err, MtaStsError::DnsTxtMultipleRecords),
            "unexpected error: {err}"
        );
    }

    // T11: one STSv1 record mixed with non-STSv1 records → Ok(Some(record)).
    // Oracle: non-STSv1 TXT records (e.g. SPF) must be ignored (RFC 8461 §3.1).
    #[test]
    fn sts_record_with_other_txt_returns_some() {
        let rec = select_sts_record(&[
            "v=spf1 include:example.com ~all",
            "v=STSv1; id=20160831085359Z",
            "google-site-verification=abc123",
        ])
        .expect("should not error")
        .expect("should be Some");
        assert_eq!(rec.policy_id, "20160831085359Z");
    }

    // T12: record with v=STSv1 as a non-first tag → Ok(None).
    // Oracle: RFC 8461 §3.1 — "If the first tag of a TXT record is not v=STSv1,
    // the record MUST be ignored."
    #[test]
    fn sts_version_not_first_tag_returns_none() {
        let result =
            parse_sts_record("foo=bar; v=STSv1; id=20160831085359Z").expect("should not error");
        assert!(result.is_none(), "v=STSv1 as non-first tag must be ignored");
    }

    // T13: record with empty id= value → DnsTxtMissingId.
    // Oracle: RFC 8461 §3.1 — id MUST be 1–32 alphanumeric characters (1-or-more).
    #[test]
    fn parse_empty_id_returns_missing_id_error() {
        let err = parse_sts_record("v=STSv1; id=").expect_err("empty id must error");
        assert!(
            matches!(err, MtaStsError::DnsTxtMissingId),
            "unexpected error: {err}"
        );
    }
}
