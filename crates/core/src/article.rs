use crate::error::ValidationError;
use serde::{Deserialize, Serialize};

/// A validated Usenet group name (e.g. `comp.lang.rust`).
///
/// Group name format per RFC 3977: dot-separated components, each matching
/// `[a-zA-Z][a-zA-Z0-9\-+_]*`, minimum one component.
///
/// # DECISION (rbe3.6): validation at construction, not at use
///
/// `GroupName::new` validates the format once and returns a typed value.
/// This means every function that accepts `&GroupName` can trust the
/// value is well-formed without re-validating.  The alternative — accepting
/// `&str` and validating at every call site — duplicates the validation
/// logic and creates a class of bugs where call sites forget to validate.
/// `new_unchecked` is restricted to `#[cfg(any(test, fuzzing))]` so that
/// invalid names can only enter the validation pipeline in controlled test
/// environments, never in production paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct GroupName(String);

impl GroupName {
    /// Construct a validated `GroupName`. Returns `ValidationError::InvalidGroupName`
    /// if the name does not conform to RFC 3977 format.
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let name: String = s.into();
        if is_valid_group_name(&name) {
            Ok(GroupName(name))
        } else {
            Err(ValidationError::InvalidGroupName(name))
        }
    }

    /// Return the underlying group name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct a `GroupName` from a raw string without format validation.
    ///
    /// This bypasses the RFC 3977 group name format check. Use only in fuzz
    /// targets and tests where you need to inject arbitrary strings into the
    /// validation pipeline to exercise error paths.
    #[cfg(any(test, fuzzing))]
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        GroupName(s.into())
    }
}

impl std::fmt::Display for GroupName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for GroupName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<GroupName> for String {
    fn from(g: GroupName) -> Self {
        g.0
    }
}

impl<'de> serde::Deserialize<'de> for GroupName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        GroupName::new(s).map_err(serde::de::Error::custom)
    }
}

/// Returns true if `name` is a valid RFC 3977 group name.
///
/// Each dot-separated component must match `[a-zA-Z][a-zA-Z0-9\-+_]*`.
/// At least one component is required. Empty string is rejected.
fn is_valid_group_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    for component in name.split('.') {
        if component.is_empty() {
            return false;
        }
        let mut chars = component.chars();
        // First character must be a letter.
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() => {}
            _ => return false,
        }
        // Remaining characters: letter, digit, hyphen, plus, underscore.
        for c in chars {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '+' && c != '_' {
                return false;
            }
        }
    }
    true
}

/// The typed mandatory headers from RFC 5536 §3.1.
///
/// Additional (non-mandatory) headers are stored in `extra_headers` in
/// declaration order, as `(name, value)` pairs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArticleHeader {
    /// RFC 5322 `From` header value.
    pub from: String,
    /// RFC 5322 `Date` header value (as received; not parsed to a time type).
    pub date: String,
    /// RFC 5536 `Message-ID` header value, including angle brackets.
    pub message_id: String,
    /// List of destination groups.
    pub newsgroups: Vec<GroupName>,
    /// `Subject` header value.
    pub subject: String,
    /// `Path` header value (colon-separated path trace).
    pub path: String,
    /// Additional headers in declaration order.
    pub extra_headers: Vec<(String, String)>,
}

/// A complete Usenet article: header block plus body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Article {
    pub header: ArticleHeader,
    /// Raw body bytes (v1: text only).
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GroupName validation ──────────────────────────────────────────────────

    #[test]
    fn group_name_single_component() {
        assert!(GroupName::new("news").is_ok());
    }

    #[test]
    fn group_name_multi_component() {
        assert!(GroupName::new("comp.lang.rust").is_ok());
    }

    #[test]
    fn group_name_with_hyphen_plus_underscore() {
        assert!(GroupName::new("alt.fan.test_group+extra-fun").is_ok());
    }

    #[test]
    fn group_name_uppercase_accepted() {
        // RFC 3977 is case-insensitive on group names; we store as given.
        assert!(GroupName::new("Comp.Lang.Rust").is_ok());
    }

    #[test]
    fn group_name_empty_rejected() {
        assert_eq!(
            GroupName::new(""),
            Err(ValidationError::InvalidGroupName(String::new()))
        );
    }

    #[test]
    fn group_name_leading_dot_rejected() {
        assert!(GroupName::new(".comp.lang").is_err());
    }

    #[test]
    fn group_name_trailing_dot_rejected() {
        assert!(GroupName::new("comp.lang.").is_err());
    }

    #[test]
    fn group_name_double_dot_rejected() {
        assert!(GroupName::new("comp..lang").is_err());
    }

    #[test]
    fn group_name_digit_first_component_rejected() {
        assert!(GroupName::new("1comp.lang").is_err());
    }

    #[test]
    fn group_name_space_rejected() {
        assert!(GroupName::new("comp lang").is_err());
    }

    #[test]
    fn group_name_display() {
        let g = GroupName::new("comp.lang.rust").unwrap();
        assert_eq!(g.to_string(), "comp.lang.rust");
    }

    #[test]
    fn group_name_deserialize_valid() {
        let g: GroupName = serde_json::from_str("\"comp.lang.rust\"").unwrap();
        assert_eq!(g.as_str(), "comp.lang.rust");
    }

    #[test]
    fn group_name_deserialize_invalid_rejected() {
        let result: Result<GroupName, _> = serde_json::from_str("\"comp..invalid\"");
        assert!(
            result.is_err(),
            "invalid group name must be rejected by Deserialize"
        );
    }

    // ── ArticleHeader & Article construction ─────────────────────────────────

    fn make_article() -> Article {
        Article {
            header: ArticleHeader {
                from: "user@example.com".into(),
                date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
                message_id: "<abc123@example.com>".into(),
                newsgroups: vec![GroupName::new("comp.lang.rust").unwrap()],
                subject: "Hello Rust".into(),
                path: "news.example.com!user".into(),
                extra_headers: vec![("X-Mailer".into(), "test".into())],
            },
            body: b"This is the body.\r\n".to_vec(),
        }
    }

    #[test]
    fn article_construction() {
        let a = make_article();
        assert_eq!(a.header.subject, "Hello Rust");
        assert_eq!(a.header.newsgroups.len(), 1);
    }

    #[test]
    fn article_serde_roundtrip() {
        let a = make_article();
        let json = serde_json::to_string(&a).expect("serialize");
        let b: Article = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(a, b);
    }
}
