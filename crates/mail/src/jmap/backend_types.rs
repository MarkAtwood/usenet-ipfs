//! Typed filter, comparator, and [`jmap_types`] trait impls for stoa's JMAP objects.
//!
//! Implements [`JmapObject`], [`GetObject`], and [`QueryObject`] for stoa's
//! three first-class JMAP types: [`Mailbox`], [`Email`], and [`Thread`].
//! These impls allow the generic handlers from `jmap-server`
//! (`handle_get`, `handle_changes`, `handle_query`, `handle_query_changes`)
//! to be used with stoa's storage backend.
//!
//! ## Property selector enums
//!
//! `JmapObject::Property` is a server-side-only type used to track which
//! properties the client requested.  Stoa's backend currently returns all
//! properties regardless of the `properties` argument (permitted by the spec —
//! RFC 8620 §5.1 says the backend MAY filter but is not required to).  The
//! enum is defined for forward compatibility.

use serde::{Deserialize, Serialize};

use jmap_types::{GetObject, JmapObject, QueryObject};

// Re-export the stoa domain types for convenience.
pub use crate::email::types::Email;
pub use crate::mailbox::types::Mailbox;

// ---------------------------------------------------------------------------
// Thread — thin typed wrapper
// ---------------------------------------------------------------------------

/// A JMAP Thread object (RFC 8621 §4.3).
///
/// `{ "id": "<msg-id>", "emailIds": ["cid1", ...] }`
///
/// Thread IDs in stoa are the raw root message-ID strings of a conversation.
/// This struct is used as the `O` type parameter to `handle_get`; the actual
/// assembly is delegated to `crate::thread::get::handle_thread_get`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Thread {
    pub id: String,
    #[serde(rename = "emailIds")]
    pub email_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Property selector enums (server-side; no serde required)
// ---------------------------------------------------------------------------

/// Property selector for [`Mailbox`] `/get`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MailboxProperty {
    Id,
    Name,
    ParentId,
    Role,
    SortOrder,
    TotalEmails,
    UnreadEmails,
    IsSubscribed,
    MyRights,
}

/// Property selector for [`Email`] `/get`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EmailProperty {
    Id,
    BlobId,
    ThreadId,
    MailboxIds,
    Keywords,
    Size,
    ReceivedAt,
    MessageId,
    InReplyTo,
    References,
    Subject,
    From,
    Preview,
    IpfsCid,
}

/// Property selector for [`Thread`] `/get`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreadProperty {
    Id,
    EmailIds,
}

// ---------------------------------------------------------------------------
// Filter and comparator types
// ---------------------------------------------------------------------------

/// Filter condition for `Mailbox/query` (RFC 8621 §2.4).
///
/// Stoa supports `isSubscribed` only; all other fields are ignored by the
/// backend (treated as "no constraint").
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MailboxFilter {
    /// When `Some(true)`, return only subscribed mailboxes.
    /// When `Some(false)`, return only unsubscribed mailboxes.
    /// When `None`, return all mailboxes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_subscribed: Option<bool>,

    /// Filter by role (e.g. `"inbox"`).  Stoa accepts but does not enforce this;
    /// the backend returns all mailboxes and lets the client filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Comparator for `Mailbox/query` sort (RFC 8621 §2.4).
///
/// Only `"name"` ascending is implemented; other sort properties are accepted
/// without error but are treated as name-ascending.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MailboxComparator {
    /// Property to sort by (e.g. `"name"`, `"sortOrder"`).
    pub property: String,
    /// `true` for ascending (default), `false` for descending.
    #[serde(default = "default_true")]
    pub is_ascending: bool,
}

/// Filter condition for `Email/query` (RFC 8621 §4.4).
///
/// Stoa implements `inMailbox` and `text`; all other fields are accepted
/// without error and treated as "no additional constraint".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmailFilter {
    /// Restrict results to a single mailbox by its JMAP id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_mailbox: Option<String>,

    /// Full-text search term.  Applied via Tantivy when a search index is
    /// configured; returns an empty result set when none is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Filter by subject (accepted; treated as no constraint in v1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Filter by from address (accepted; treated as no constraint in v1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Filter by to address (accepted; treated as no constraint in v1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// Comparator for `Email/query` sort (RFC 8621 §4.4).
///
/// Only `"receivedAt"` descending is the effective default; other sort
/// properties are accepted without error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmailComparator {
    /// Property to sort by (e.g. `"receivedAt"`, `"subject"`, `"from"`).
    pub property: String,
    /// `true` for ascending (default), `false` for descending.
    #[serde(default = "default_true")]
    pub is_ascending: bool,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// JmapObject / GetObject / QueryObject impls
// ---------------------------------------------------------------------------

impl JmapObject for Mailbox {
    const TYPE_NAME: &'static str = "Mailbox";
    type Property = MailboxProperty;
}

impl GetObject for Mailbox {}

impl QueryObject for Mailbox {
    type Filter = MailboxFilter;
    type Comparator = MailboxComparator;
}

impl JmapObject for Email {
    const TYPE_NAME: &'static str = "Email";
    type Property = EmailProperty;
}

impl GetObject for Email {}

impl QueryObject for Email {
    type Filter = EmailFilter;
    type Comparator = EmailComparator;
}

impl JmapObject for Thread {
    const TYPE_NAME: &'static str = "Thread";
    type Property = ThreadProperty;
}

impl GetObject for Thread {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: MailboxFilter with isSubscribed round-trips through JSON.
    #[test]
    fn mailbox_filter_is_subscribed_round_trips() {
        let f = MailboxFilter {
            is_subscribed: Some(true),
            role: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: MailboxFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
        // Wire format must use camelCase.
        assert!(json.contains("isSubscribed"), "got: {json}");
    }

    /// Oracle: MailboxFilter with no fields serializes to `{}`.
    #[test]
    fn mailbox_filter_empty_is_empty_object() {
        let f = MailboxFilter::default();
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "{}");
    }

    /// Oracle: EmailFilter with inMailbox and text round-trips.
    #[test]
    fn email_filter_round_trips() {
        let f = EmailFilter {
            in_mailbox: Some("mbox123".to_string()),
            text: Some("hello".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EmailFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
        assert!(
            json.contains("inMailbox"),
            "wire must use camelCase: {json}"
        );
    }

    /// Oracle: EmailComparator isAscending defaults to true when absent.
    #[test]
    fn email_comparator_is_ascending_defaults_to_true() {
        let json = r#"{"property":"receivedAt"}"#;
        let c: EmailComparator = serde_json::from_str(json).unwrap();
        assert!(c.is_ascending, "isAscending must default to true");
    }

    /// Oracle: MailboxComparator isAscending defaults to true when absent.
    #[test]
    fn mailbox_comparator_is_ascending_defaults_to_true() {
        let json = r#"{"property":"name"}"#;
        let c: MailboxComparator = serde_json::from_str(json).unwrap();
        assert!(c.is_ascending, "isAscending must default to true");
    }

    /// Oracle: Thread round-trips through JSON with correct field names.
    #[test]
    fn thread_round_trips_json() {
        let t = Thread {
            id: "<root@example.com>".to_string(),
            email_ids: vec!["cid1".to_string(), "cid2".to_string()],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("emailIds"), "wire must use camelCase: {json}");
        let back: Thread = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    /// Compile-time: Mailbox implements GetObject and QueryObject.
    #[allow(dead_code)]
    fn assert_mailbox_bounds() {
        fn check<T: GetObject + QueryObject>() {}
        check::<Mailbox>();
    }

    /// Compile-time: Email implements GetObject and QueryObject.
    #[allow(dead_code)]
    fn assert_email_bounds() {
        fn check<T: GetObject + QueryObject>() {}
        check::<Email>();
    }

    /// Compile-time: Thread implements GetObject.
    #[allow(dead_code)]
    fn assert_thread_bounds() {
        fn check<T: GetObject>() {}
        check::<Thread>();
    }
}
