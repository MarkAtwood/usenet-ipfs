//! IMAP mailbox command handlers: SELECT, EXAMINE, LIST, STATUS.
//!
//! Newsgroups are exposed as IMAP mailboxes under a `News/` prefix using
//! `'/'` as the hierarchy delimiter (e.g., `News/comp.lang.rust`).
//!
//! Article-level data (EXISTS, UNSEEN counts) is stubbed at zero until the
//! article sync layer is wired in (r8u.11 FETCH wave).

use std::borrow::Cow;
use std::num::NonZeroU32;

use imap_next::imap_types::{
    core::{Atom, IString, QuotedChar, Tag},
    extensions::namespace::Namespace,
    flag::{Flag, FlagNameAttribute, FlagPerm},
    mailbox::{ListMailbox, Mailbox},
    response::{Code, Data, Status},
    status::{StatusDataItem, StatusDataItemName},
};
use sqlx::SqlitePool;
use tracing::debug;

// ── Public entry points ───────────────────────────────────────────────────────

/// Result from a successful SELECT or EXAMINE.
pub struct SelectResult {
    pub uidvalidity: u32,
    pub next_uid: u32,
    pub mailbox_name: String,
    pub tagged_ok: Status<'static>,
}

/// Handle `SELECT <mailbox>` or `EXAMINE <mailbox>`.
///
/// Returns a `SelectResult` containing the data needed to build untagged
/// responses, or a tagged NO status if the mailbox is unavailable.
pub async fn handle_select(
    pool: &SqlitePool,
    tag: Tag<'static>,
    mailbox: Mailbox<'static>,
    read_only: bool,
) -> Result<SelectResult, Status<'static>> {
    let name = mailbox_name(&mailbox);
    let (uidvalidity, next_uid) = get_or_create_uidvalidity(pool, &name).await.map_err(|e| {
        debug!("DB error in SELECT: {e}");
        Status::no(Some(tag.clone()), None, "Internal error").expect("static no")
    })?;

    let ok_code = if read_only {
        Code::ReadOnly
    } else {
        Code::ReadWrite
    };
    let ok_text = if read_only {
        "EXAMINE complete"
    } else {
        "SELECT complete"
    };
    let tagged_ok = Status::ok(Some(tag), Some(ok_code), ok_text).expect("static ok is valid");

    Ok(SelectResult {
        uidvalidity,
        next_uid,
        mailbox_name: name,
        tagged_ok,
    })
}

/// Build the untagged `Data` responses for SELECT/EXAMINE.
///
/// Caller enqueues these via `server.enqueue_data()`, then the `Status`
/// responses from `select_status_responses()`, then the tagged OK.
///
/// When `rev2_mode` is true (client has ENABLEd IMAP4rev2), the `* RECENT`
/// response is omitted — RFC 9051 §7.3.2 removes the RECENT concept and
/// servers MUST NOT send it to IMAP4rev2 clients.
pub fn select_untagged_data(rev2_mode: bool) -> Vec<Data<'static>> {
    // EXISTS count is stubbed until article sync is wired.
    let mut items = vec![Data::Flags(system_flags()), Data::Exists(0)];
    if !rev2_mode {
        items.push(Data::Recent(0));
    }
    items
}

/// Build the untagged `* OK [CODE] text` responses for SELECT/EXAMINE.
pub fn select_status_responses(result: &SelectResult) -> Vec<Status<'static>> {
    let uidvalidity = NonZeroU32::new(result.uidvalidity).unwrap_or(NonZeroU32::new(1).unwrap());
    let next_uid = NonZeroU32::new(result.next_uid).unwrap_or(NonZeroU32::new(1).unwrap());

    vec![
        Status::ok(None, Some(Code::UidValidity(uidvalidity)), "UIDs valid").expect("static ok"),
        Status::ok(None, Some(Code::UidNext(next_uid)), "Predicted next UID").expect("static ok"),
        Status::ok(
            None,
            Some(Code::PermanentFlags(permanent_flags())),
            "Permanent flags",
        )
        .expect("static ok"),
    ]
}

/// Convert a `ListMailbox` wildcard to a `String` for pattern matching.
pub fn list_mailbox_to_string(lm: &ListMailbox<'_>) -> String {
    match lm {
        ListMailbox::Token(t) => String::from_utf8_lossy(t.as_ref()).into_owned(),
        ListMailbox::String(IString::Literal(l)) => {
            String::from_utf8_lossy(l.as_ref()).into_owned()
        }
        ListMailbox::String(IString::Quoted(q)) => q.as_ref().to_owned(),
    }
}

/// Return the RFC 6154 / RFC 3348 LIST attributes for a mailbox name.
///
/// Special-use flags (RFC 6154): \Inbox, \Sent, \Drafts, \Trash, \Junk, \Archive.
/// Child-info flags (RFC 3348): \HasChildren, \HasNoChildren.
/// Selectability flag (RFC 3501): \Noselect.
///
/// Rules:
/// - Known special-use leaf mailboxes receive their RFC 6154 flag and \HasNoChildren.
/// - Parent containers (names ending with '/') receive \HasChildren and \Noselect.
/// - All other mailboxes receive \HasNoChildren.
pub fn mailbox_flags(name: &str) -> Vec<FlagNameAttribute<'static>> {
    /// Build a `FlagNameAttribute::Extension` from a known-valid IMAP atom string.
    ///
    /// All callers pass compile-time string literals that are valid IMAP atoms,
    /// so the expect() is safe and will never panic at runtime.
    fn ext_flag(s: &'static str) -> FlagNameAttribute<'static> {
        FlagNameAttribute::from(Atom::try_from(s).expect("static atom string is always valid"))
    }

    let has_no_children = ext_flag("HasNoChildren");
    let has_children = ext_flag("HasChildren");

    // Parent containers: name ends with '/' (e.g. "News/", "List/").
    // These hold child mailboxes but are not themselves selectable.
    if name.ends_with('/') {
        return vec![has_children, FlagNameAttribute::Noselect];
    }

    // RFC 6154 special-use leaf mailboxes matched by display name.
    // \Inbox is from RFC 3501 §7.2.2 (well-known, widely implemented).
    // \Sent, \Drafts, \Trash, \Junk, \Archive are from RFC 6154 §2.
    match name {
        "INBOX" => vec![ext_flag("Inbox"), has_no_children],
        "Sent" => vec![ext_flag("Sent"), has_no_children],
        "Drafts" => vec![ext_flag("Drafts"), has_no_children],
        "Trash" => vec![ext_flag("Trash"), has_no_children],
        "Junk" => vec![ext_flag("Junk"), has_no_children],
        "Archive" => vec![ext_flag("Archive"), has_no_children],
        _ => vec![has_no_children],
    }
}

/// Handle `LIST <reference> <mailbox-wildcard>`.
///
/// Returns one `Data::List` item per matching mailbox.
/// Newsgroups are exposed under the `News/` prefix.
/// Wildcard rules: `*` matches any sequence (including `/`);
/// `%` matches any sequence that does not contain `/`.
pub async fn handle_list(
    pool: &SqlitePool,
    reference: &Mailbox<'static>,
    wildcard: &str,
) -> Vec<Data<'static>> {
    let prefix = mailbox_name(reference);
    let pattern = if prefix.is_empty() {
        wildcard.to_owned()
    } else {
        format!("{prefix}/{wildcard}")
    };

    // Optimise: if the IMAP pattern has a literal DB prefix (e.g. "News/comp."
    // → DB prefix "comp."), push a LIKE filter to the query so we only
    // fetch matching rows.  The Rust-level glob_match is still applied
    // afterwards to enforce exact wildcard semantics.
    let db_prefix: Option<String> = {
        let news_part = pattern.strip_prefix("News/").unwrap_or("");
        let end = news_part.find(['*', '%']).unwrap_or(news_part.len());
        if end > 0 {
            let literal = &news_part[..end];
            // Escape LIKE metacharacters so '_' and '%' in group names are
            // matched literally; '\\' is the ESCAPE char in the query below.
            let escaped = literal
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            Some(format!("{escaped}%"))
        } else {
            None
        }
    };

    let rows: Vec<(String,)> = match db_prefix {
        Some(like_pat) => {
            match sqlx::query_as(
                "SELECT mailbox FROM imap_uid_validity \
                 WHERE mailbox LIKE ? ESCAPE '\\' ORDER BY mailbox",
            )
            .bind(like_pat)
            .fetch_all(pool)
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    debug!("DB error in LIST: {e}");
                    return vec![];
                }
            }
        }
        None => {
            match sqlx::query_as("SELECT mailbox FROM imap_uid_validity ORDER BY mailbox")
                .fetch_all(pool)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    debug!("DB error in LIST: {e}");
                    return vec![];
                }
            }
        }
    };

    rows.into_iter()
        .filter_map(|(db_name,)| {
            // Newsgroups stored in the DB without prefix; expose them under News/.
            let imap_name = format!("News/{db_name}");
            if !glob_match(&pattern, &imap_name) {
                return None;
            }
            let items = mailbox_flags(&imap_name);
            let mailbox = Mailbox::try_from(imap_name).ok()?;
            Some(Data::List {
                items,
                delimiter: Some(QuotedChar::unvalidated('/')),
                mailbox,
            })
        })
        .collect()
}

/// Handle `NAMESPACE` (RFC 2342).
///
/// Returns one personal namespace with prefix `""` and delimiter `"/"`.
/// Other-users and shared namespace lists are empty (NIL).
pub fn handle_namespace() -> Data<'static> {
    let personal = vec![Namespace::new(
        IString::try_from("").expect("empty string is a valid IString"),
        Some(QuotedChar::try_from('/').expect("slash is a valid QuotedChar")),
    )];
    Data::namespace(personal, vec![], vec![])
        .expect("valid namespace args produce valid Data::Namespace")
}

/// Handle `STATUS <mailbox> (<items>)`.
///
/// Returns `Some(Data::Status { ... })` or `None` if the mailbox is not
/// found in `imap_uid_validity`.
pub async fn handle_status(
    pool: &SqlitePool,
    mailbox: Mailbox<'static>,
    item_names: &[StatusDataItemName],
) -> Option<Data<'static>> {
    let name = mailbox_name(&mailbox);
    let row: Option<(i64, i64)> = match sqlx::query_as(
        "SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?",
    )
    .bind(&name)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(mailbox = %name, "handle_status: database error: {e}");
            return None;
        }
    };

    let (uidvalidity, next_uid) = match row {
        Some((v, n)) => (
            clamp_u32(v, "uidvalidity", &name),
            clamp_u32(n, "next_uid", &name),
        ),
        None => return None,
    };

    let mut items: Vec<StatusDataItem> = Vec::new();
    for item_name in item_names {
        match item_name {
            StatusDataItemName::Messages => items.push(StatusDataItem::Messages(0)),
            StatusDataItemName::Recent => items.push(StatusDataItem::Recent(0)),
            StatusDataItemName::Unseen => items.push(StatusDataItem::Unseen(0)),
            StatusDataItemName::Deleted => items.push(StatusDataItem::Deleted(0)),
            StatusDataItemName::DeletedStorage => items.push(StatusDataItem::DeletedStorage(0)),
            StatusDataItemName::UidNext => {
                let uid = NonZeroU32::new(next_uid).unwrap_or(NonZeroU32::new(1).unwrap());
                items.push(StatusDataItem::UidNext(uid));
            }
            StatusDataItemName::UidValidity => {
                let uv = NonZeroU32::new(uidvalidity).unwrap_or(NonZeroU32::new(1).unwrap());
                items.push(StatusDataItem::UidValidity(uv));
            }
        }
    }

    Some(Data::Status {
        mailbox,
        items: Cow::Owned(items),
    })
}

// ── Database helpers ──────────────────────────────────────────────────────────

/// Get or create the UIDVALIDITY and UIDNEXT for a mailbox.
///
/// On first access, generates UIDVALIDITY from the current Unix timestamp
/// Cast an `i64` DB value to `u32`, clamping to 1 and logging on overflow.
///
/// UIDVALIDITY and next_uid are stored as `i64` by SQLite but must fit in
/// `u32` for IMAP.  Overflow indicates DB corruption; clamping to 1 keeps
/// the server operational while the warning surfaces the issue to operators.
fn clamp_u32(v: i64, field: &str, mailbox: &str) -> u32 {
    u32::try_from(v).unwrap_or_else(|_| {
        tracing::warn!(
            mailbox,
            field,
            value = v,
            "corrupt {field} exceeds u32, clamping to 1"
        );
        1
    })
}

/// (seconds).  UIDVALIDITY must never decrease for a given mailbox, and
/// persisting it in the DB satisfies that invariant across restarts.
pub async fn get_or_create_uidvalidity(
    pool: &SqlitePool,
    mailbox: &str,
) -> Result<(u32, u32), sqlx::Error> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?")
            .bind(mailbox)
            .fetch_optional(pool)
            .await?;

    if let Some((v, n)) = row {
        return Ok((
            clamp_u32(v, "uidvalidity", mailbox),
            clamp_u32(n, "next_uid", mailbox),
        ));
    }

    // Generate UIDVALIDITY from current Unix time (seconds).
    let uidvalidity = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(u64::from(u32::MAX)) as u32;
    let uidvalidity = uidvalidity.max(1);

    sqlx::query(
        "INSERT OR IGNORE INTO imap_uid_validity (mailbox, uidvalidity, next_uid) \
         VALUES (?, ?, 1)",
    )
    .bind(mailbox)
    .bind(uidvalidity as i64)
    .execute(pool)
    .await?;

    // Re-fetch in case of a concurrent INSERT OR IGNORE.
    let (v, n): (i64, i64) =
        sqlx::query_as("SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?")
            .bind(mailbox)
            .fetch_one(pool)
            .await?;

    Ok((
        clamp_u32(v, "uidvalidity", mailbox),
        clamp_u32(n, "next_uid", mailbox),
    ))
}

// ── Flag helpers ──────────────────────────────────────────────────────────────

fn system_flags() -> Vec<Flag<'static>> {
    vec![
        Flag::Answered,
        Flag::Flagged,
        Flag::Deleted,
        Flag::Seen,
        Flag::Draft,
    ]
}

fn permanent_flags() -> Vec<FlagPerm<'static>> {
    vec![
        FlagPerm::Flag(Flag::Answered),
        FlagPerm::Flag(Flag::Flagged),
        FlagPerm::Flag(Flag::Deleted),
        FlagPerm::Flag(Flag::Seen),
        FlagPerm::Flag(Flag::Draft),
        FlagPerm::Asterisk,
    ]
}

// ── Mailbox name helpers ──────────────────────────────────────────────────────

/// Convert an imap-types `Mailbox` to a plain `String` for use as a DB key.
pub fn mailbox_name(mailbox: &Mailbox<'_>) -> String {
    match mailbox {
        Mailbox::Inbox => "INBOX".to_owned(),
        Mailbox::Other(other) => String::from_utf8_lossy(other.inner().as_ref()).into_owned(),
    }
}

// ── Wildcard matching ─────────────────────────────────────────────────────────

/// Maximum combined (pattern + name) length accepted by the glob matcher.
///
/// Patterns longer than this are rejected (return false) to bound worst-case
/// O(m×n) work.  1 KiB is generous for any real IMAP LIST wildcard.
const MAX_GLOB_BYTES: usize = 1024;

/// Match an IMAP LIST wildcard pattern against a mailbox name.
///
/// `*` matches any sequence of characters including hierarchy separators (`/`).
/// `%` matches any sequence of characters NOT including `/`.
///
/// Returns `false` if `pattern.len() + name.len() > MAX_GLOB_BYTES` to
/// prevent time-DoS from pathologically long client-supplied patterns.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern.len().saturating_add(name.len()) > MAX_GLOB_BYTES {
        return false;
    }
    glob_bytes(pattern.as_bytes(), name.as_bytes())
}

/// Iterative O(m*n) DP glob matching — prevents exponential blowup from
/// adversarial patterns like `%%%%%...` on long strings.
///
/// `dp[i][j]` = true if `pat[..i]` matches `s[..j]`.
///
/// # DECISION (rbe3.82): iterative DP glob matcher prevents IMAP LIST ReDoS
///
/// Recursive backtracking glob matchers have worst-case O(2^n) time on
/// adversarial patterns (e.g. `%*%*%*...` against a long non-matching string).
/// IMAP LIST patterns come from the authenticated client but the input is still
/// attacker-controlled; a single LIST command with a malicious pattern could
/// block the session goroutine for seconds.  The DP approach fills an
/// (m+1)×(n+1) boolean table in O(m*n) time regardless of pattern structure.
/// The combined-length cap in `glob_match` (MAX_GLOB_BYTES) further bounds
/// worst-case work.  Do NOT replace this with a recursive implementation.  Do
/// NOT remove the MAX_GLOB_BYTES cap in `glob_match`.
fn glob_bytes(pat: &[u8], s: &[u8]) -> bool {
    let m = pat.len();
    let n = s.len();
    // Use two rows to keep space O(n).
    let mut prev = vec![false; n + 1];
    let mut curr = vec![false; n + 1];
    prev[0] = true;

    for i in 1..=m {
        // A wildcard can match empty — carry forward.
        curr[0] = if pat[i - 1] == b'*' || pat[i - 1] == b'%' {
            prev[0]
        } else {
            false
        };

        for j in 1..=n {
            curr[j] = match pat[i - 1] {
                b'*' => prev[j] || curr[j - 1],
                b'%' => {
                    // % matches zero characters: prev[j]
                    // % matches one non-'/' character: curr[j-1] (if s[j-1] != '/')
                    prev[j] || (s[j - 1] != b'/' && curr[j - 1])
                }
                p => prev[j - 1] && p == s[j - 1],
            };
        }

        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_match("*", "News/comp.lang.rust"));
        assert!(glob_match("*", "News/alt.test"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_percent_does_not_cross_hierarchy() {
        assert!(glob_match("News/%", "News/comp.lang.rust"));
        assert!(!glob_match("%", "News/comp.lang.rust"));
    }

    #[test]
    fn glob_star_crosses_hierarchy() {
        assert!(glob_match("News/*", "News/comp.lang.rust"));
        assert!(glob_match("News/*", "News/comp.lang"));
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("News/comp.lang.rust", "News/comp.lang.rust"));
        assert!(!glob_match("News/comp.lang.rust", "News/comp.lang.c"));
    }

    #[test]
    fn glob_empty_pattern_matches_empty_string() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "anything"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("News/*", "News/comp.lang.rust"));
        assert!(!glob_match("Other/*", "News/comp.lang.rust"));
    }

    #[test]
    fn glob_adversarial_pattern_completes_quickly() {
        // A recursive implementation would take O(2^n) for this input.
        // The iterative DP must complete in O(m*n) time.
        let pat = "%".repeat(50);
        let name = "a".repeat(50);
        let start = std::time::Instant::now();
        let _ = glob_match(&pat, &name);
        assert!(
            start.elapsed().as_millis() < 100,
            "glob_match must complete in under 100ms for adversarial input"
        );
    }

    #[test]
    fn glob_oversized_pattern_returns_false() {
        // A pattern + name exceeding MAX_GLOB_BYTES must be rejected to bound
        // worst-case O(m×n) work and prevent time-DoS.
        let pat = "*".repeat(MAX_GLOB_BYTES + 1);
        assert!(
            !glob_match(&pat, "INBOX"),
            "oversized pattern must return false"
        );
    }

    #[test]
    fn glob_percent_with_slash_in_name_blocked() {
        // % must not match across hierarchy separators.
        assert!(!glob_match("%", "News/comp.lang.rust"));
        assert!(glob_match("News/%", "News/comp.lang.rust"));
    }

    #[test]
    fn mailbox_name_inbox() {
        assert_eq!(mailbox_name(&Mailbox::Inbox), "INBOX");
    }

    #[test]
    fn system_flags_contains_standard_set() {
        let flags = system_flags();
        assert!(flags.contains(&Flag::Seen));
        assert!(flags.contains(&Flag::Deleted));
        assert!(flags.contains(&Flag::Flagged));
        assert!(flags.contains(&Flag::Answered));
        assert!(flags.contains(&Flag::Draft));
    }

    // ── Async DB tests ────────────────────────────────────────────────────────

    async fn make_pool() -> sqlx::SqlitePool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE imap_uid_validity (
                mailbox     TEXT    NOT NULL PRIMARY KEY,
                uidvalidity INTEGER NOT NULL,
                next_uid    INTEGER NOT NULL DEFAULT 1
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn uidvalidity_is_stable_across_calls() {
        let pool = make_pool().await;
        let (v1, n1) = get_or_create_uidvalidity(&pool, "comp.lang.rust")
            .await
            .unwrap();
        let (v2, n2) = get_or_create_uidvalidity(&pool, "comp.lang.rust")
            .await
            .unwrap();
        assert_eq!(v1, v2, "UIDVALIDITY must not change on re-access");
        assert_eq!(n1, n2);
        assert!(v1 >= 1);
    }

    #[tokio::test]
    async fn uidvalidity_is_nonzero() {
        let pool = make_pool().await;
        let (v, n) = get_or_create_uidvalidity(&pool, "alt.test").await.unwrap();
        assert!(v >= 1, "UIDVALIDITY must be at least 1");
        assert_eq!(n, 1, "initial next_uid is 1");
    }

    #[tokio::test]
    async fn handle_status_returns_none_for_unknown_mailbox() {
        let pool = make_pool().await;
        let mailbox = Mailbox::try_from("nonexistent.group".to_owned()).unwrap();
        let result = handle_status(&pool, mailbox, &[StatusDataItemName::Messages]).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn handle_status_returns_uidvalidity_for_known_mailbox() {
        let pool = make_pool().await;
        let (expected_uv, _) = get_or_create_uidvalidity(&pool, "comp.lang.rust")
            .await
            .unwrap();
        let mailbox = Mailbox::try_from("comp.lang.rust".to_owned()).unwrap();
        let data = handle_status(&pool, mailbox, &[StatusDataItemName::UidValidity]).await;
        assert!(
            data.is_some(),
            "STATUS should return data for known mailbox"
        );
        if let Some(Data::Status { items, .. }) = data {
            let uv = items.iter().find_map(|item| {
                if let StatusDataItem::UidValidity(v) = item {
                    Some(v.get())
                } else {
                    None
                }
            });
            assert_eq!(
                uv,
                Some(expected_uv.max(1)),
                "UIDVALIDITY must match persisted value"
            );
        } else {
            panic!("expected Data::Status");
        }
    }

    #[tokio::test]
    async fn handle_list_queries_db_without_error() {
        // Verifies the DB query path executes and returns results consistent with
        // glob_match logic (which is tested exhaustively in the sync tests above).
        let pool = make_pool().await;
        get_or_create_uidvalidity(&pool, "comp.lang.rust")
            .await
            .unwrap();
        get_or_create_uidvalidity(&pool, "comp.lang.c")
            .await
            .unwrap();
        get_or_create_uidvalidity(&pool, "alt.test").await.unwrap();

        // With Mailbox::Inbox as reference the prefix is "INBOX", so the effective
        // pattern is "INBOX/*" — none of our seeded newsgroup mailboxes match.
        let data = handle_list(&pool, &Mailbox::Inbox, "*").await;
        assert!(
            data.is_empty(),
            "INBOX/* should not match any News/* entries"
        );
    }

    // ── RFC 6154 special-use flag tests ───────────────────────────────────────
    //
    // Oracle: RFC 6154 §2 and RFC 3348 §5.
    //
    // RFC 6154 §2 defines: \Archive, \Drafts, \Flagged, \Junk, \Sent, \Trash.
    // \Inbox is from RFC 3501 §7.2.2.
    // \HasChildren and \HasNoChildren are from RFC 3348 §5.
    // \Noselect is from RFC 3501 §7.2.2.
    //
    // Tests verify mailbox_flags() and the LIST response carries the flags.

    /// RFC 6154: INBOX must have \Inbox flag; RFC 3348: leaf mailbox gets \HasNoChildren.
    #[test]
    fn mailbox_flags_inbox_has_inbox_and_has_no_children() {
        let flags = mailbox_flags("INBOX");
        let flag_strs: Vec<String> = flags.iter().map(|f| format!("{f}")).collect();
        assert!(
            flag_strs.contains(&"\\Inbox".to_owned()),
            "INBOX must have \\Inbox flag (RFC 3501 §7.2.2); got: {flag_strs:?}"
        );
        assert!(
            flag_strs.contains(&"\\HasNoChildren".to_owned()),
            "INBOX must have \\HasNoChildren flag (RFC 3348 §5); got: {flag_strs:?}"
        );
    }

    /// RFC 6154: Sent must have \Sent flag; leaf mailbox gets \HasNoChildren.
    #[test]
    fn mailbox_flags_sent_has_sent_flag() {
        let flags = mailbox_flags("Sent");
        let flag_strs: Vec<String> = flags.iter().map(|f| format!("{f}")).collect();
        assert!(
            flag_strs.contains(&"\\Sent".to_owned()),
            "Sent must have \\Sent flag (RFC 6154 §2); got: {flag_strs:?}"
        );
        assert!(
            flag_strs.contains(&"\\HasNoChildren".to_owned()),
            "Sent must have \\HasNoChildren (RFC 3348 §5); got: {flag_strs:?}"
        );
    }

    /// RFC 6154: Drafts, Trash, Junk, Archive each get their named flag + \HasNoChildren.
    #[test]
    fn mailbox_flags_other_special_folders() {
        for (name, expected_flag) in [
            ("Drafts", "\\Drafts"),
            ("Trash", "\\Trash"),
            ("Junk", "\\Junk"),
            ("Archive", "\\Archive"),
        ] {
            let flags = mailbox_flags(name);
            let flag_strs: Vec<String> = flags.iter().map(|f| format!("{f}")).collect();
            assert!(
                flag_strs.contains(&expected_flag.to_owned()),
                "{name} must have {expected_flag} flag (RFC 6154 §2); got: {flag_strs:?}"
            );
            assert!(
                flag_strs.contains(&"\\HasNoChildren".to_owned()),
                "{name} must have \\HasNoChildren (RFC 3348 §5); got: {flag_strs:?}"
            );
        }
    }

    /// Parent containers (names ending with '/') get \HasChildren and \Noselect.
    #[test]
    fn mailbox_flags_parent_container_has_children_and_noselect() {
        for name in ["News/", "List/"] {
            let flags = mailbox_flags(name);
            let flag_strs: Vec<String> = flags.iter().map(|f| format!("{f}")).collect();
            assert!(
                flag_strs.contains(&"\\HasChildren".to_owned()),
                "{name} must have \\HasChildren; got: {flag_strs:?}"
            );
            assert!(
                flags.contains(&FlagNameAttribute::Noselect),
                "{name} must have \\Noselect; got: {flag_strs:?}"
            );
        }
    }

    /// Unknown mailboxes get only \HasNoChildren (no special-use flag).
    #[test]
    fn mailbox_flags_unknown_mailbox_gets_has_no_children_only() {
        let flags = mailbox_flags("comp.lang.rust");
        let flag_strs: Vec<String> = flags.iter().map(|f| format!("{f}")).collect();
        assert_eq!(
            flag_strs,
            vec!["\\HasNoChildren"],
            "unknown mailbox must have only \\HasNoChildren; got: {flag_strs:?}"
        );
    }

    /// Newsgroups are exposed as News/<group> entries with '/' delimiter.
    /// Each entry must carry \HasNoChildren from mailbox_flags.
    #[tokio::test]
    async fn handle_list_newsgroups_under_news_prefix() {
        let pool = make_pool().await;
        get_or_create_uidvalidity(&pool, "comp.lang.rust")
            .await
            .unwrap();
        get_or_create_uidvalidity(&pool, "alt.test").await.unwrap();

        let reference = Mailbox::try_from("".to_owned()).unwrap_or(Mailbox::Inbox);
        let data = handle_list(&pool, &reference, "*").await;
        assert_eq!(data.len(), 2, "should return both newsgroups");

        for item in &data {
            if let Data::List {
                delimiter,
                mailbox,
                items,
            } = item
            {
                assert_eq!(
                    *delimiter,
                    Some(QuotedChar::unvalidated('/')),
                    "delimiter must be '/'"
                );
                let name = match mailbox {
                    Mailbox::Inbox => "INBOX".to_owned(),
                    Mailbox::Other(other) => {
                        String::from_utf8_lossy(other.inner().as_ref()).into_owned()
                    }
                };
                assert!(
                    name.starts_with("News/"),
                    "mailbox name must start with 'News/'; got: {name}"
                );
                let flag_strs: Vec<String> = items.iter().map(|f| format!("{f}")).collect();
                assert!(
                    flag_strs.contains(&"\\HasNoChildren".to_owned()),
                    "News/* entries must carry \\HasNoChildren; got: {flag_strs:?}"
                );
            } else {
                panic!("expected Data::List");
            }
        }
    }

    /// RFC 3501 §6.3.8: reference name is a literal prefix, not a pattern.
    /// Underscore is a LIKE metacharacter; it must be escaped so LIST "a_b" "*"
    /// does not match "axb" or "a1b" in the DB.
    #[tokio::test]
    async fn handle_list_underscore_in_reference_matches_literally() {
        let pool = make_pool().await;
        // Insert two groups: one where _ is literal, one where it would match
        // if '_' were treated as LIKE wildcard.
        get_or_create_uidvalidity(&pool, "comp_lang.rust")
            .await
            .unwrap();
        get_or_create_uidvalidity(&pool, "compXlang.rust")
            .await
            .unwrap();

        // Reference "News/comp_lang" should only match "comp_lang.*", NOT "compXlang.*".
        let reference = Mailbox::try_from("News/comp_lang".to_owned()).unwrap_or(Mailbox::Inbox);
        let data = handle_list(&pool, &reference, "*").await;
        let names: Vec<String> = data
            .iter()
            .filter_map(|d| {
                if let Data::List { mailbox, .. } = d {
                    match mailbox {
                        Mailbox::Other(other) => {
                            Some(String::from_utf8_lossy(other.inner().as_ref()).into_owned())
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect();
        assert!(
            names.iter().all(|n| n.starts_with("News/comp_lang")),
            "LIST with '_' reference must not match 'compXlang': {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("compXlang")),
            "underscore must be escaped: compXlang must not appear; got: {names:?}"
        );
    }

    // ── NAMESPACE (RFC 2342) tests ────────────────────────────────────────────
    //
    // Oracle: RFC 2342 §5.
    //
    // This server has exactly one personal namespace: prefix="" (empty string),
    // delimiter='/' (the IMAP hierarchy separator for the News/ prefix).  There
    // are no "Other Users" namespaces and no "Shared" namespaces.
    //
    // RFC 2342 §5 wire format:
    //   * NAMESPACE (("" "/")) NIL NIL\r\n
    //   personal ^^^^^^^^^^^^^ — one entry: empty prefix, slash delimiter
    //   other    ^^^ — NIL (no other-users namespaces)
    //   shared       ^^^ — NIL (no shared namespaces)
    //
    // Tests 1–3 call `handle_namespace()`, added by drrd.10 to mailbox.rs.
    // Signature expected:  pub fn handle_namespace() -> Data<'static>
    // Until drrd.10 lands, these tests will not compile — that is expected.
    //
    // Test 4 (wire encoding) builds the value from scratch and compiles before
    // drrd.10 is complete.

    /// RFC 2342 §5: the personal namespace must have an empty string prefix.
    #[test]
    fn handle_namespace_personal_prefix_is_empty() {
        use imap_next::imap_types::{
            core::IString, extensions::namespace::Namespace, response::Data,
        };

        let data: Data<'static> = handle_namespace();
        let Data::Namespace { personal, .. } = data else {
            panic!("handle_namespace must return Data::Namespace");
        };
        assert_eq!(
            personal.len(),
            1,
            "exactly one personal namespace entry required (RFC 2342 §5)"
        );
        let ns: &Namespace<'_> = &personal[0];
        // RFC 2342 §5: "the Personal Namespace prefix is the empty string".
        let prefix_bytes: &[u8] = match &ns.prefix {
            IString::Quoted(q) => q.as_ref().as_bytes(),
            IString::Literal(l) => l.as_ref(),
        };
        assert_eq!(
            prefix_bytes, b"",
            "personal namespace prefix must be the empty string (RFC 2342 §5)"
        );
    }

    /// Delimiter must be '/' — newsgroups live under `News/` prefix.
    #[test]
    fn handle_namespace_personal_delimiter_is_slash() {
        use imap_next::imap_types::{core::QuotedChar, response::Data};

        let data: Data<'static> = handle_namespace();
        let Data::Namespace { personal, .. } = data else {
            panic!("handle_namespace must return Data::Namespace");
        };
        let ns = &personal[0];
        assert_eq!(
            ns.delimiter,
            Some(QuotedChar::unvalidated('/')),
            "personal namespace delimiter must be '/'"
        );
    }

    /// RFC 2342 §5: Other Users and Shared namespace lists must be empty (NIL
    /// on the wire).
    #[test]
    fn handle_namespace_other_and_shared_are_empty() {
        use imap_next::imap_types::response::Data;

        let data: Data<'static> = handle_namespace();
        let Data::Namespace { other, shared, .. } = data else {
            panic!("handle_namespace must return Data::Namespace");
        };
        assert!(
            other.is_empty(),
            "Other Users namespace list must be NIL/empty (RFC 2342 §5)"
        );
        assert!(
            shared.is_empty(),
            "Shared namespace list must be NIL/empty (RFC 2342 §5)"
        );
    }

    /// Wire encoding: a `Data::Namespace` with one personal namespace
    /// (prefix="", delimiter='/') and no other/shared namespaces must
    /// encode to bytes containing "NAMESPACE" and two "NIL" tokens for the
    /// empty other and shared namespace lists.
    ///
    /// Expected wire line:
    ///   * NAMESPACE (("" "/")) NIL NIL\r\n
    ///
    /// This test builds the value from scratch and does NOT call
    /// `handle_namespace()`, so it compiles before drrd.10 lands.
    #[test]
    fn handle_namespace_wire_encoding() {
        use imap_codec::{encode::Encoder, ResponseCodec};
        use imap_next::imap_types::{
            core::{IString, QuotedChar},
            extensions::namespace::Namespace,
            response::{Data, Response},
        };

        // Construct the exact Data value that handle_namespace() must return.
        // personal prefix="" delimiter='/' other=NIL shared=NIL.
        let personal_ns = Namespace::new(
            IString::try_from("").expect("empty string is a valid IString"),
            Some(QuotedChar::unvalidated('/')),
        );
        let data: Data<'static> = Data::namespace(
            vec![personal_ns],
            vec![], // other — encodes as NIL
            vec![], // shared — encodes as NIL
        )
        .expect("valid namespace arguments must not produce an error");

        let response = Response::Data(data);
        let bytes: Vec<u8> = ResponseCodec::default().encode(&response).dump();
        let wire = String::from_utf8_lossy(&bytes);

        // Must contain the NAMESPACE keyword (RFC 2342 §5).
        assert!(
            bytes.windows(b"NAMESPACE".len()).any(|w| w == b"NAMESPACE"),
            "wire encoding must contain 'NAMESPACE'; got: {wire:?}"
        );
        // Two NIL tokens for the empty other and shared namespace lists.
        // Oracle: imap-codec namespace encoder — empty Vec → b"NIL".
        let nil_count = bytes.windows(b"NIL".len()).filter(|w| *w == b"NIL").count();
        assert_eq!(
            nil_count, 2,
            "exactly two NIL tokens required (other + shared); got: {wire:?}"
        );
        // Personal namespace prefix must be the empty quoted string.
        assert!(
            bytes.windows(2).any(|w| w == b"\"\""),
            "personal namespace prefix must encode as empty quoted string \"\\\"\\\"\"; got: {wire:?}"
        );
        // Delimiter must be '/' (slash).
        assert!(
            bytes.windows(3).any(|w| w == b"\"/\""),
            "delimiter must encode as \"/\"; got: {wire:?}"
        );
        // Response line must end with CRLF (RFC 2342 §5 grammar).
        assert!(
            bytes.ends_with(b"\r\n"),
            "NAMESPACE response must end with CRLF; got: {wire:?}"
        );
    }
}
