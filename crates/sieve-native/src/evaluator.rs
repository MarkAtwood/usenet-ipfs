// SPDX-License-Identifier: MIT

//! Sieve script evaluator (RFC 5228 + RFC 5229 variables extension).
//!
//! ## Single-user global Sieve architecture
//!
//! Global Sieve script (`_global` key) applies to all users on this server
//! instance. Per-user scripts are stored under the user's key. The evaluator
//! is stateless; scripts are loaded from the store on each evaluation.
//!
//! ## RFC 5228 — base Sieve
//!
//! Defines commands (`if`, `fileinto`, `reject`, `discard`, `keep`, `stop`,
//! `require`) and tests (`header`, `address`, `envelope`, `exists`, `size`,
//! `allof`, `anyof`, `not`, `true`, `false`).  Key semantic rules:
//!
//! - **Fail-safe** (§2.9): unknown commands, tests, and comparators produce a
//!   no-op (`Continue`) or `false` instead of an error.  This lets scripts
//!   that use unsupported extensions degrade gracefully rather than rejecting
//!   or losing mail because of an unrecognised keyword.
//! - **Default keep** (§2.10.2): if a script completes with no explicit
//!   disposition action, the message is implicitly kept.
//! - **`require`** (§2.10.5): must appear before any command that uses the
//!   declared extension.  Unknown extensions are rejected at compile time
//!   (see `lib.rs::compile`).
//!
//! ## RFC 5229 — variables extension
//!
//! Adds the `set` command and `${varname}` substitution in string arguments.
//! Substitution is only active when the script declares `require ["variables"]`.
//! Variable names are case-insensitive; all names are normalised to lowercase.
//! An undeclared (never `set`) variable expands to the empty string.

use crate::form::{Form, Script, Stmt};
use crate::message;
use crate::SieveAction;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::HashMap;
use tracing::warn;

/// Maximum compiled regexes kept per thread. Prevents unbounded growth in
/// long-running SMTP processes that receive many distinct Sieve :regex patterns.
const REGEX_CACHE_CAP: usize = 256;

thread_local! {
    static REGEX_CACHE: RefCell<lru::LruCache<(String, bool), fancy_regex::Regex>> =
        RefCell::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(REGEX_CACHE_CAP).expect("cache cap > 0"),
        ));
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/// Maximum nesting depth enforced at eval time.
///
/// Must match `MAX_VALIDATE_DEPTH` in `lib.rs`.  Kept here as an independent
/// constant so the evaluator does not depend on the compile-time validator;
/// the two values must be kept in sync.
const MAX_EVAL_DEPTH: usize = 32;

pub struct Ctx<'a> {
    headers: Vec<(String, String)>,
    message_size: usize,
    envelope_from: &'a str,
    envelope_to: &'a str,
    variables: HashMap<String, String>,
    /// Whether `require ["variables"]` was declared (RFC 5229 §3).
    ///
    /// `${varname}` substitution is only active when this is `true`.  The flag
    /// is determined once at the start of `eval_script` by scanning the script
    /// for a `require` statement that includes `"variables"`.  Variable names
    /// are case-insensitive; storage uses lowercased keys throughout (see
    /// `expand_vars`).
    variables_enabled: bool,
    /// The last explicit disposition action taken before a `stop` (RFC 5228 §4.1).
    ///
    /// RFC 5228 §4.1: `stop` halts script execution; any actions already taken
    /// remain in effect.  When `stop` is encountered, `eval_script` returns
    /// `last_action` if one was recorded, or implicit Keep otherwise.
    last_action: Option<SieveAction>,
    /// Current `if`/`elsif` nesting depth.
    ///
    /// Incremented on entry to `eval_if`; decremented on exit.  Capped at
    /// `MAX_EVAL_DEPTH` as a defensive guard against scripts that bypassed
    /// the compile-time depth check.
    nesting_depth: usize,
}

// ---------------------------------------------------------------------------
// Internal result type
// ---------------------------------------------------------------------------

enum StmtResult {
    Continue,
    Keep,
    Discard,
    FileInto(String),
    Reject(String),
    Stop,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate a compiled Sieve [`Script`] against a raw RFC 5322 message.
///
/// Returns the list of actions the script requests.  If the script produces
/// no explicit disposition, `[Keep]` is appended per RFC 5228 §2.10.2.
pub fn eval_script(
    script: &Script,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
) -> Vec<SieveAction> {
    let headers = message::extract_headers(raw_message);

    // Detect whether `require ["variables"]` appears in the script (RFC 5229 §3).
    // Variable substitution is only active when the script declares this extension.
    let variables_enabled = script.iter().any(|stmt| {
        if let [Form::Word(w), rest @ ..] = stmt.as_slice() {
            if w == "require" {
                return rest.iter().any(|f| match f {
                    Form::Str(s) => s == "variables",
                    Form::StringList(v) => v.iter().any(|s| s == "variables"),
                    _ => false,
                });
            }
        }
        false
    });

    let mut ctx = Ctx {
        headers,
        message_size: raw_message.len(),
        envelope_from,
        envelope_to,
        variables: HashMap::new(),
        variables_enabled,
        last_action: None,
        nesting_depth: 0,
    };

    let mut actions: Vec<SieveAction> = Vec::new();

    match eval_stmt_list(script, &mut ctx) {
        None | Some(StmtResult::Continue) => {
            actions.push(SieveAction::Keep);
        }
        // RFC 5228 §4.1: `stop` halts execution; actions already taken remain
        // in effect.  Return the last recorded explicit action, or implicit
        // Keep if no explicit action preceded the `stop`.
        Some(StmtResult::Stop) => {
            actions.push(ctx.last_action.take().unwrap_or(SieveAction::Keep));
        }
        Some(StmtResult::Keep) => actions.push(SieveAction::Keep),
        Some(StmtResult::Discard) => actions.push(SieveAction::Discard),
        Some(StmtResult::FileInto(folder)) => actions.push(SieveAction::FileInto(folder)),
        Some(StmtResult::Reject(reason)) => actions.push(SieveAction::Reject(reason)),
    }

    actions
}

// ---------------------------------------------------------------------------
// Statement list / statement dispatch
// ---------------------------------------------------------------------------

fn eval_stmt_list(stmts: &[Stmt], ctx: &mut Ctx<'_>) -> Option<StmtResult> {
    for stmt in stmts {
        match eval_stmt(stmt, ctx) {
            StmtResult::Continue => {}
            other => return Some(other),
        }
    }
    None
}

fn eval_stmt(stmt: &Stmt, ctx: &mut Ctx<'_>) -> StmtResult {
    match stmt.as_slice() {
        // require — validated at compile time; ignore at eval time.
        [Form::Word(w), ..] if w == "require" => StmtResult::Continue,

        // if / elsif / else chain.
        [Form::Word(w), rest @ ..] if w == "if" => eval_if(rest, ctx),

        // fileinto "folder"
        [Form::Word(w), Form::Str(folder)] if w == "fileinto" => {
            let folder = expand_vars(folder, ctx);
            ctx.last_action = Some(SieveAction::FileInto(folder.clone()));
            StmtResult::FileInto(folder)
        }

        // reject "reason"
        [Form::Word(w), Form::Str(reason)] if w == "reject" => {
            let reason = expand_vars(reason, ctx);
            ctx.last_action = Some(SieveAction::Reject(reason.clone()));
            StmtResult::Reject(reason)
        }

        // discard
        [Form::Word(w)] if w == "discard" => {
            ctx.last_action = Some(SieveAction::Discard);
            StmtResult::Discard
        }

        // keep
        [Form::Word(w)] if w == "keep" => {
            ctx.last_action = Some(SieveAction::Keep);
            StmtResult::Keep
        }

        // stop
        [Form::Word(w)] if w == "stop" => StmtResult::Stop,

        // set [modifiers...] "name" "value"  (RFC 5229 §4)
        [Form::Word(w), rest @ ..] if w == "set" => {
            // Collect leading Tag modifiers, then expect Str(name) Str(value).
            let mut i = 0;
            let mut modifier_names: Vec<&str> = Vec::new();
            while i < rest.len() {
                if let Form::Tag(t) = &rest[i] {
                    modifier_names.push(t.as_str());
                    i += 1;
                } else {
                    break;
                }
            }
            if let (Some(Form::Str(name)), Some(Form::Str(value))) = (rest.get(i), rest.get(i + 1))
            {
                let expanded = expand_vars(value, ctx);
                let modified = apply_set_modifiers(expanded, &modifier_names);
                ctx.variables.insert(name.to_lowercase(), modified);
            }
            StmtResult::Continue
        }

        // Unknown command — silently continue per RFC 5228 §2.9 (fail-safe).
        // §2.9 requires that unrecognised commands are treated as no-ops so
        // that scripts using unsupported extensions degrade gracefully instead
        // of causing message loss.
        _ => StmtResult::Continue,
    }
}

// ---------------------------------------------------------------------------
// if / elsif / else
// ---------------------------------------------------------------------------

/// Evaluate an if-chain.
///
/// `rest` is the slice of forms *after* the leading `Word("if")`:
/// `[test_form0, test_form1, ..., Block(then_stmts), optional elsif/else ...]`
fn eval_if(rest: &[Form], ctx: &mut Ctx<'_>) -> StmtResult {
    if ctx.nesting_depth >= MAX_EVAL_DEPTH {
        // Should not happen for scripts that passed compile-time validation,
        // but guard defensively against bypassed checks (e.g. future
        // deserialization paths or test-only CompiledScript construction).
        warn!(
            depth = ctx.nesting_depth,
            "sieve: if-chain nesting depth exceeded MAX_EVAL_DEPTH; treating as no-op"
        );
        return StmtResult::Continue;
    }
    ctx.nesting_depth += 1;

    let block_pos = match rest.iter().position(|f| matches!(f, Form::Block(_))) {
        Some(p) => p,
        None => {
            ctx.nesting_depth -= 1;
            return StmtResult::Continue; // malformed
        }
    };

    let test_forms = &rest[..block_pos];
    let block = match &rest[block_pos] {
        Form::Block(stmts) => stmts,
        _ => {
            ctx.nesting_depth -= 1;
            return StmtResult::Continue;
        }
    };
    let after_block = &rest[block_pos + 1..];

    let result = if eval_test(test_forms, ctx) {
        match eval_stmt_list(block, ctx) {
            None | Some(StmtResult::Continue) => StmtResult::Continue,
            Some(other) => other,
        }
    } else {
        eval_elsif_else(after_block, ctx)
    };

    ctx.nesting_depth -= 1;
    result
}

fn eval_elsif_else(rest: &[Form], ctx: &mut Ctx<'_>) -> StmtResult {
    match rest {
        [] => StmtResult::Continue,

        [Form::Word(w), tail @ ..] if w == "elsif" => eval_if(tail, ctx),

        [Form::Word(w), Form::Block(stmts), ..] if w == "else" => {
            match eval_stmt_list(stmts, ctx) {
                None | Some(StmtResult::Continue) => StmtResult::Continue,
                Some(other) => other,
            }
        }

        _ => StmtResult::Continue,
    }
}

// ---------------------------------------------------------------------------
// Test evaluation
// ---------------------------------------------------------------------------

fn eval_test(forms: &[Form], ctx: &mut Ctx<'_>) -> bool {
    match forms {
        [Form::Word(w), rest @ ..] => match w.as_str() {
            "header" => eval_header_test(rest, ctx),
            "address" => eval_address_test(rest, ctx),
            "envelope" => eval_envelope_test(rest, ctx),
            "exists" => eval_exists_test(rest, ctx),
            "size" => eval_size_test(rest, ctx.message_size),
            "allof" => eval_allof(rest, ctx),
            "anyof" => eval_anyof(rest, ctx),
            "not" => !eval_test(rest, ctx),
            "true" => true,
            "false" => false,
            // Unknown test — fail-safe: return false per RFC 5228 §2.9.
            // An unsupported test never matches, so surrounding actions are
            // skipped rather than executed incorrectly.
            _ => false,
        },
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// allof / anyof
// ---------------------------------------------------------------------------

fn eval_allof(rest: &[Form], ctx: &mut Ctx<'_>) -> bool {
    match rest {
        [Form::TestList(tests)] => tests.iter().all(|t| eval_test(t, ctx)),
        _ => false,
    }
}

fn eval_anyof(rest: &[Form], ctx: &mut Ctx<'_>) -> bool {
    match rest {
        [Form::TestList(tests)] => tests.iter().any(|t| eval_test(t, ctx)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Match type / comparator / address-part extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum MatchType {
    Is,
    Contains,
    Matches,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Comparator {
    AsciiCasemap,
    Octet,
}

/// Scan `forms` for a match-type tag; remove it and return (type, rest).
///
/// All extraction functions operate on `&[&Form]` so they can be chained
/// without cloning: each one consumes a `Vec<&Form>` and produces another.
fn extract_match_type<'a>(forms: &[&'a Form]) -> (MatchType, Vec<&'a Form>) {
    let mut mt = MatchType::Is;
    let mut remaining = Vec::new();
    for f in forms.iter().copied() {
        if let Form::Tag(t) = f {
            match t.as_str() {
                "is" => {
                    mt = MatchType::Is;
                    continue;
                }
                "contains" => {
                    mt = MatchType::Contains;
                    continue;
                }
                "matches" => {
                    mt = MatchType::Matches;
                    continue;
                }
                "regex" => {
                    mt = MatchType::Regex;
                    continue;
                }
                _ => {}
            }
        }
        remaining.push(f);
    }
    (mt, remaining)
}

/// Scan `forms` for `:comparator "name"`; remove those two forms and return
/// (Comparator, rest).
fn extract_comparator<'a>(forms: &[&'a Form]) -> (Comparator, Vec<&'a Form>) {
    let mut cmp = Comparator::AsciiCasemap;
    let mut remaining = Vec::new();
    let mut iter = forms.iter().copied();
    while let Some(f) = iter.next() {
        if let Form::Tag(t) = f {
            if t == "comparator" {
                if let Some(Form::Str(s)) = iter.next() {
                    if s == "i;octet" {
                        cmp = Comparator::Octet;
                    }
                }
                continue;
            }
        }
        remaining.push(f);
    }
    (cmp, remaining)
}

/// Scan `forms` for an address-part tag; remove it and return (part, rest).
fn extract_address_part<'a>(forms: &[&'a Form]) -> (&'static str, Vec<&'a Form>) {
    let mut part = "all";
    let remaining: Vec<&Form> = forms
        .iter()
        .copied()
        .filter(|f| match f {
            Form::Tag(t) => match t.as_str() {
                "localpart" => {
                    part = "localpart";
                    false
                }
                "domain" => {
                    part = "domain";
                    false
                }
                "all" => {
                    part = "all";
                    false
                }
                _ => true,
            },
            _ => true,
        })
        .collect();
    (part, remaining)
}

// ---------------------------------------------------------------------------
// String matching helpers
// ---------------------------------------------------------------------------

fn str_is(a: &str, b: &str, casemap: bool) -> bool {
    if casemap {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn str_contains(haystack: &str, needle: &str, casemap: bool) -> bool {
    if casemap {
        if needle.is_empty() {
            return true;
        }
        let needle = needle.as_bytes();
        haystack
            .as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    } else {
        haystack.contains(needle)
    }
}

/// Sieve glob matching (RFC 5228 §2.7.1).
/// `*` = zero or more chars, `?` = exactly one char, `\*`/`\?` = literals.
fn str_matches_glob(value: &str, pattern: &str, casemap: bool) -> bool {
    let (regex_pat, _) = sieve_glob_to_regex_capturing(pattern);
    str_matches_regex_pat(value, &regex_pat, casemap)
}

/// Sieve glob match with RFC 5229 §4 capture variable extraction.
///
/// When the match succeeds and `vars` is `Some`, populates `${0}` (whole
/// match) and `${1}`, `${2}`, ... (one per `*` wildcard, in order) in the
/// given map.  `?` wildcards do not produce capture groups (RFC 5229 §4
/// assigns numbered captures only to `*`).
///
/// Returns `true` when the pattern matches `value`.
fn str_matches_glob_captures(
    value: &str,
    pattern: &str,
    casemap: bool,
    vars: Option<&mut HashMap<String, String>>,
) -> bool {
    let (regex_pat, star_count) = sieve_glob_to_regex_capturing(pattern);
    REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (regex_pat.clone(), casemap);
        if cache.get(&key).is_none() {
            let pat = if casemap {
                format!("(?i){regex_pat}")
            } else {
                regex_pat.clone()
            };
            match fancy_regex::Regex::new(&pat) {
                Ok(re) => {
                    cache.put(key.clone(), re);
                }
                Err(err) => {
                    warn!(pattern = %pat, "Sieve :matches compile error: {err}");
                    return false;
                }
            }
        }
        let re = cache.get(&key).expect("just inserted");
        match re.captures(value) {
            Ok(Some(caps)) => {
                if let Some(v) = vars {
                    v.insert(
                        "0".to_string(),
                        caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string(),
                    );
                    for i in 1..=star_count {
                        let captured = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                        v.insert(i.to_string(), captured.to_string());
                    }
                }
                true
            }
            Ok(None) => false,
            Err(e) => {
                warn!(pattern = %regex_pat, "Sieve :matches execution error: {e}");
                false
            }
        }
    })
}

/// Convert a Sieve glob pattern to an anchored capturing regex string.
///
/// Each `*` wildcard becomes a capturing group `(.*)` so RFC 5229 §4
/// numbered variables can be populated on match.  `?` is not captured.
///
/// Returns `(regex_string, star_count)` where `star_count` is the number
/// of `*` wildcards (= number of capture groups, excluding group 0).
fn sieve_glob_to_regex_capturing(pattern: &str) -> (String, usize) {
    let mut out = String::from("(?s)\\A");
    let mut star_count: usize = 0;
    let mut buf = [0u8; 4];
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    chars.next();
                    match next {
                        '*' | '?' => out.push_str(&fancy_regex::escape(next.encode_utf8(&mut buf))),
                        other => {
                            out.push_str(&fancy_regex::escape(ch.encode_utf8(&mut buf)));
                            out.push_str(&fancy_regex::escape(other.encode_utf8(&mut buf)));
                        }
                    }
                } else {
                    out.push_str(&fancy_regex::escape("\\"));
                }
            }
            '*' => {
                star_count += 1;
                out.push_str("(.*)");
            }
            '?' => out.push('.'),
            other => out.push_str(&fancy_regex::escape(other.encode_utf8(&mut buf))),
        }
    }
    out.push_str("\\z");
    (out, star_count)
}

/// Match `value` against a regex extension pattern (anchored to whole value).
fn str_matches_regex(value: &str, pattern: &str, casemap: bool) -> bool {
    let anchored = format!("(?s)\\A(?:{pattern})\\z");
    str_matches_regex_pat(value, &anchored, casemap)
}

fn str_matches_regex_pat(value: &str, anchored: &str, casemap: bool) -> bool {
    REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (anchored.to_string(), casemap);

        // Insert on miss; LruCache evicts the LRU entry when CAP is reached.
        if cache.get(&key).is_none() {
            let pat = if casemap {
                format!("(?i){anchored}")
            } else {
                anchored.to_string()
            };
            match fancy_regex::Regex::new(&pat) {
                Ok(re) => {
                    cache.put(key.clone(), re);
                }
                Err(err) => {
                    warn!(pattern = %pat, "Sieve :regex compile error: {err}");
                    return false;
                }
            }
        }

        // get() promotes the entry to MRU; unwrap is safe: we just ensured it exists.
        cache.get(&key).expect("just inserted").is_match(value).unwrap_or_else(|e| {
            warn!(pattern = %anchored, casemap, "Sieve :regex execution error (backtracking limit?): {e}");
            false
        })
    })
}

fn apply_match(value: &str, key: &str, mt: MatchType, casemap: bool) -> bool {
    match mt {
        MatchType::Is => str_is(value, key, casemap),
        MatchType::Contains => str_contains(value, key, casemap),
        MatchType::Matches => str_matches_glob(value, key, casemap),
        MatchType::Regex => str_matches_regex(value, key, casemap),
    }
}

// ---------------------------------------------------------------------------
// Collect string operands from a form slice
// ---------------------------------------------------------------------------

/// Return `(names, keys)` — the two string-list arguments of a test.
fn collect_two_string_lists<'a>(forms: &[&'a Form]) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut lists: Vec<Vec<&str>> = Vec::new();
    for f in forms {
        match f {
            Form::Str(s) => lists.push(vec![s.as_str()]),
            Form::StringList(v) => lists.push(v.iter().map(String::as_str).collect()),
            _ => {}
        }
    }
    let names = lists.first().cloned().unwrap_or_default();
    let keys = lists.get(1).cloned().unwrap_or_default();
    (names, keys)
}

/// Return a single string list from forms.
fn collect_one_string_list<'a>(forms: &[&'a Form]) -> Vec<&'a str> {
    let mut result: Vec<&str> = Vec::new();
    for f in forms {
        match f {
            Form::Str(s) => result.push(s.as_str()),
            Form::StringList(v) => result.extend(v.iter().map(String::as_str)),
            _ => {}
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Individual test implementations
// ---------------------------------------------------------------------------

fn eval_header_test(forms: &[Form], ctx: &mut Ctx<'_>) -> bool {
    let refs: Vec<&Form> = forms.iter().collect();
    let (mt, after_mt) = extract_match_type(&refs);
    let (cmp, after_cmp) = extract_comparator(&after_mt);
    let casemap = cmp == Comparator::AsciiCasemap;
    let (field_names, keys) = collect_two_string_lists(&after_cmp);
    let variables_enabled = ctx.variables_enabled;

    // Collect captures into a local map first so the immutable borrow of
    // ctx.headers and the mutable borrow of ctx.variables do not overlap.
    let mut pending_captures: Option<HashMap<String, String>> = None;
    'search: for (hdr_name, hdr_value) in &ctx.headers {
        for fname in &field_names {
            if hdr_name.eq_ignore_ascii_case(fname) {
                for key in &keys {
                    if mt == MatchType::Matches && variables_enabled {
                        let mut captures: HashMap<String, String> = HashMap::new();
                        if str_matches_glob_captures(hdr_value, key, casemap, Some(&mut captures)) {
                            pending_captures = Some(captures);
                            break 'search;
                        }
                    } else if apply_match(hdr_value, key, mt, casemap) {
                        return true;
                    }
                }
            }
        }
    }

    if let Some(captures) = pending_captures {
        ctx.variables.extend(captures);
        true
    } else {
        false
    }
}

fn eval_address_test(forms: &[Form], ctx: &mut Ctx<'_>) -> bool {
    let refs: Vec<&Form> = forms.iter().collect();
    let (mt, after_mt) = extract_match_type(&refs);
    let (cmp, after_cmp) = extract_comparator(&after_mt);
    let casemap = cmp == Comparator::AsciiCasemap;
    let (part, after_part) = extract_address_part(&after_cmp);
    let (field_names, keys) = collect_two_string_lists(&after_part);

    for (hdr_name, hdr_value) in &ctx.headers {
        for fname in &field_names {
            if hdr_name.eq_ignore_ascii_case(fname) {
                let addr = message::address_part(hdr_value, part);
                for key in &keys {
                    if apply_match(&addr, key, mt, casemap) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn eval_envelope_test(forms: &[Form], ctx: &mut Ctx<'_>) -> bool {
    let refs: Vec<&Form> = forms.iter().collect();
    let (mt, after_mt) = extract_match_type(&refs);
    let (cmp, after_cmp) = extract_comparator(&after_mt);
    let casemap = cmp == Comparator::AsciiCasemap;
    let (part, after_part) = extract_address_part(&after_cmp);
    let (part_names, keys) = collect_two_string_lists(&after_part);

    for pname in &part_names {
        let raw_addr = match pname.to_ascii_lowercase().as_str() {
            "from" => ctx.envelope_from,
            "to" => ctx.envelope_to,
            _ => continue,
        };
        let addr = message::address_part(raw_addr, part);
        for key in &keys {
            if apply_match(&addr, key, mt, casemap) {
                return true;
            }
        }
    }
    false
}

fn eval_exists_test(forms: &[Form], ctx: &Ctx<'_>) -> bool {
    let tmp: Vec<&Form> = forms.iter().collect();
    let names = collect_one_string_list(&tmp);
    names.iter().all(|name| {
        ctx.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    })
}

fn eval_size_test(forms: &[Form], message_size: usize) -> bool {
    let mut over = false;
    let mut under = false;
    let mut limit: Option<u64> = None;

    for f in forms {
        match f {
            Form::Tag(t) if t == "over" => over = true,
            Form::Tag(t) if t == "under" => under = true,
            Form::Num(n) => limit = Some(*n),
            _ => {}
        }
    }

    let limit = match limit {
        Some(l) => l as usize,
        None => return false,
    };

    if over {
        message_size > limit
    } else if under {
        message_size < limit
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Variable substitution (RFC 5229)
// ---------------------------------------------------------------------------

/// Replace `${varname}` with values from `ctx.variables`.  `\$` → literal `$`.
///
/// Substitution is skipped entirely when `ctx.variables_enabled` is false
/// (i.e. `require ["variables"]` was not declared — RFC 5229 §3).
fn expand_vars(s: &str, ctx: &Ctx<'_>) -> String {
    if !ctx.variables_enabled {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if chars.peek() == Some(&'$') {
                chars.next();
                out.push('$');
            } else {
                out.push('\\');
            }
            continue;
        }
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut name = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                name.push(inner);
            }
            if closed {
                // Variable names are case-insensitive (RFC 5229 §3): the spec
                // requires that ${Foo}, ${FOO}, and ${foo} all refer to the
                // same variable.  All lookups use the lowercased name; `set`
                // stores under the lowercased name too (see eval_stmt).
                let val = ctx
                    .variables
                    .get(&name.to_lowercase())
                    .map(String::as_str)
                    .unwrap_or("");
                out.push_str(val);
            } else {
                // Unclosed brace — emit literally.
                out.push_str("${");
                out.push_str(&name);
            }
            continue;
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------------------
// set modifier application (RFC 5229 §4)
// ---------------------------------------------------------------------------

/// Apply RFC 5229 §4 modifiers to a value in precedence order.
///
/// Modifiers may appear in any order in the script; they are always applied
/// in precedence order regardless:
///
/// | Precedence | Modifier        |
/// |------------|-----------------|
/// | 40         | `:lower`/`:upper` |
/// | 30         | `:length`       |
/// | 20         | `:quotewildcard` |
/// | 10         | `:firstline`    |
fn apply_set_modifiers(value: String, modifiers: &[&str]) -> String {
    // Sort modifiers by precedence (highest first = applied first).
    fn precedence(m: &str) -> u8 {
        match m {
            "lower" | "upper" => 40,
            "length" => 30,
            "quotewildcard" => 20,
            "firstline" => 10,
            _ => 0,
        }
    }

    let mut sorted: Vec<&str> = modifiers.to_vec();
    sorted.sort_by_key(|m| Reverse(precedence(m)));

    let mut v = value;
    for m in sorted {
        v = match m {
            "lower" => v.to_ascii_lowercase(),
            "upper" => v.to_ascii_uppercase(),
            "length" => v.chars().count().to_string(),
            "quotewildcard" => v.replace('*', "\\*").replace('?', "\\?"),
            "firstline" => {
                // Truncate at the first \n or \r\n.
                if let Some(pos) = v.find('\n') {
                    let end = if pos > 0 && v.as_bytes()[pos - 1] == b'\r' {
                        pos - 1
                    } else {
                        pos
                    };
                    v[..end].to_string()
                } else {
                    v
                }
            }
            // Unknown modifiers are silently ignored (fail-safe per RFC 5229 §4).
            // The spec does not require an error on unrecognised modifiers.
            _ => v,
        };
    }
    v
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── sieve_glob_to_regex_capturing: regex string output ───────────────────

    /// The `*` wildcard must emit `(.*)` in the capturing regex.
    #[test]
    fn glob_star_emits_dot_star() {
        let (re, count) = sieve_glob_to_regex_capturing("foo*bar");
        assert!(re.contains(".*"), "star must expand to .* in regex: {re:?}");
        assert_eq!(count, 1, "one * must produce one capture group");
    }

    /// The `?` wildcard must emit `.` (any single char) in the regex.
    #[test]
    fn glob_question_emits_dot() {
        let (re, _) = sieve_glob_to_regex_capturing("fo?");
        // Should contain a bare "." but NOT ".*" for the ? position.
        assert!(re.contains('.'), "? must emit a dot in regex: {re:?}");
    }

    /// A literal dot in the pattern must be escaped so it does not match
    /// any character.  Oracle: RFC 5228 §2.7.1 — only `*` and `?` are
    /// wildcards; all other characters are literals.
    #[test]
    fn glob_literal_dot_escaped() {
        let (re, _) = sieve_glob_to_regex_capturing("a.b");
        // fancy_regex::escape(".") yields "\.", which we expect to appear.
        assert!(
            re.contains("\\."),
            "literal dot must be escaped in regex: {re:?}"
        );
    }

    // ── str_matches_glob: functional oracle (RFC 5228 §2.7.1) ───────────────

    /// `*` matches zero characters.
    /// Oracle: RFC 5228 §2.7.1 "asterisk … matches zero or more characters".
    #[test]
    fn glob_star_matches_empty() {
        assert!(
            str_matches_glob("", "*", false),
            "* must match empty string"
        );
    }

    /// `*` matches an arbitrary sequence.
    #[test]
    fn glob_star_matches_multi() {
        assert!(str_matches_glob("hello world", "*", false));
        assert!(str_matches_glob("hello world", "hel*rld", false));
    }

    /// `?` matches exactly one character; not zero, not two.
    /// Oracle: RFC 5228 §2.7.1 "question mark … matches any single character".
    #[test]
    fn glob_question_matches_one_char() {
        assert!(
            str_matches_glob("a", "?", false),
            "? must match single char"
        );
        assert!(
            !str_matches_glob("", "?", false),
            "? must not match empty string"
        );
        assert!(
            !str_matches_glob("ab", "?", false),
            "? must not match two chars"
        );
    }

    /// A literal dot in the pattern must match only a dot, not any character.
    /// Oracle: RFC 5228 §2.7.1 — only `*` and `?` are wildcards.
    #[test]
    fn glob_literal_dot_matches_only_dot() {
        assert!(
            str_matches_glob("hello.world", "hello.world", false),
            "literal dot must match dot"
        );
        assert!(
            !str_matches_glob("helloXworld", "hello.world", false),
            "literal dot must NOT match arbitrary char"
        );
    }

    /// A literal `+` in the pattern is not a regex quantifier.
    #[test]
    fn glob_literal_plus_is_not_quantifier() {
        assert!(
            str_matches_glob("a+b", "a+b", false),
            "literal + must match +"
        );
        assert!(
            !str_matches_glob("ab", "a+b", false),
            "literal + must NOT be a quantifier"
        );
        assert!(!str_matches_glob("aab", "a+b", false));
    }

    /// `\*` in the pattern matches a literal `*`, not a wildcard.
    /// Oracle: RFC 5228 §2.7.1 "backslash followed by an asterisk
    /// or question mark is a literal character".
    #[test]
    fn glob_escaped_star_is_literal() {
        assert!(
            str_matches_glob("test*", "test\\*", false),
            r"test\* must match literal test*"
        );
        assert!(
            !str_matches_glob("testXXX", "test\\*", false),
            r"test\* must NOT treat \* as wildcard"
        );
    }

    /// `\?` in the pattern matches a literal `?`.
    #[test]
    fn glob_escaped_question_is_literal() {
        assert!(
            str_matches_glob("test?", "test\\?", false),
            r"test\? must match literal test?"
        );
        assert!(
            !str_matches_glob("testX", "test\\?", false),
            r"test\? must NOT match arbitrary char"
        );
    }

    /// Glob matching is case-insensitive when `casemap` is true.
    /// Oracle: RFC 5228 §2.7.3 comparator `i;ascii-casemap`.
    #[test]
    fn glob_casemap_ignores_case() {
        assert!(
            str_matches_glob("HELLO", "hel*", true),
            "casemap=true must be case-insensitive"
        );
        assert!(
            !str_matches_glob("HELLO", "hel*", false),
            "casemap=false must be case-sensitive"
        );
    }

    /// A malformed regex pattern (one that isn't a valid regex after
    /// glob conversion) must not panic — it must return false.
    /// This verifies the `unwrap_or(false)` safety net in str_matches_regex_pat.
    #[test]
    fn glob_malformed_regex_does_not_panic() {
        // Inject a pattern that, after glob→regex conversion, produces valid regex.
        // But pass a direct invalid regex to str_matches_regex_pat to hit the
        // error path.
        let result = str_matches_regex_pat("anything", "(?s)\\A(?:[\\z", false);
        assert!(!result, "invalid regex must return false, not panic");
    }
}
