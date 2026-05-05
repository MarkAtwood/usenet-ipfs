// SPDX-License-Identifier: MIT

//! Native (dependency-free) Sieve script compiler and evaluator.
//!
//! This crate provides the same public API as `stoa-sieve` but with
//! no external runtime dependencies beyond `fancy-regex`.  The compiler and
//! evaluator are implemented from scratch against RFC 5228 (base Sieve) and
//! RFC 5229 (variables extension).
//!
//! The internal pipeline is:
//!
//! 1. [`lexer::tokenize`] — raw source → `Vec<Token>`
//! 2. [`form::read_script`] — tokens → `Script` (a uniform form tree)
//! 3. [`evaluator::eval_script`] — `Script` + message → `Vec<SieveAction>`

use std::collections::HashMap;
use std::sync::Arc;

pub mod form;
pub mod lexer;
pub mod parse_error;

mod evaluator;
mod message;

/// Runtime environment for a Sieve evaluation (RFC 5183).
///
/// Callers populate this before calling [`evaluate`]; the evaluator treats
/// any name absent from the map as the empty string (RFC 5183 §4).
///
/// # Example
///
/// ```rust
/// # use stoa_sieve_native::SieveEnv;
/// let mut env = SieveEnv::new();
/// env.set("vnd.stoa.dkim-result", "pass");
/// assert_eq!(env.get("vnd.stoa.dkim-result"), "pass");
/// assert_eq!(env.get("unknown"), "");
/// ```
#[derive(Debug, Default, Clone)]
pub struct SieveEnv {
    values: HashMap<String, String>,
}

impl SieveEnv {
    /// Create an empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an environment value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    /// Get an environment value; returns `""` if the name is unknown (RFC 5183 §4).
    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or("")
    }
}

/// A compiled Sieve script, ready for evaluation.
///
/// Opaque to callers; contains the parsed form tree.  `Send + Sync` because
/// the inner `Arc<form::Script>` contains only `Send + Sync` types.
#[derive(Debug)]
pub struct CompiledScript(Arc<form::Script>);

// Explicit assertion that CompiledScript is Send + Sync.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<CompiledScript>();
    }
    let _ = check;
};

/// Disposition returned after evaluating a Sieve script against a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveAction {
    Keep,
    FileInto(String),
    Discard,
    Reject(String),
}

/// Compile a Sieve script from raw source bytes.
///
/// The bytes must be valid UTF-8.  Returns `Err` with a human-readable
/// description on parse or compile failure, including unknown `require`
/// extensions.
///
/// # Errors
///
/// Returns `Err` if the script is not valid UTF-8, if tokenising or parsing
/// fails, or if the script requires an unsupported extension.
pub fn compile(script: &[u8]) -> Result<CompiledScript, String> {
    let source = std::str::from_utf8(script).map_err(|e| format!("invalid UTF-8: {e}"))?;
    let tokens = lexer::tokenize(source).map_err(String::from)?;
    let parsed = form::read_script(&tokens).map_err(String::from)?;

    // Validate require extensions and collect declared extensions.
    const KNOWN: &[&str] = &["fileinto", "reject", "variables", "regex", "environment"];
    let mut declared: Vec<String> = Vec::new();
    for stmt in &parsed {
        if let [form::Form::Word(w), rest @ ..] = stmt.as_slice() {
            if w == "require" {
                let extensions: Vec<&str> = rest
                    .iter()
                    .flat_map(|f| match f {
                        form::Form::Str(s) => vec![s.as_str()],
                        form::Form::StringList(v) => v.iter().map(String::as_str).collect(),
                        _ => vec![],
                    })
                    .collect();
                for ext in extensions {
                    if !KNOWN.contains(&ext) {
                        return Err(format!("unsupported Sieve extension: {ext}"));
                    }
                    declared.push(ext.to_string());
                }
            }
        }
    }

    // Validate that extensions requiring a `require` declaration are not used
    // without one.  RFC 5228 §2.10.5: using a capability without declaring it
    // in `require` is a compile-time error.
    //
    // Currently enforced: `environment` test (RFC 5183).
    if !declared.contains(&"environment".to_string()) {
        check_no_test_keyword(&parsed, "environment")?;
    }

    validate_script(&parsed)?;

    Ok(CompiledScript(Arc::new(parsed)))
}

/// Walk every statement in a script (recursing into blocks and test lists)
/// and enforce compile-time constraints:
///
/// - RFC 5228 §2.7.2: unknown comparator names must fail the script.
///   Known comparators: `"i;ascii-casemap"` and `"i;octet"`.
/// - Regex extension: invalid regex patterns must fail the script so that
///   broken patterns are caught early rather than silently failing at eval time.
///
/// # ReDoS note
///
/// `fancy_regex::Regex::new` rejects syntactically invalid patterns but does
/// **not** detect exponential-backtracking (ReDoS) patterns such as `(a+)+b`.
/// Compile-time complexity analysis would require a heavy additional dependency
/// that does not currently exist in Rust.  The runtime mitigation is
/// `sieve_eval_timeout_ms` (set in the SMTP config): the evaluator is killed
/// after the configured deadline, bounding worst-case CPU per untrusted script.
/// Operators must set this to a reasonable value (e.g. 100 ms) when accepting
/// scripts from untrusted sources.
/// Maximum nesting depth for `if`/`elsif` blocks and `allof`/`anyof` test
/// lists.  Matches the Dovecot Pigeonhole limit; prevents stack exhaustion
/// on maliciously crafted scripts.
const MAX_VALIDATE_DEPTH: usize = 32;

/// Return an error if `keyword` appears as a test name anywhere in the script.
///
/// Used to enforce that extensions declared in `require` are used before the
/// extension's test keyword can appear.  Recurses into blocks and test lists.
fn check_no_test_keyword(script: &form::Script, keyword: &str) -> Result<(), String> {
    for stmt in script {
        check_stmt_no_test_keyword(stmt, keyword)?;
    }
    Ok(())
}

fn check_stmt_no_test_keyword(stmt: &form::Stmt, keyword: &str) -> Result<(), String> {
    // A test keyword appears immediately after `if` or `elsif` as the test
    // name.  We also need to check inside blocks and test lists recursively.
    for (i, form) in stmt.iter().enumerate() {
        match form {
            form::Form::Word(w) => {
                // Check if this word is `if` or `elsif` and the next word is the keyword.
                if w == "if" || w == "elsif" {
                    if let Some(form::Form::Word(test_name)) = stmt.get(i + 1) {
                        if test_name == keyword {
                            return Err(format!(
                                "test '{keyword}' used without require [\"{keyword}\"]"
                            ));
                        }
                    }
                }
            }
            form::Form::Block(stmts) => {
                check_no_test_keyword(stmts, keyword)?;
            }
            form::Form::TestList(tests) => {
                for test in tests {
                    check_stmt_no_test_keyword(test, keyword)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_script(script: &form::Script) -> Result<(), String> {
    for stmt in script {
        validate_stmt(stmt, 0)?;
    }
    Ok(())
}

fn validate_stmt(stmt: &form::Stmt, depth: usize) -> Result<(), String> {
    if depth >= MAX_VALIDATE_DEPTH {
        return Err(format!(
            "script nesting depth exceeds limit of {MAX_VALIDATE_DEPTH}"
        ));
    }
    // Scan the flat form list for Tag("comparator") followed by Str(name).
    // Also detect Tag("regex") and validate all Str patterns in the stmt.
    let mut has_regex_tag = false;
    let mut iter = stmt.iter().peekable();
    while let Some(form) = iter.next() {
        match form {
            form::Form::Tag(t) if t == "comparator" => {
                // The next form must be the comparator name string.
                match iter.peek() {
                    Some(form::Form::Str(name)) => {
                        const KNOWN_COMPARATORS: &[&str] = &["i;ascii-casemap", "i;octet"];
                        if !KNOWN_COMPARATORS.contains(&name.as_str()) {
                            return Err(format!("unsupported comparator: {name}"));
                        }
                        iter.next(); // consume the comparator name
                    }
                    Some(_) => {
                        return Err(
                            ":comparator tag must be followed by a string literal".to_string()
                        );
                    }
                    None => {
                        return Err(":comparator tag at end of statement with no name".to_string());
                    }
                }
            }
            form::Form::Tag(t) if t == "regex" => {
                has_regex_tag = true;
            }
            form::Form::Block(stmts) => {
                // Recurse into braced blocks.
                for inner in stmts {
                    validate_stmt(inner, depth + 1)?;
                }
            }
            form::Form::TestList(tests) => {
                // Recurse into parenthesised test lists.
                for test in tests {
                    validate_stmt(test, depth + 1)?;
                }
            }
            _ => {}
        }
    }

    // If this statement uses :regex, validate only the key-list (pattern) strings.
    // In every Sieve test that accepts :regex, the key-list is the LAST Str or
    // StringList before the Block.  Scanning backwards avoids mistaking field-name
    // strings (e.g. "X[Special]") for regex patterns — field names are in the
    // second-to-last position and are not valid regex in general.
    if has_regex_tag {
        let last_str_pos = stmt
            .iter()
            .rposition(|f| matches!(f, form::Form::Str(_) | form::Form::StringList(_)));
        if let Some(pos) = last_str_pos {
            match &stmt[pos] {
                form::Form::Str(pattern) => {
                    let anchored = format!("(?s)\\A(?:{pattern})\\z");
                    fancy_regex::Regex::new(&anchored)
                        .map_err(|e| format!("invalid regex pattern {pattern:?}: {e}"))?;
                }
                form::Form::StringList(patterns) => {
                    for pattern in patterns {
                        let anchored = format!("(?s)\\A(?:{pattern})\\z");
                        fancy_regex::Regex::new(&anchored)
                            .map_err(|e| format!("invalid regex pattern {pattern:?}: {e}"))?;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Evaluate a compiled Sieve script against a raw RFC 5322 message.
///
/// `envelope_from` and `envelope_to` are the SMTP envelope addresses.
/// `env` provides RFC 5183 environment values; pass `&SieveEnv::new()` for
/// an empty environment when the extension is not used.
///
/// Returns the list of actions the script requests; defaults to `[Keep]`
/// when the script produces no explicit disposition (RFC 5228 §2.10.2).
pub fn evaluate(
    script: &CompiledScript,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
    env: &SieveEnv,
) -> Vec<SieveAction> {
    evaluator::eval_script(&script.0, raw_message, envelope_from, envelope_to, env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use form::Form;
    use lexer::{tokenize, Token};

    // -----------------------------------------------------------------------
    // Lexer tests
    // -----------------------------------------------------------------------

    #[test]
    fn tokenize_basic() {
        let src = r#"if header :contains "Subject" "test" { keep; }"#;
        let tokens = tokenize(src).expect("tokenize failed");
        assert_eq!(
            tokens,
            vec![
                Token::Word("if".into()),
                Token::Word("header".into()),
                Token::Tag("contains".into()),
                Token::StringLit("Subject".into()),
                Token::StringLit("test".into()),
                Token::LBrace,
                Token::Word("keep".into()),
                Token::Semicolon,
                Token::RBrace,
            ]
        );
    }

    #[test]
    fn tokenize_number_multipliers() {
        let tokens = tokenize("1K 2M").expect("tokenize failed");
        assert_eq!(
            tokens,
            vec![Token::Number(1024), Token::Number(2 * 1024 * 1024)]
        );
    }

    #[test]
    fn tokenize_quoted_string_escapes() {
        // Source: "hello \"world\""
        let tokens = tokenize(r#""hello \"world\"""#).expect("tokenize failed");
        assert_eq!(tokens, vec![Token::StringLit("hello \"world\"".into())]);
    }

    #[test]
    fn tokenize_line_comment_skipped() {
        let src = "keep # this is a comment\n;";
        let tokens = tokenize(src).expect("tokenize failed");
        assert_eq!(tokens, vec![Token::Word("keep".into()), Token::Semicolon]);
    }

    #[test]
    fn tokenize_block_comment_skipped() {
        let src = "keep /* ignore this */ ;";
        let tokens = tokenize(src).expect("tokenize failed");
        assert_eq!(tokens, vec![Token::Word("keep".into()), Token::Semicolon]);
    }

    // -----------------------------------------------------------------------
    // Multiline string test
    // -----------------------------------------------------------------------

    #[test]
    fn parse_multiline_string() {
        // RFC 5228 §2.3.1 multiline literal: text:\nfoo\n.\n
        let src = "text:\nfoo\n.\n";
        let tokens = tokenize(src).expect("tokenize failed");
        assert_eq!(tokens, vec![Token::StringLit("foo".into())]);
    }

    // -----------------------------------------------------------------------
    // Form / script parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_script_simple_if() {
        let src = r#"if header :contains "Subject" "x" { keep; }"#;
        let tokens = tokenize(src).expect("tokenize failed");
        let script = form::read_script(&tokens).expect("read_script failed");
        assert_eq!(script.len(), 1, "expected exactly 1 top-level statement");
        let stmt = &script[0];
        // First form is Word("if")
        assert!(matches!(&stmt[0], Form::Word(w) if w == "if"));
        // Second form is Word("header")
        assert!(matches!(&stmt[1], Form::Word(w) if w == "header"));
        // Third form is Tag("contains")
        assert!(matches!(&stmt[2], Form::Tag(t) if t == "contains"));
        // Fourth is Str("Subject"), fifth is Str("x")
        assert!(matches!(&stmt[3], Form::Str(s) if s == "Subject"));
        assert!(matches!(&stmt[4], Form::Str(s) if s == "x"));
        // Sixth form is Block containing [keep]
        assert!(matches!(&stmt[5], Form::Block(_)));
        if let Form::Block(block) = &stmt[5] {
            assert_eq!(block.len(), 1);
            assert!(matches!(&block[0][0], Form::Word(w) if w == "keep"));
        }
    }

    #[test]
    fn parse_error_unclosed_brace() {
        let src = "if true {";
        let tokens = tokenize(src).expect("tokenize failed");
        let result = form::read_script(&tokens);
        assert!(result.is_err(), "expected ParseError for unclosed brace");
        let err = result.unwrap_err();
        assert!(
            err.message.contains("unclosed") || err.message.contains("missing"),
            "unexpected error message: {}",
            err.message
        );
    }

    #[test]
    fn parse_require() {
        let src = r#"require ["fileinto", "reject"];"#;
        let tokens = tokenize(src).expect("tokenize failed");
        let script = form::read_script(&tokens).expect("read_script failed");
        assert_eq!(script.len(), 1);
        let stmt = &script[0];
        assert!(matches!(&stmt[0], Form::Word(w) if w == "require"));
        assert!(
            matches!(&stmt[1], Form::StringList(v) if v == &["fileinto", "reject"]),
            "expected StringList([\"fileinto\", \"reject\"]), got {:?}",
            &stmt[1]
        );
    }

    // -----------------------------------------------------------------------
    // compile() integration smoke test
    // -----------------------------------------------------------------------

    #[test]
    fn compile_simple_script() {
        let src = b"require [\"fileinto\"];\nif header :contains \"X-Spam\" \"yes\" { fileinto \"Spam\"; }";
        let result = compile(src);
        assert!(result.is_ok(), "compile failed: {:?}", result.err());
    }

    #[test]
    fn compile_invalid_utf8() {
        let result = compile(b"\xff\xfe");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UTF-8"));
    }

    // -----------------------------------------------------------------------
    // Evaluator tests
    // -----------------------------------------------------------------------

    fn make_msg(subject: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: {subject}\r\n\r\nBody.\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn eval_implicit_keep_empty_script() {
        let script = compile(b"").unwrap();
        let actions = evaluate(
            &script,
            &make_msg("test"),
            "sender@example.com",
            "recip@example.com",
            &SieveEnv::new(),
        );
        assert_eq!(actions, vec![SieveAction::Keep]);
    }

    #[test]
    fn eval_explicit_keep() {
        let script = compile(b"keep;").unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::Keep]);
    }

    #[test]
    fn eval_discard() {
        let script = compile(b"discard;").unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::Discard]);
    }

    #[test]
    fn eval_fileinto_subject_match() {
        let script = compile(
            b"require [\"fileinto\"]; if header :contains \"Subject\" \"URGENT\" { fileinto \"INBOX.Urgent\"; }",
        )
        .unwrap();
        let actions = evaluate(
            &script,
            &make_msg("URGENT: fix this"),
            "",
            "",
            &SieveEnv::new(),
        );
        assert_eq!(actions, vec![SieveAction::FileInto("INBOX.Urgent".into())]);
    }

    #[test]
    fn eval_fileinto_subject_no_match() {
        let script = compile(
            b"require [\"fileinto\"]; if header :contains \"Subject\" \"URGENT\" { fileinto \"INBOX.Urgent\"; }",
        )
        .unwrap();
        let actions = evaluate(
            &script,
            &make_msg("Normal message"),
            "",
            "",
            &SieveEnv::new(),
        );
        assert_eq!(actions, vec![SieveAction::Keep]);
    }

    #[test]
    fn eval_reject() {
        let script = compile(b"require [\"reject\"]; reject \"Not wanted\";").unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::Reject("Not wanted".into())]);
    }

    #[test]
    fn eval_header_is_case_insensitive() {
        let script = compile(b"if header :is \"subject\" \"exact match\" { discard; }").unwrap();
        let actions = evaluate(&script, &make_msg("exact match"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::Discard]);
    }

    #[test]
    fn eval_size_over_true() {
        let script =
            compile(b"require [\"fileinto\"]; if size :over 10 { fileinto \"Big\"; }").unwrap();
        let msg = make_msg("test"); // should be > 10 bytes
        let actions = evaluate(&script, &msg, "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("Big".into())]);
    }

    #[test]
    fn eval_exists_header_present() {
        let script =
            compile(b"require [\"fileinto\"]; if exists \"X-Spam-Flag\" { fileinto \"Spam\"; }")
                .unwrap();
        let msg = b"X-Spam-Flag: YES\r\nSubject: test\r\n\r\nBody\r\n";
        let actions = evaluate(&script, msg, "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("Spam".into())]);
    }

    #[test]
    fn eval_unknown_extension_compile_error() {
        let result = compile(b"require [\"erewhon\"];");
        assert!(result.is_err());
    }

    #[test]
    fn eval_unknown_comparator_compile_error() {
        let result =
            compile(b"if header :is :comparator \"i;invalid\" \"Subject\" \"test\" { keep; }");
        assert!(result.is_err(), "unknown comparator must fail at compile");
        assert!(
            result.unwrap_err().contains("comparator"),
            "error must mention comparator"
        );
    }

    /// RFC 5228 §2.7.2: `:comparator` must be followed by a string literal.
    /// A non-string token after `:comparator` is a parse error — the parser
    /// must not silently consume the next token and corrupt state.
    #[test]
    fn comparator_followed_by_non_str_is_parse_error() {
        // `:comparator 42` — 42 is a Number token, not a Str.
        let result = compile(b"if header :comparator 42 \"Subject\" \"test\" { keep; }");
        assert!(
            result.is_err(),
            ":comparator followed by non-string must fail at compile"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("comparator"),
            "error must mention comparator; got: {msg:?}"
        );
    }

    /// RFC 5228 §4.1: `stop` halts execution; when no explicit action preceded
    /// it the implicit keep applies.  Oracle: RFC 5228 §4.1 and §2.10.2.
    #[test]
    fn eval_stop_alone_yields_implicit_keep() {
        let script = compile(b"stop;").unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(
            actions,
            vec![SieveAction::Keep],
            "stop with no prior action must produce implicit Keep (RFC 5228 §4.1)"
        );
    }

    #[test]
    fn compile_invalid_regex_pattern_fails() {
        let result =
            compile(b"require [\"regex\"]; if header :regex \"Subject\" \"[invalid\" { keep; }");
        assert!(result.is_err(), "invalid regex must fail at compile");
    }

    #[test]
    fn compile_regex_does_not_validate_header_name_as_pattern() {
        // "X[Special]" is a valid header name but not a valid regex character class.
        // Only the match keys (last Str/StringList) are validated as regex; the
        // header field name must not be.
        let result =
            compile(b"require [\"regex\"]; if header :regex \"X[Special]\" \"test.*\" { keep; }");
        assert!(
            result.is_ok(),
            "header name should not be validated as regex: {:?}",
            result.err()
        );
    }

    #[test]
    fn compile_regex_validates_pattern_in_string_list() {
        // When the key-list is a StringList, each pattern in it must be validated.
        let result = compile(
            b"require [\"regex\"]; if header :regex \"Subject\" [\"ok.*\", \"[invalid\"] { keep; }",
        );
        assert!(
            result.is_err(),
            "invalid regex in key StringList must fail at compile"
        );
    }

    // -----------------------------------------------------------------------
    // RFC 5229 variables extension tests
    // -----------------------------------------------------------------------

    #[test]
    fn eval_variables_set_and_fileinto() {
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set \"folder\" \"INBOX.Work\"; fileinto \"${folder}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("INBOX.Work".into())]);
    }

    #[test]
    fn eval_variables_modifier_lower() {
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set :lower \"folder\" \"INBOX.WORK\"; fileinto \"${folder}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("inbox.work".into())]);
    }

    #[test]
    fn eval_variables_modifier_upper() {
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set :upper \"folder\" \"inbox.work\"; fileinto \"${folder}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("INBOX.WORK".into())]);
    }

    #[test]
    fn eval_variables_modifier_length() {
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set :length \"len\" \"hello\"; fileinto \"${len}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("5".into())]);
    }

    #[test]
    fn eval_variables_modifier_firstline() {
        // The \n here is a real newline byte in the Sieve quoted string.
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set :firstline \"f\" \"line1\nline2\"; fileinto \"${f}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("line1".into())]);
    }

    #[test]
    fn eval_variables_case_insensitive_name() {
        let script = compile(
            b"require [\"variables\", \"fileinto\"]; set \"MyVar\" \"hello\"; fileinto \"${myvar}\";",
        )
        .unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::FileInto("hello".into())]);
    }

    #[test]
    fn eval_no_variables_require_no_substitution() {
        // Without require ["variables"], ${reason} is literal text (RFC 5229 §3).
        let script = compile(b"require [\"reject\"]; reject \"${reason}\";").unwrap();
        let actions = evaluate(&script, &make_msg("test"), "", "", &SieveEnv::new());
        assert_eq!(actions, vec![SieveAction::Reject("${reason}".into())]);
    }

    // -----------------------------------------------------------------------
    // RFC 5229 :matches capture variable tests (List-Id routing script)
    // -----------------------------------------------------------------------

    /// Default List-Id routing script routes a message with a `List-Id:` header
    /// to `List/<extracted-id>`.
    ///
    /// The script uses `header :matches` with `"*<*>*"` to capture the list
    /// identifier between `<` and `>`, then constructs the mailbox name via `${2}`.
    ///
    /// Test vector: `List-Id: <rust-users.lists.rust-lang.org>` routes to
    /// `List/rust-users.lists.rust-lang.org`.  The oracle for this test vector
    /// is the cross-validation suite in `tests/cross_validate.rs` which runs
    /// the same script through the `stoa-sieve` (sieve-rs) oracle.
    #[test]
    fn default_list_routing_script_routes_list_id_to_list_mailbox() {
        let script_src = br#"require ["fileinto", "variables"];

if header :matches "List-Id" "*<*>*" {
    set "list_id" "${2}";
    fileinto "List/${list_id}";
    stop;
}
"#;
        let script = compile(script_src).unwrap();
        let msg = b"From: sender@example.com\r\nList-Id: <rust-users.lists.rust-lang.org>\r\nSubject: test\r\n\r\nBody.\r\n";
        let actions = evaluate(&script, msg, "", "recip@example.com", &SieveEnv::new());
        assert_eq!(
            actions,
            vec![SieveAction::FileInto(
                "List/rust-users.lists.rust-lang.org".into()
            )],
            "message with List-Id must be routed to List/<list-id>"
        );
    }

    /// Default List-Id routing script falls through to implicit Keep (INBOX)
    /// when no `List-Id:` header is present.
    #[test]
    fn default_list_routing_script_no_list_id_keeps_to_inbox() {
        let script_src = br#"require ["fileinto", "variables"];

if header :matches "List-Id" "*<*>*" {
    set "list_id" "${2}";
    fileinto "List/${list_id}";
    stop;
}
"#;
        let script = compile(script_src).unwrap();
        let msg = b"From: sender@example.com\r\nSubject: regular message\r\n\r\nBody.\r\n";
        let actions = evaluate(&script, msg, "", "recip@example.com", &SieveEnv::new());
        assert_eq!(
            actions,
            vec![SieveAction::Keep],
            "message without List-Id must fall through to implicit Keep (INBOX)"
        );
    }

    /// `:matches` capture groups (`${1}`, `${2}`, ...) are set after a successful
    /// match when the `variables` extension is required (RFC 5229 §4).
    ///
    /// Pattern `"*<*>*"` has three `*` wildcards: ${1}=prefix, ${2}=inner,
    /// ${3}=suffix.  Direct use of `${2}` in `fileinto` (without an explicit
    /// `set`) must also work.
    #[test]
    fn matches_capture_variables_direct_use_in_fileinto() {
        let script_src = br#"require ["fileinto", "variables"];
if header :matches "List-Id" "*<*>*" {
    fileinto "List/${2}";
    stop;
}
"#;
        let script = compile(script_src).unwrap();
        let msg = b"From: sender@example.com\r\nList-Id: Test List <test.lists.example.com>\r\nSubject: test\r\n\r\nBody.\r\n";
        let actions = evaluate(&script, msg, "", "", &SieveEnv::new());
        assert_eq!(
            actions,
            vec![SieveAction::FileInto("List/test.lists.example.com".into())],
            "capture variable ${{2}} must contain the list-id between < and >"
        );
    }

    // -----------------------------------------------------------------------
    // RFC 5183 environment extension tests (issue stoa-p4oc4.7.1)
    // -----------------------------------------------------------------------

    /// RFC 5183 §4: unknown environment name → empty string → matches "".
    /// Oracle: RFC 5183 §4 "If the item does not exist, it matches the
    /// empty string."
    #[test]
    fn environment_unknown_name_returns_empty() {
        let script = compile(
            br#"require ["environment"]; if environment "x" "" { keep; } else { discard; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        // "x" is not set — should match the empty-string key-list value.
        // env has no "x", so environment "x" returns ""; "" :is "" → true
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::Keep],
            "unknown env name must match empty string (RFC 5183 §4)"
        );
        // Explicitly set "x" to a non-empty value — now it must NOT match "".
        env.set("x", "something");
        let actions2 = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions2,
            vec![SieveAction::Discard],
            "set env name must not match empty string when value is non-empty"
        );
    }

    /// environment test matches when the known name has the expected value.
    /// Oracle: RFC 5183 §4 grammar; known test vector.
    #[test]
    fn environment_known_name_matches() {
        let script = compile(
            br#"require ["fileinto","environment"]; if environment "vnd.stoa.dkim-result" "pass" { fileinto "Verified"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dkim-result", "pass");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::FileInto("Verified".into())],
            "environment test must match when value equals key"
        );
    }

    /// environment test does not match when the value differs.
    #[test]
    fn environment_known_name_no_match() {
        let script = compile(
            br#"require ["fileinto","environment"]; if environment "vnd.stoa.dkim-result" "pass" { fileinto "Verified"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dkim-result", "fail");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::Keep],
            "environment test must not match when value differs from key"
        );
    }

    /// environment test with a string-list key — matches any element in list.
    /// Oracle: RFC 5183 §4; RFC 5228 §2.7 key-list semantics.
    #[test]
    fn environment_list_match() {
        let script = compile(
            br#"require ["fileinto","environment"]; if environment "vnd.stoa.spf-result" ["fail","softfail"] { fileinto "Spam"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.spf-result", "softfail");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::FileInto("Spam".into())],
            "environment test must match any element in string-list key"
        );
    }

    /// environment test without require ["environment"] must fail at compile.
    /// Oracle: RFC 5228 §2.10.5; RFC 5183 §1.
    #[test]
    fn environment_requires_extension() {
        let result = compile(br#"if environment "vnd.stoa.dkim-result" "pass" { keep; }"#);
        assert!(
            result.is_err(),
            "environment test without require must fail at compile"
        );
    }

    /// :contains match type works for environment values.
    #[test]
    fn environment_contains_match() {
        let script = compile(
            br#"require ["fileinto","environment"]; if environment :contains "vnd.stoa.dkim-domain" "example" { fileinto "Known"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dkim-domain", "mail.example.com");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::FileInto("Known".into())],
            "environment :contains must work like header :contains"
        );
    }

    // -----------------------------------------------------------------------
    // RFC 5183 E2E scenarios (issue stoa-p4oc4.7.3)
    // Oracle: known SieveEnv inputs → known expected SieveAction outputs.
    // -----------------------------------------------------------------------

    /// Scenario 1: DKIM-passing mail filed into Verified by environment test.
    /// Oracle: SieveEnv vnd.stoa.dkim-result=pass → FileInto("Verified").
    #[test]
    fn sieve_environment_e2e_dkim_pass_fileinto_verified() {
        let script = compile(
            br#"require ["fileinto","environment"];
if environment "vnd.stoa.dkim-result" "pass" { fileinto "Verified"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dkim-result", "pass");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(actions, vec![SieveAction::FileInto("Verified".into())]);
    }

    /// Scenario 2: SPF softfail → FileInto("Spam").
    /// Oracle: SieveEnv vnd.stoa.spf-result=softfail → FileInto("Spam").
    #[test]
    fn sieve_environment_e2e_spf_fail_fileinto_spam() {
        let script = compile(
            br#"require ["fileinto","environment"];
if environment "vnd.stoa.spf-result" ["fail","softfail"] { fileinto "Spam"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.spf-result", "softfail");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(actions, vec![SieveAction::FileInto("Spam".into())]);
    }

    /// Scenario 3: DMARC policy=reject → Reject action.
    /// Oracle: SieveEnv vnd.stoa.dmarc-policy=reject → Reject.
    #[test]
    fn sieve_environment_e2e_dmarc_reject_policy_discard() {
        let script = compile(
            br#"require ["reject","environment"];
if environment "vnd.stoa.dmarc-policy" "reject" { reject "DMARC policy reject"; }"#,
        )
        .unwrap();
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dmarc-policy", "reject");
        let actions = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions,
            vec![SieveAction::Reject("DMARC policy reject".into())]
        );
    }

    /// Scenario 4: empty SieveEnv — unknown name matches "none" if set explicitly.
    /// Oracle: empty env → get("vnd.stoa.dkim-result") = "" (not "none");
    /// script testing :is "none" must NOT match the empty env case.
    /// Explicit env set "vnd.stoa.dkim-result"="none" DOES match.
    #[test]
    fn sieve_environment_e2e_no_dkim_defaults_to_empty_not_none() {
        let script = compile(
            br#"require ["fileinto","environment"];
if environment "vnd.stoa.dkim-result" "none" { fileinto "NoDKIM"; }"#,
        )
        .unwrap();

        // Empty SieveEnv: unknown name → "" which does NOT equal "none".
        let empty_env = SieveEnv::new();
        let actions = evaluate(&script, &make_msg("test"), "", "", &empty_env);
        assert_eq!(
            actions,
            vec![SieveAction::Keep],
            "empty env must return '' for unknown name, not 'none'"
        );

        // Explicitly set to "none": must match.
        let mut env = SieveEnv::new();
        env.set("vnd.stoa.dkim-result", "none");
        let actions2 = evaluate(&script, &make_msg("test"), "", "", &env);
        assert_eq!(
            actions2,
            vec![SieveAction::FileInto("NoDKIM".into())],
            "explicitly set 'none' value must match environment test"
        );
    }

    // ── depth limit ───────────────────────────────────────────────────────────

    /// A script with 33 nested `if` blocks (one above the 32-level limit) must
    /// be rejected with a depth error.  If the limit is not enforced, a
    /// malicious operator-uploaded script of sufficient depth would exhaust
    /// the thread stack during compile().
    #[test]
    fn deeply_nested_if_blocks_rejected() {
        // Build: if header :contains "X" "y" { if header ... { ... } }
        // repeated 33 times (MAX_VALIDATE_DEPTH + 1).
        const DEPTH: usize = 33;
        let mut script = String::new();
        for _ in 0..DEPTH {
            script.push_str(r#"if header :contains "Subject" "x" { "#);
        }
        script.push_str("keep;");
        for _ in 0..DEPTH {
            script.push_str(" }");
        }

        let result = compile(script.as_bytes());
        assert!(
            result.is_err(),
            "script with {DEPTH} nesting levels must be rejected; got {result:?}"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("nesting depth"),
            "error must mention nesting depth; got: {msg:?}"
        );
    }
}
