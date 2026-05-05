// SPDX-License-Identifier: MIT

//! Form reader: converts a flat token stream into a uniform form-based
//! representation of a Sieve script (RFC 5228).
//!
//! This layer intentionally does *not* perform semantic analysis — it simply
//! groups tokens into nested forms.  A higher layer (the evaluator) is
//! responsible for interpreting the forms.
//!
//! ## Source location in [`ParseError`]
//!
//! [`ParseError`] has `line` and `col` fields, but this module always sets
//! them to `0`.  [`Token`] carries no source position — the lexer discards
//! location data after categorising each token.  Fixing this would require
//! changing `Token` to a `(Token, line, col)` tuple throughout the lexer and
//! all parser functions.  Until that refactor happens, structural parse errors
//! report location `(0, 0)`.

use crate::lexer::Token;
use crate::parse_error::ParseError;

/// A single form: a uniform, recursive representation of one syntactic element.
#[derive(Debug, Clone)]
pub enum Form {
    /// An identifier keyword.
    Word(String),
    /// A tagged argument (`:name`), colon already stripped.
    Tag(String),
    /// A string literal (quoted or multiline).
    Str(String),
    /// A numeric literal.
    Num(u64),
    /// A bracketed string list: `["a", "b"]`.
    StringList(Vec<String>),
    /// A parenthesised test list: `(test1, test2)`.
    TestList(Vec<Stmt>),
    /// A braced command block: `{ stmt; stmt; }`.
    Block(Vec<Stmt>),
}

/// A statement is a sequence of forms terminated by a semicolon or a block.
pub type Stmt = Vec<Form>;

/// A script is a sequence of statements.
pub type Script = Vec<Stmt>;

/// Parse a flat token slice into a [`Script`].
///
/// # Errors
///
/// Returns [`ParseError`] on any structural error: unclosed brackets, unexpected
/// tokens, or token exhaustion mid-statement.
pub fn read_script(tokens: &[Token]) -> Result<Script, ParseError> {
    let mut pos = 0usize;
    let mut script = Script::new();
    while pos < tokens.len() {
        // Skip lone semicolons (empty statements).
        if tokens[pos] == Token::Semicolon {
            pos += 1;
            continue;
        }
        let (stmt, new_pos) = read_stmt(tokens, pos)?;
        pos = new_pos;
        if !stmt.is_empty() {
            script.push(stmt);
        }
    }
    Ok(script)
}

/// Read one statement starting at `pos`.
///
/// Returns `(stmt, new_pos)` where `new_pos` is the index of the first token
/// after this statement.
fn read_stmt(tokens: &[Token], start: usize) -> Result<(Stmt, usize), ParseError> {
    let mut stmt = Stmt::new();
    let mut pos = start;

    loop {
        if pos >= tokens.len() {
            // End of token stream with an open statement.
            if stmt.is_empty() {
                return Ok((stmt, pos));
            }
            return Err(ParseError {
                message: "unexpected end of input in statement (missing ';'?)".to_string(),
                // line/col unavailable: Token carries no source position; see module doc.
                line: 0,
                col: 0,
            });
        }

        match &tokens[pos] {
            Token::Semicolon => {
                pos += 1;
                return Ok((stmt, pos));
            }

            Token::Word(s) => {
                stmt.push(Form::Word(s.clone()));
                pos += 1;
            }

            Token::Tag(s) => {
                stmt.push(Form::Tag(s.clone()));
                pos += 1;
            }

            Token::StringLit(s) => {
                stmt.push(Form::Str(s.clone()));
                pos += 1;
            }

            Token::Number(n) => {
                stmt.push(Form::Num(*n));
                pos += 1;
            }

            Token::LBracket => {
                pos += 1; // consume '['
                let (list, new_pos) = read_string_list(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::StringList(list));
            }

            Token::LParen => {
                pos += 1; // consume '('
                let (test_list, new_pos) = read_test_list(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::TestList(test_list));
            }

            Token::LBrace => {
                pos += 1; // consume '{'
                let (block, new_pos) = read_block(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::Block(block));
                // After a block, absorb any trailing `elsif`/`else` clauses
                // into the same statement so the evaluator sees the full
                // if/elsif/else chain as one unit (RFC 5228 §3.1).
                loop {
                    match tokens.get(pos) {
                        Some(Token::Word(w)) if w == "elsif" || w == "else" => {
                            // Pull the keyword and everything up to (and including)
                            // the next Block into the same statement.
                            stmt.push(Form::Word(w.clone()));
                            pos += 1;
                            // Consume any forms between the keyword and the next block.
                            while pos < tokens.len() {
                                match &tokens[pos] {
                                    Token::LBrace => {
                                        pos += 1;
                                        let (inner_block, new_pos2) = read_block(tokens, pos)?;
                                        pos = new_pos2;
                                        stmt.push(Form::Block(inner_block));
                                        break; // inner block consumed; check for another elsif/else
                                    }
                                    Token::Word(s) => {
                                        stmt.push(Form::Word(s.clone()));
                                        pos += 1;
                                    }
                                    Token::Tag(s) => {
                                        stmt.push(Form::Tag(s.clone()));
                                        pos += 1;
                                    }
                                    Token::StringLit(s) => {
                                        stmt.push(Form::Str(s.clone()));
                                        pos += 1;
                                    }
                                    Token::Number(n) => {
                                        stmt.push(Form::Num(*n));
                                        pos += 1;
                                    }
                                    Token::LBracket => {
                                        pos += 1;
                                        let (list, new_pos2) = read_string_list(tokens, pos)?;
                                        pos = new_pos2;
                                        stmt.push(Form::StringList(list));
                                    }
                                    Token::LParen => {
                                        pos += 1;
                                        let (test_list, new_pos2) = read_test_list(tokens, pos)?;
                                        pos = new_pos2;
                                        stmt.push(Form::TestList(test_list));
                                    }
                                    _ => break,
                                }
                            }
                        }
                        _ => break, // no trailing clause; terminate the statement
                    }
                }
                return Ok((stmt, pos));
            }

            Token::Comma => {
                return Err(ParseError {
                    message: "unexpected ',' outside string list or test list".to_string(),
                    line: 0,
                    col: 0,
                });
            }

            Token::RBracket | Token::RParen | Token::RBrace => {
                // Closing delimiters are handled by the caller; reaching one here
                // means a mismatched or unexpected closer.
                return Err(ParseError {
                    message: format!(
                        "unexpected closing delimiter '{}'",
                        token_char(&tokens[pos])
                    ),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

/// Read a bracketed string list starting *after* the `[`.
///
/// Returns `(strings, pos_after_rbracket)`.
fn read_string_list(tokens: &[Token], start: usize) -> Result<(Vec<String>, usize), ParseError> {
    let mut list: Vec<String> = Vec::new();
    let mut pos = start;
    let mut expect_comma = false;

    loop {
        if pos >= tokens.len() {
            return Err(ParseError {
                message: "unclosed '[' in string list".to_string(),
                line: 0,
                col: 0,
            });
        }

        match &tokens[pos] {
            Token::RBracket => {
                pos += 1;
                return Ok((list, pos));
            }

            Token::Comma => {
                if !expect_comma {
                    return Err(ParseError {
                        message: "unexpected ',' in string list".to_string(),
                        line: 0,
                        col: 0,
                    });
                }
                expect_comma = false;
                pos += 1;
            }

            Token::StringLit(s) => {
                if expect_comma {
                    return Err(ParseError {
                        message: "expected ',' between string list elements".to_string(),
                        line: 0,
                        col: 0,
                    });
                }
                list.push(s.clone());
                expect_comma = true;
                pos += 1;
            }

            other => {
                return Err(ParseError {
                    message: format!(
                        "non-string token {:?} inside string list",
                        token_char(other)
                    ),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

/// Read a parenthesised test list starting *after* the `(`.
///
/// Tests are separated by commas; no semicolons.
/// Returns `(test_stmts, pos_after_rparen)`.
fn read_test_list(tokens: &[Token], start: usize) -> Result<(Vec<Stmt>, usize), ParseError> {
    let mut tests: Vec<Stmt> = Vec::new();
    let mut pos = start;

    loop {
        if pos >= tokens.len() {
            return Err(ParseError {
                message: "unclosed '(' in test list".to_string(),
                line: 0,
                col: 0,
            });
        }

        if tokens[pos] == Token::RParen {
            pos += 1;
            return Ok((tests, pos));
        }

        // Read one test: forms up to the next ',' or ')'.
        let (test_stmt, new_pos) = read_test_stmt(tokens, pos)?;
        pos = new_pos;
        tests.push(test_stmt);

        // After a test, expect ',' or ')'.
        if pos >= tokens.len() {
            return Err(ParseError {
                message: "unclosed '(' in test list".to_string(),
                line: 0,
                col: 0,
            });
        }
        match &tokens[pos] {
            Token::Comma => {
                pos += 1; // consume comma, loop for next test
            }
            Token::RParen => {
                pos += 1;
                return Ok((tests, pos));
            }
            _ => {
                return Err(ParseError {
                    message: "expected ',' or ')' after test in test list".to_string(),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

/// Read one test expression (a stmt without semicolons) within a test list.
///
/// Stops at `,` or `)` without consuming them.
fn read_test_stmt(tokens: &[Token], start: usize) -> Result<(Stmt, usize), ParseError> {
    let mut stmt = Stmt::new();
    let mut pos = start;

    loop {
        if pos >= tokens.len() {
            if stmt.is_empty() {
                return Ok((stmt, pos));
            }
            return Err(ParseError {
                message: "unexpected end of input in test expression".to_string(),
                line: 0,
                col: 0,
            });
        }

        match &tokens[pos] {
            // These terminators belong to the test list, not the test itself.
            Token::Comma | Token::RParen => {
                return Ok((stmt, pos));
            }

            Token::Word(s) => {
                stmt.push(Form::Word(s.clone()));
                pos += 1;
            }
            Token::Tag(s) => {
                stmt.push(Form::Tag(s.clone()));
                pos += 1;
            }
            Token::StringLit(s) => {
                stmt.push(Form::Str(s.clone()));
                pos += 1;
            }
            Token::Number(n) => {
                stmt.push(Form::Num(*n));
                pos += 1;
            }
            Token::LBracket => {
                pos += 1;
                let (list, new_pos) = read_string_list(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::StringList(list));
            }
            Token::LParen => {
                pos += 1;
                let (test_list, new_pos) = read_test_list(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::TestList(test_list));
            }
            Token::LBrace => {
                pos += 1;
                let (block, new_pos) = read_block(tokens, pos)?;
                pos = new_pos;
                stmt.push(Form::Block(block));
                return Ok((stmt, pos));
            }
            Token::Semicolon => {
                return Err(ParseError {
                    message: "unexpected ';' inside test list".to_string(),
                    line: 0,
                    col: 0,
                });
            }
            Token::RBracket | Token::RBrace => {
                return Err(ParseError {
                    message: format!(
                        "unexpected closing delimiter '{}' inside test expression",
                        token_char(&tokens[pos])
                    ),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

/// Read a block of statements starting *after* the `{`.
///
/// Returns `(stmts, pos_after_rbrace)`.
fn read_block(tokens: &[Token], start: usize) -> Result<(Vec<Stmt>, usize), ParseError> {
    let mut stmts: Vec<Stmt> = Vec::new();
    let mut pos = start;

    loop {
        if pos >= tokens.len() {
            return Err(ParseError {
                message: "unclosed '{' — missing '}'".to_string(),
                line: 0,
                col: 0,
            });
        }

        if tokens[pos] == Token::RBrace {
            pos += 1;
            return Ok((stmts, pos));
        }

        // Skip empty statements.
        if tokens[pos] == Token::Semicolon {
            pos += 1;
            continue;
        }

        let (stmt, new_pos) = read_stmt(tokens, pos)?;
        pos = new_pos;
        if !stmt.is_empty() {
            stmts.push(stmt);
        }
    }
}

/// Return a single-character label for a token (used in error messages).
fn token_char(t: &Token) -> char {
    match t {
        Token::LBracket => '[',
        Token::RBracket => ']',
        Token::LParen => '(',
        Token::RParen => ')',
        Token::LBrace => '{',
        Token::RBrace => '}',
        Token::Semicolon => ';',
        Token::Comma => ',',
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    /// Structural parse errors must report location (0, 0) because `Token`
    /// carries no source position.  This test pins that contract so that if
    /// the lexer is ever extended to carry positions, the authors know to
    /// plumb them through the form parser too.
    #[test]
    fn structural_parse_error_location_is_zero() {
        // An unclosed block triggers a structural error deep in read_block.
        let tokens = tokenize("if true {").expect("tokenize");
        let err = read_script(&tokens).expect_err("unclosed block should fail");
        assert_eq!(
            err.line, 0,
            "line must be 0 — Token carries no source position"
        );
        assert_eq!(
            err.col, 0,
            "col must be 0 — Token carries no source position"
        );
    }
}
