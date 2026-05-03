// SPDX-License-Identifier: MIT

/// A parse error with source location.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 && self.col == 0 {
            write!(f, "parse error: {}", self.message)
        } else {
            write!(
                f,
                "parse error at {}:{}: {}",
                self.line, self.col, self.message
            )
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for String {
    fn from(e: ParseError) -> String {
        e.to_string()
    }
}
