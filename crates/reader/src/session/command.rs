/// RFC 3977 §3.1.3 — maximum line length including CRLF is 512 bytes.
/// `parse_command` receives a line with CRLF already stripped by the caller,
/// so the limit on the stripped content is 510 bytes (512 − 2).
const MAX_LINE_BYTES: usize = 510;

/// An article reference: either a message-ID, a local article number,
/// or a CID locator (the `cid:<cid-string>` form from ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArticleRef {
    MessageId(String),
    Number(u64),
    Cid(String),
}

/// An NNTP article number range as used by OVER/XOVER.
/// `From(n)` means article n and all higher; `Range(lo, hi)` is inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArticleRange {
    Single(u64),
    From(u64),
    Range(u64, u64),
}

/// LIST subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSubcommand {
    /// LIST ACTIVE [wildmat] — optional wildmat filter.
    Active(Option<String>),
    Newsgroups,
    OverviewFmt,
}

/// Key specifying what field to search in an NNTP SEARCH command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    Subject,
    From,
    Body,
    Text,
    Since,
    Before,
}

impl std::str::FromStr for SearchKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "SUBJECT" => Ok(Self::Subject),
            "FROM" => Ok(Self::From),
            "BODY" => Ok(Self::Body),
            "TEXT" => Ok(Self::Text),
            "SINCE" => Ok(Self::Since),
            "BEFORE" => Ok(Self::Before),
            _ => Err(()),
        }
    }
}

/// All RFC 3977 commands (plus standard additive extensions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Capabilities,
    ModeReader,
    Quit,
    List(ListSubcommand),
    /// NEWGROUPS yyyymmdd hhmmss [GMT]
    Newgroups {
        date: String,
        time: String,
    },
    /// NEWNEWS wildmat yyyymmdd hhmmss [GMT]
    Newnews {
        wildmat: String,
        date: String,
        time: String,
    },
    Group(String),
    Next,
    Last,
    Article(Option<ArticleRef>),
    Head(Option<ArticleRef>),
    Body(Option<ArticleRef>),
    Stat(Option<ArticleRef>),
    /// OVER/XOVER with optional range or message-id argument
    Over(Option<OverArg>),
    Post,
    Ihave(String),
    AuthinfoUser(String),
    AuthinfoPass(String),
    /// AUTHINFO SASL OAUTHBEARER <initial-response> — RFC 4643 §2.3 / RFC 7628.
    ///
    /// The initial response is the raw base64url string as received on the wire;
    /// lifecycle.rs decodes it and extracts the Bearer token.
    AuthinfoSaslOauthbearer(String),
    StartTls,
    /// XCID [<message-id>] — return the CID for the current or named article.
    /// Advertised as XCID in CAPABILITIES. Response: 290 <cid>.
    Xcid(Option<String>),
    /// XGET <cid> — fetch a raw IPFS block by CID and return it base64-encoded
    /// as a synthetic MIME message.
    /// Advertised as XGET in CAPABILITIES. Response: 290/430/501/403.
    Xget(String),
    /// XVERIFY <message-id> <expected-cid> [SIG] — verify stored CID matches
    /// expected-cid; optionally re-verify operator signature.
    /// Advertised as XVERIFY in CAPABILITIES. Response: 291/541/542.
    Xverify {
        message_id: String,
        expected_cid: String,
        verify_sig: bool,
    },
    /// HDR field-name [range|message-id] — return a single header field for
    /// one or more articles (RFC 3977 §8.5). Advertised as HDR in CAPABILITIES.
    /// Response: 225 Headers follow + lines + "."
    Hdr {
        field: String,
        range_or_msgid: Option<String>,
    },
    /// `SEARCH <key> <value>` — non-standard full-text search extension.
    /// Advertised in CAPABILITIES as "SEARCH". Requires GROUP context.
    Search {
        key: SearchKey,
        value: String,
    },
    /// Any unrecognized command, stored verbatim for logging/500 response.
    Unknown(String),
}

/// The argument to OVER/XOVER: either a range or a message-id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverArg {
    Range(ArticleRange),
    MessageId(String),
}

/// Errors from `parse_command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    LineTooLong,
    Unknown(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::LineTooLong => write!(f, "line exceeds 512-byte RFC 3977 limit"),
            ParseError::Unknown(cmd) => write!(f, "unknown command: {cmd}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a single NNTP command line.
///
/// The input may include a trailing CRLF or LF; it is stripped before parsing.
/// Command names are matched case-insensitively per RFC 3977 §3.1.
pub fn parse_command(line: &str) -> Result<Command, ParseError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ParseError::LineTooLong);
    }

    // Strip trailing CRLF or LF.
    let line = line.trim_end_matches(['\r', '\n']);

    let mut parts = line.splitn(2, [' ', '\t']);
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    let rest = parts.next().unwrap_or("").trim();

    match verb.as_str() {
        "CAPABILITIES" => Ok(Command::Capabilities),
        "QUIT" => Ok(Command::Quit),
        "NEXT" => Ok(Command::Next),
        "LAST" => Ok(Command::Last),
        "POST" => Ok(Command::Post),
        "STARTTLS" => Ok(Command::StartTls),

        "MODE" => match rest.to_ascii_uppercase().as_str() {
            "READER" => Ok(Command::ModeReader),
            _ => Ok(Command::Unknown(line.to_string())),
        },

        "LIST" => {
            let mut toks = rest.split_ascii_whitespace();
            let sub_upper = toks
                .next()
                .map(|s| s.to_ascii_uppercase())
                .unwrap_or_else(|| "ACTIVE".to_string());
            match sub_upper.as_str() {
                "ACTIVE" => Ok(Command::List(ListSubcommand::Active(
                    toks.next().map(str::to_string),
                ))),
                "" => Ok(Command::List(ListSubcommand::Active(None))),
                "NEWSGROUPS" => Ok(Command::List(ListSubcommand::Newsgroups)),
                "OVERVIEW.FMT" => Ok(Command::List(ListSubcommand::OverviewFmt)),
                _ => Ok(Command::Unknown(line.to_string())),
            }
        }

        "NEWGROUPS" => {
            let mut toks = rest.split_ascii_whitespace();
            let date = toks.next().unwrap_or("").to_string();
            let time = toks.next().unwrap_or("").to_string();
            Ok(Command::Newgroups { date, time })
        }

        "NEWNEWS" => {
            let mut toks = rest.splitn(3, char::is_whitespace);
            let wildmat = toks.next().unwrap_or("").to_string();
            let mut remainder = toks.next().unwrap_or("").to_string();
            if remainder.is_empty() {
                return Ok(Command::Newnews {
                    wildmat,
                    date: String::new(),
                    time: String::new(),
                });
            }
            // remainder may be "yyyymmdd" with time still in rest; re-split
            let mut date_time = rest.splitn(3, char::is_whitespace);
            date_time.next(); // wildmat
            let date = date_time.next().unwrap_or("").to_string();
            remainder = date_time.next().unwrap_or("").to_string();
            // strip optional "GMT" suffix
            let time = remainder
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            Ok(Command::Newnews {
                wildmat,
                date,
                time,
            })
        }

        "GROUP" => Ok(Command::Group(rest.to_string())),

        "ARTICLE" => Ok(Command::Article(parse_article_ref(rest))),
        "HEAD" => Ok(Command::Head(parse_article_ref(rest))),
        "BODY" => Ok(Command::Body(parse_article_ref(rest))),
        "STAT" => Ok(Command::Stat(parse_article_ref(rest))),

        "SEARCH" => {
            // Split on first whitespace: "SUBJECT foo bar" → key="SUBJECT", value="foo bar"
            let (key_str, value_str) = rest
                .split_once(|c: char| c.is_ascii_whitespace())
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or((rest.trim(), ""));

            let key = key_str
                .parse::<SearchKey>()
                .map_err(|_| ParseError::Unknown(format!("unknown search key: {key_str}")))?;

            if value_str.is_empty() {
                return Err(ParseError::Unknown(
                    "SEARCH requires a value argument".to_owned(),
                ));
            }

            Ok(Command::Search {
                key,
                value: value_str.to_owned(),
            })
        }

        "XCID" => {
            let arg = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            Ok(Command::Xcid(arg))
        }

        "XGET" => Ok(Command::Xget(rest.to_string())),

        "XVERIFY" => {
            let mut parts = rest.splitn(3, char::is_whitespace);
            let message_id = parts.next().unwrap_or("").to_string();
            let expected_cid = parts.next().unwrap_or("").to_string();
            let sig_token = parts.next().unwrap_or("").trim().to_ascii_uppercase();
            let verify_sig = sig_token == "SIG";
            Ok(Command::Xverify {
                message_id,
                expected_cid,
                verify_sig,
            })
        }

        "HDR" => {
            let mut toks = rest.splitn(2, char::is_whitespace);
            let field = toks.next().unwrap_or("").to_string();
            let range_or_msgid = toks
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            Ok(Command::Hdr {
                field,
                range_or_msgid,
            })
        }

        "OVER" | "XOVER" => {
            if rest.is_empty() {
                return Ok(Command::Over(None));
            }
            if rest.starts_with('<') {
                return Ok(Command::Over(Some(OverArg::MessageId(rest.to_string()))));
            }
            Ok(Command::Over(Some(OverArg::Range(parse_range(rest)))))
        }

        "IHAVE" => Ok(Command::Ihave(rest.to_string())),

        "AUTHINFO" => {
            let mut toks = rest.splitn(2, char::is_whitespace);
            let sub = toks.next().unwrap_or("").to_ascii_uppercase();
            let arg = toks.next().unwrap_or("").trim().to_string();
            match sub.as_str() {
                "USER" => Ok(Command::AuthinfoUser(arg)),
                "PASS" => Ok(Command::AuthinfoPass(arg)),
                "SASL" => {
                    // AUTHINFO SASL <mechanism> [<initial-response>]
                    let mut sasl_toks = arg.splitn(2, char::is_whitespace);
                    let mechanism = sasl_toks.next().unwrap_or("").to_ascii_uppercase();
                    let initial_response = sasl_toks.next().unwrap_or("").trim().to_string();
                    match mechanism.as_str() {
                        "OAUTHBEARER" => Ok(Command::AuthinfoSaslOauthbearer(initial_response)),
                        _ => Ok(Command::Unknown(line.to_string())),
                    }
                }
                _ => Ok(Command::Unknown(line.to_string())),
            }
        }

        "" => Err(ParseError::Unknown(String::new())),

        _ => Err(ParseError::Unknown(verb)),
    }
}

/// Parse an optional article reference (message-ID, number, or CID locator).
fn parse_article_ref(s: &str) -> Option<ArticleRef> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with('<') {
        return Some(ArticleRef::MessageId(s.to_string()));
    }
    if let Some(cid_str) = s.strip_prefix("cid:") {
        return Some(ArticleRef::Cid(cid_str.to_string()));
    }
    s.parse::<u64>().ok().map(ArticleRef::Number)
}

/// Parse an OVER/HDR range string: "n", "n-", or "n-m".
///
/// Public so that `lifecycle.rs` can reuse it for HDR range arguments.
pub fn parse_range_pub(s: &str) -> ArticleRange {
    parse_range(s)
}

/// Parse an OVER range string: "n", "n-", or "n-m".
fn parse_range(s: &str) -> ArticleRange {
    if let Some(dash_pos) = s.find('-') {
        let lo_str = &s[..dash_pos];
        let hi_str = &s[dash_pos + 1..];
        // Invalid token defaults to 0. Article 0 does not exist, so the
        // session will return 423 No Such Article, which is the correct
        // response for a malformed range.
        let lo = lo_str.parse::<u64>().unwrap_or(0);
        if hi_str.is_empty() {
            ArticleRange::From(lo)
        } else {
            let hi = hi_str.parse::<u64>().unwrap_or(lo);
            ArticleRange::Range(lo, hi)
        }
    } else {
        // Same rationale: 0 → 423 No Such Article.
        ArticleRange::Single(s.parse::<u64>().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CAPABILITIES ----

    #[test]
    fn parse_capabilities() {
        assert_eq!(parse_command("CAPABILITIES\r\n"), Ok(Command::Capabilities));
    }

    #[test]
    fn parse_capabilities_lowercase() {
        assert_eq!(parse_command("capabilities\r\n"), Ok(Command::Capabilities));
    }

    #[test]
    fn parse_capabilities_mixed_case() {
        assert_eq!(parse_command("CaPaBiLiTiEs\r\n"), Ok(Command::Capabilities));
    }

    // ---- QUIT ----

    #[test]
    fn parse_quit() {
        assert_eq!(parse_command("QUIT\r\n"), Ok(Command::Quit));
    }

    // ---- MODE READER ----

    #[test]
    fn parse_mode_reader() {
        assert_eq!(parse_command("MODE READER\r\n"), Ok(Command::ModeReader));
    }

    #[test]
    fn parse_mode_reader_lowercase() {
        assert_eq!(parse_command("mode reader\r\n"), Ok(Command::ModeReader));
    }

    // ---- LIST ----

    #[test]
    fn parse_list_no_arg_defaults_to_active() {
        assert_eq!(
            parse_command("LIST\r\n"),
            Ok(Command::List(ListSubcommand::Active(None)))
        );
    }

    #[test]
    fn parse_list_active() {
        assert_eq!(
            parse_command("LIST ACTIVE\r\n"),
            Ok(Command::List(ListSubcommand::Active(None)))
        );
    }

    #[test]
    fn parse_list_active_with_wildmat() {
        assert_eq!(
            parse_command("LIST ACTIVE comp.*\r\n"),
            Ok(Command::List(ListSubcommand::Active(Some("comp.*".to_string()))))
        );
    }

    #[test]
    fn parse_list_newsgroups() {
        assert_eq!(
            parse_command("LIST NEWSGROUPS\r\n"),
            Ok(Command::List(ListSubcommand::Newsgroups))
        );
    }

    #[test]
    fn parse_list_overview_fmt() {
        assert_eq!(
            parse_command("LIST OVERVIEW.FMT\r\n"),
            Ok(Command::List(ListSubcommand::OverviewFmt))
        );
    }

    // ---- NEWGROUPS ----

    #[test]
    fn parse_newgroups() {
        let cmd = parse_command("NEWGROUPS 20240101 000000\r\n").unwrap();
        assert_eq!(
            cmd,
            Command::Newgroups {
                date: "20240101".into(),
                time: "000000".into()
            }
        );
    }

    // ---- NEWNEWS ----

    #[test]
    fn parse_newnews() {
        let cmd = parse_command("NEWNEWS comp.lang.rust 20240101 000000\r\n").unwrap();
        assert_eq!(
            cmd,
            Command::Newnews {
                wildmat: "comp.lang.rust".into(),
                date: "20240101".into(),
                time: "000000".into(),
            }
        );
    }

    // ---- GROUP ----

    #[test]
    fn parse_group() {
        assert_eq!(
            parse_command("GROUP comp.lang.rust\r\n"),
            Ok(Command::Group("comp.lang.rust".into()))
        );
    }

    // ---- NEXT / LAST ----

    #[test]
    fn parse_next() {
        assert_eq!(parse_command("NEXT\r\n"), Ok(Command::Next));
    }

    #[test]
    fn parse_last() {
        assert_eq!(parse_command("LAST\r\n"), Ok(Command::Last));
    }

    // ---- ARTICLE / HEAD / BODY / STAT ----

    #[test]
    fn parse_article_no_arg() {
        assert_eq!(parse_command("ARTICLE\r\n"), Ok(Command::Article(None)));
    }

    #[test]
    fn parse_article_number() {
        assert_eq!(
            parse_command("ARTICLE 42\r\n"),
            Ok(Command::Article(Some(ArticleRef::Number(42))))
        );
    }

    #[test]
    fn parse_article_message_id() {
        assert_eq!(
            parse_command("ARTICLE <foo@bar>\r\n"),
            Ok(Command::Article(Some(ArticleRef::MessageId(
                "<foo@bar>".into()
            ))))
        );
    }

    #[test]
    fn parse_article_cid_locator() {
        let cid = "bafyreihtsj5m7rkyqkj64blmobrwkmbbkxsfyiaixuobo6m62mkggb3oay";
        assert_eq!(
            parse_command(&format!("ARTICLE cid:{cid}\r\n")),
            Ok(Command::Article(Some(ArticleRef::Cid(cid.to_string()))))
        );
    }

    #[test]
    fn parse_head_number() {
        assert_eq!(
            parse_command("HEAD 7\r\n"),
            Ok(Command::Head(Some(ArticleRef::Number(7))))
        );
    }

    #[test]
    fn parse_body_message_id() {
        assert_eq!(
            parse_command("BODY <test@example.com>\r\n"),
            Ok(Command::Body(Some(ArticleRef::MessageId(
                "<test@example.com>".into()
            ))))
        );
    }

    #[test]
    fn parse_stat_no_arg() {
        assert_eq!(parse_command("STAT\r\n"), Ok(Command::Stat(None)));
    }

    // ---- HDR ----

    #[test]
    fn parse_hdr_no_arg() {
        assert_eq!(
            parse_command("HDR Subject\r\n"),
            Ok(Command::Hdr {
                field: "Subject".into(),
                range_or_msgid: None,
            })
        );
    }

    #[test]
    fn parse_hdr_with_range() {
        assert_eq!(
            parse_command("HDR Subject 1-10\r\n"),
            Ok(Command::Hdr {
                field: "Subject".into(),
                range_or_msgid: Some("1-10".into()),
            })
        );
    }

    #[test]
    fn parse_hdr_with_message_id() {
        assert_eq!(
            parse_command("HDR Subject <foo@bar>\r\n"),
            Ok(Command::Hdr {
                field: "Subject".into(),
                range_or_msgid: Some("<foo@bar>".into()),
            })
        );
    }

    #[test]
    fn parse_hdr_lowercase_field() {
        assert_eq!(
            parse_command("hdr from\r\n"),
            Ok(Command::Hdr {
                field: "from".into(),
                range_or_msgid: None,
            })
        );
    }

    // ---- OVER / XOVER ----

    #[test]
    fn parse_over_no_arg() {
        assert_eq!(parse_command("OVER\r\n"), Ok(Command::Over(None)));
    }

    #[test]
    fn parse_over_single() {
        assert_eq!(
            parse_command("OVER 5\r\n"),
            Ok(Command::Over(Some(OverArg::Range(ArticleRange::Single(5)))))
        );
    }

    #[test]
    fn parse_over_range() {
        assert_eq!(
            parse_command("OVER 1-10\r\n"),
            Ok(Command::Over(Some(OverArg::Range(ArticleRange::Range(
                1, 10
            )))))
        );
    }

    #[test]
    fn parse_over_open_range() {
        assert_eq!(
            parse_command("OVER 100-\r\n"),
            Ok(Command::Over(Some(OverArg::Range(ArticleRange::From(100)))))
        );
    }

    #[test]
    fn parse_xover_same_as_over() {
        assert_eq!(
            parse_command("XOVER 1-5\r\n"),
            Ok(Command::Over(Some(OverArg::Range(ArticleRange::Range(
                1, 5
            )))))
        );
    }

    #[test]
    fn parse_over_message_id() {
        assert_eq!(
            parse_command("OVER <msg@host>\r\n"),
            Ok(Command::Over(Some(OverArg::MessageId("<msg@host>".into()))))
        );
    }

    // ---- POST / IHAVE ----

    #[test]
    fn parse_post() {
        assert_eq!(parse_command("POST\r\n"), Ok(Command::Post));
    }

    #[test]
    fn parse_ihave() {
        assert_eq!(
            parse_command("IHAVE <msg@host>\r\n"),
            Ok(Command::Ihave("<msg@host>".into()))
        );
    }

    // ---- AUTHINFO ----

    #[test]
    fn parse_authinfo_user() {
        assert_eq!(
            parse_command("AUTHINFO USER alice\r\n"),
            Ok(Command::AuthinfoUser("alice".into()))
        );
    }

    #[test]
    fn parse_authinfo_pass() {
        assert_eq!(
            parse_command("AUTHINFO PASS s3cr3t\r\n"),
            Ok(Command::AuthinfoPass("s3cr3t".into()))
        );
    }

    // ---- AUTHINFO SASL OAUTHBEARER ----

    #[test]
    fn parse_authinfo_sasl_oauthbearer_with_initial_response() {
        let b64 = "biwsAWF1dGg9QmVhcmVyIHRlc3R0b2tlbgEB";
        assert_eq!(
            parse_command(&format!("AUTHINFO SASL OAUTHBEARER {b64}\r\n")),
            Ok(Command::AuthinfoSaslOauthbearer(b64.into()))
        );
    }

    #[test]
    fn parse_authinfo_sasl_oauthbearer_no_initial_response() {
        assert_eq!(
            parse_command("AUTHINFO SASL OAUTHBEARER\r\n"),
            Ok(Command::AuthinfoSaslOauthbearer(String::new()))
        );
    }

    #[test]
    fn parse_authinfo_sasl_unknown_mechanism_is_unknown() {
        assert!(matches!(
            parse_command("AUTHINFO SASL GSSAPI ticket\r\n"),
            Ok(Command::Unknown(_))
        ));
    }

    #[test]
    fn parse_authinfo_sasl_oauthbearer_case_insensitive() {
        let b64 = "dGVzdA==";
        assert_eq!(
            parse_command(&format!("authinfo sasl oauthbearer {b64}\r\n")),
            Ok(Command::AuthinfoSaslOauthbearer(b64.into()))
        );
    }

    // ---- STARTTLS ----

    #[test]
    fn parse_starttls() {
        assert_eq!(parse_command("STARTTLS\r\n"), Ok(Command::StartTls));
    }

    // ---- XGET ----

    #[test]
    fn parse_xget_with_cid() {
        let cid = "bafyreihtsj5m7rkyqkj64blmobrwkmbbkxsfyiaixuobo6m62mkggb3oay";
        assert_eq!(
            parse_command(&format!("XGET {cid}\r\n")),
            Ok(Command::Xget(cid.to_string()))
        );
    }

    #[test]
    fn parse_xget_lowercase() {
        let cid = "bafyreihtsj5m7rkyqkj64blmobrwkmbbkxsfyiaixuobo6m62mkggb3oay";
        assert_eq!(
            parse_command(&format!("xget {cid}\r\n")),
            Ok(Command::Xget(cid.to_string()))
        );
    }

    // ---- Unknown / error cases ----

    #[test]
    fn parse_unknown_command() {
        let result = parse_command("FROBNICATE\r\n");
        assert_eq!(result, Err(ParseError::Unknown("FROBNICATE".into())));
    }

    #[test]
    fn parse_empty_line_is_unknown() {
        let result = parse_command("\r\n");
        assert!(matches!(result, Err(ParseError::Unknown(_))));
    }

    #[test]
    fn parse_line_too_long() {
        // 511 stripped bytes = 513 wire bytes (with CRLF): exceeds RFC 3977 §3.1 limit.
        let long: String = "A".repeat(511);
        let result = parse_command(&long);
        assert_eq!(result, Err(ParseError::LineTooLong));
    }

    #[test]
    fn parse_line_exactly_510_bytes_is_ok() {
        // RFC 3977 §3.1 allows 512 bytes including CRLF → 510 stripped content bytes.
        // parse_command receives a CRLF-stripped line, so 510 bytes must be accepted.
        let line = format!("QUIT{}", " ".repeat(506));
        assert_eq!(line.len(), 510);
        let result = parse_command(&line);
        assert_ne!(result, Err(ParseError::LineTooLong));
    }

    #[test]
    fn lf_only_stripped() {
        assert_eq!(parse_command("QUIT\n"), Ok(Command::Quit));
    }

    #[test]
    fn no_crlf_accepted() {
        assert_eq!(parse_command("QUIT"), Ok(Command::Quit));
    }
}

#[cfg(test)]
mod search_key_tests {
    use super::*;

    #[test]
    fn parse_search_subject() {
        let cmd = parse_command("SEARCH SUBJECT rust programming").unwrap();
        assert!(matches!(
            cmd,
            Command::Search {
                key: SearchKey::Subject,
                ref value
            } if value == "rust programming"
        ));
    }

    #[test]
    fn parse_search_body_single_word() {
        let cmd = parse_command("SEARCH BODY hello").unwrap();
        assert!(matches!(
            cmd,
            Command::Search {
                key: SearchKey::Body,
                ..
            }
        ));
    }

    #[test]
    fn parse_search_unknown_key_returns_error() {
        assert!(parse_command("SEARCH BADKEY value").is_err());
    }

    #[test]
    fn parse_search_missing_value_returns_error() {
        assert!(parse_command("SEARCH BODY").is_err());
    }

    #[test]
    fn search_key_case_insensitive() {
        assert_eq!("subject".parse::<SearchKey>(), Ok(SearchKey::Subject));
        assert_eq!("BODY".parse::<SearchKey>(), Ok(SearchKey::Body));
        assert_eq!("BADKEY".parse::<SearchKey>(), Err(()));
    }
}
