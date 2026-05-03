use std::fmt;

/// An NNTP response with a numeric code, a text message, and an optional
/// multi-line body.
///
/// `Display` formats as `"NNN text\r\n"` for single-line responses, or
/// `"NNN text\r\n<body lines>\r\n.\r\n"` for multi-line responses, per
/// RFC 3977 §3.2.
///
/// `multiline` must be `true` whenever the RFC requires a dot-terminated
/// body, including when that body is empty (e.g. LIST ACTIVE on a server
/// with no groups). Single-line responses leave it `false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub text: String,
    /// Multi-line body lines (without CRLF).
    pub body: Vec<String>,
    /// True iff the response uses dot-termination per RFC 3977 §3.2.
    pub multiline: bool,
}

impl Response {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
            body: vec![],
            multiline: false,
        }
    }

    fn new_multiline(code: u16, text: impl Into<String>, body: Vec<String>) -> Self {
        Self {
            code,
            text: text.into(),
            body,
            multiline: true,
        }
    }

    // --- RFC 3977 standard responses ---

    pub fn service_available_posting_allowed() -> Self {
        Self::new(200, "Service available, posting allowed")
    }
    pub fn service_available_posting_prohibited() -> Self {
        Self::new(201, "Service available, posting prohibited")
    }
    /// Returns a CAPABILITIES response with only the VERSION 2 line.
    /// Use `capabilities_with_ctx` to build the full list from session state.
    pub fn capabilities() -> Self {
        Self::new(101, "Capability list follows")
    }

    /// Returns a fully-populated CAPABILITIES response per RFC 3977 §5.2.
    ///
    /// `posting_allowed`: include `POST` capability.
    /// `auth_required`: include `AUTHINFO USER` capability.
    /// `starttls_available`: include `STARTTLS` capability (RFC 4642).
    /// `sasl_oauthbearer`: include `SASL OAUTHBEARER` capability (RFC 7628).
    ///
    /// When `starttls_available` is true the connection is plain-text and TLS
    /// cert/key are configured, so mid-session upgrade via STARTTLS is possible.
    /// After upgrade, `starttls_available` is false and `STARTTLS` is omitted.
    pub fn capabilities_with_ctx(
        posting_allowed: bool,
        auth_required: bool,
        starttls_available: bool,
        sasl_oauthbearer: bool,
        search_available: bool,
    ) -> Self {
        let mut caps = vec![
            "VERSION 2".to_string(),
            "READER".to_string(),
            "OVER".to_string(),
            "HDR".to_string(),
            "LIST ACTIVE NEWSGROUPS".to_string(),
            // CID extension capabilities (ADR-0007)
            "XCID".to_string(),
            "XVERIFY".to_string(),
            "XGET".to_string(),
            "X-CID-LOCATOR".to_string(),
            // DID signature verification header extension
            "X-USENET-IPFS-DID-VERIFIED".to_string(),
        ];
        if search_available {
            caps.push("SEARCH".to_string());
        }
        if starttls_available {
            caps.push("STARTTLS".to_string());
        }
        if posting_allowed {
            caps.push("POST".to_string());
        }
        if auth_required {
            caps.push("AUTHINFO USER".to_string());
        }
        if sasl_oauthbearer {
            caps.push("SASL OAUTHBEARER".to_string());
        }
        Self::new_multiline(101, "Capability list follows", caps)
    }

    /// RFC 4642 §2: server acknowledges STARTTLS, client should begin TLS handshake.
    pub fn starttls_ready() -> Self {
        Self::new(382, "Continue with TLS negotiation")
    }
    pub fn closing_connection() -> Self {
        Self::new(205, "Closing connection")
    }
    pub fn group_selected(group: &str, count: u64, low: u64, high: u64) -> Self {
        Self::new(211, format!("{count} {low} {high} {group}"))
    }
    pub fn information_follows() -> Self {
        Self::new(215, "Information follows")
    }
    pub fn list_active(body: Vec<String>) -> Self {
        Self::new_multiline(215, "list of newsgroups follows", body)
    }
    pub fn list_newsgroups(body: Vec<String>) -> Self {
        Self::new_multiline(215, "descriptions of newsgroups follow", body)
    }
    pub fn newgroups(body: Vec<String>) -> Self {
        Self::new_multiline(231, "list of new newsgroups follows", body)
    }
    pub fn newnews(body: Vec<String>) -> Self {
        Self::new_multiline(230, "list of new articles follows", body)
    }
    pub fn article_exists(number: u64, msgid: &str) -> Self {
        Self::new(223, format!("{number} {msgid} Article exists"))
    }
    pub fn article_follows() -> Self {
        Self::new(220, "Article follows")
    }
    pub fn headers_follow() -> Self {
        Self::new(221, "Headers follow")
    }
    pub fn body_follows() -> Self {
        Self::new(222, "Body follows")
    }
    pub fn overview_follows() -> Self {
        Self::new(224, "Overview info follows")
    }
    pub fn hdr_follows(body: Vec<String>) -> Self {
        Self::new_multiline(225, "headers follow", body)
    }
    pub fn xhdr_follows(body: Vec<String>) -> Self {
        Self::new_multiline(221, "Headers follow", body)
    }
    pub fn list_overview_fmt(body: Vec<String>) -> Self {
        Self::new_multiline(215, "Order of fields in overview database.", body)
    }
    pub fn authentication_accepted() -> Self {
        Self::new(281, "Authentication accepted")
    }
    pub fn send_article() -> Self {
        Self::new(340, "Send article to be posted")
    }
    pub fn enter_password() -> Self {
        Self::new(381, "Enter password")
    }
    pub fn service_unavailable() -> Self {
        Self::new(400, "Service temporarily unavailable")
    }
    pub fn no_such_newsgroup() -> Self {
        Self::new(411, "No such newsgroup")
    }
    pub fn no_newsgroup_selected() -> Self {
        Self::new(412, "No newsgroup selected")
    }
    pub fn current_article_invalid() -> Self {
        Self::new(420, "Current article number is invalid")
    }
    pub fn no_next_article() -> Self {
        Self::new(421, "No next article")
    }
    pub fn no_previous_article() -> Self {
        Self::new(422, "No previous article")
    }
    pub fn no_article_with_number() -> Self {
        Self::new(423, "No article with that number")
    }
    pub fn no_article_with_message_id() -> Self {
        Self::new(430, "No article with that message-ID")
    }
    pub fn article_not_wanted() -> Self {
        Self::new(435, "Article not wanted")
    }
    pub fn transfer_not_possible() -> Self {
        Self::new(436, "Transfer not possible")
    }
    pub fn posting_not_permitted() -> Self {
        Self::new(440, "Posting not permitted")
    }
    pub fn posting_failed() -> Self {
        Self::new(441, "Posting failed")
    }
    pub fn authentication_required() -> Self {
        Self::new(480, "Authentication required")
    }
    pub fn authentication_failed() -> Self {
        Self::new(481, "Authentication failed")
    }
    pub fn authentication_out_of_sequence() -> Self {
        Self::new(482, "Authentication commands issued out of sequence")
    }
    pub fn unknown_command() -> Self {
        Self::new(500, "Unknown command")
    }
    pub fn syntax_error() -> Self {
        Self::new(501, "Syntax error in command")
    }
    pub fn command_unavailable() -> Self {
        Self::new(502, "Command unavailable")
    }
    pub fn program_fault() -> Self {
        Self::new(503, "Program fault")
    }
}

/// Serialize the response to wire bytes without materialising an intermediate String.
///
/// Pre-allocates a `Vec<u8>` sized to the approximate response length and
/// writes each component with `extend_from_slice`, avoiding the per-`write!`
/// overhead of the `Display` path.  For OVER responses with thousands of body
/// lines this is meaningfully faster than `to_string().into_bytes()`.
impl Response {
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = 6
            + self.text.len()
            + 2
            + self.body.iter().map(|l| l.len() + 2).sum::<usize>()
            + if self.multiline { 3 } else { 0 };
        let mut out = Vec::with_capacity(capacity);
        // Status line: "NNN text\r\n"
        let code_str = self.code.to_string();
        out.extend_from_slice(code_str.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.text.as_bytes());
        out.extend_from_slice(b"\r\n");
        for line in &self.body {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if self.multiline {
            out.extend_from_slice(b".\r\n");
        }
        out
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}\r\n", self.code, self.text)?;
        for line in &self.body {
            write!(f, "{line}\r\n")?;
        }
        if self.multiline {
            write!(f, ".\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_with_crlf() {
        let r = Response::new(200, "Service available, posting allowed");
        assert_eq!(r.to_string(), "200 Service available, posting allowed\r\n");
    }

    #[test]
    fn group_selected_format() {
        let r = Response::group_selected("comp.lang.rust", 42, 1, 42);
        assert_eq!(r.to_string(), "211 42 1 42 comp.lang.rust\r\n");
    }

    #[test]
    fn capabilities_with_ctx_code_is_101() {
        assert_eq!(
            Response::capabilities_with_ctx(true, false, false, false, false).code,
            101
        );
        assert_eq!(
            Response::capabilities_with_ctx(false, true, false, false, false).code,
            101
        );
    }

    #[test]
    fn capabilities_with_ctx_multiline_display() {
        let r = Response::capabilities_with_ctx(false, false, false, false, false);
        let s = r.to_string();
        assert!(s.starts_with("101 Capability list follows\r\n"));
        assert!(s.contains("VERSION 2\r\n"));
        assert!(s.ends_with(".\r\n"));
    }

    #[test]
    fn capabilities_omits_starttls_when_not_available() {
        // STARTTLS not advertised when starttls_available=false.
        let r = Response::capabilities_with_ctx(false, false, false, false, false);
        assert!(
            !r.body.iter().any(|l| l == "STARTTLS"),
            "STARTTLS must not appear in CAPABILITIES when not available"
        );
    }

    #[test]
    fn capabilities_includes_starttls_when_available() {
        let r = Response::capabilities_with_ctx(false, false, true, false, false);
        assert!(
            r.body.iter().any(|l| l == "STARTTLS"),
            "STARTTLS must appear in CAPABILITIES when available"
        );
    }

    #[test]
    fn starttls_ready_is_382() {
        assert_eq!(Response::starttls_ready().code, 382);
    }

    #[test]
    fn capabilities_includes_did_verified_extension() {
        let r = Response::capabilities_with_ctx(false, false, false, false, false);
        assert!(
            r.body.iter().any(|l| l == "X-USENET-IPFS-DID-VERIFIED"),
            "X-USENET-IPFS-DID-VERIFIED must appear in CAPABILITIES"
        );
    }

    #[test]
    fn capabilities_includes_sasl_oauthbearer_when_configured() {
        let r = Response::capabilities_with_ctx(false, false, false, true, false);
        assert!(
            r.body.iter().any(|l| l == "SASL OAUTHBEARER"),
            "SASL OAUTHBEARER must appear in CAPABILITIES when configured"
        );
    }

    #[test]
    fn capabilities_omits_sasl_oauthbearer_when_not_configured() {
        let r = Response::capabilities_with_ctx(false, false, false, false, false);
        assert!(
            !r.body.iter().any(|l| l == "SASL OAUTHBEARER"),
            "SASL OAUTHBEARER must not appear in CAPABILITIES when not configured"
        );
    }

    #[test]
    fn capabilities_includes_search_when_available() {
        let r = Response::capabilities_with_ctx(false, false, false, false, true);
        assert!(
            r.body.iter().any(|l| l == "SEARCH"),
            "SEARCH must appear in CAPABILITIES when search_available=true"
        );
    }

    #[test]
    fn capabilities_omits_search_when_not_available() {
        let r = Response::capabilities_with_ctx(false, false, false, false, false);
        assert!(
            !r.body.iter().any(|l| l == "SEARCH"),
            "SEARCH must not appear in CAPABILITIES when search_available=false"
        );
    }

    #[test]
    fn all_constructor_codes() {
        assert_eq!(Response::service_available_posting_allowed().code, 200);
        assert_eq!(Response::service_available_posting_prohibited().code, 201);
        assert_eq!(Response::closing_connection().code, 205);
        assert_eq!(Response::information_follows().code, 215);
        assert_eq!(Response::article_exists(1, "<x@y>").code, 223);
        assert_eq!(Response::article_follows().code, 220);
        assert_eq!(Response::headers_follow().code, 221);
        assert_eq!(Response::body_follows().code, 222);
        assert_eq!(Response::overview_follows().code, 224);
        assert_eq!(Response::authentication_accepted().code, 281);
        assert_eq!(Response::send_article().code, 340);
        assert_eq!(Response::enter_password().code, 381);
        assert_eq!(Response::service_unavailable().code, 400);
        assert_eq!(Response::no_such_newsgroup().code, 411);
        assert_eq!(Response::no_newsgroup_selected().code, 412);
        assert_eq!(Response::current_article_invalid().code, 420);
        assert_eq!(Response::no_next_article().code, 421);
        assert_eq!(Response::no_previous_article().code, 422);
        assert_eq!(Response::no_article_with_number().code, 423);
        assert_eq!(Response::no_article_with_message_id().code, 430);
        assert_eq!(Response::article_not_wanted().code, 435);
        assert_eq!(Response::transfer_not_possible().code, 436);
        assert_eq!(Response::posting_not_permitted().code, 440);
        assert_eq!(Response::posting_failed().code, 441);
        assert_eq!(Response::authentication_required().code, 480);
        assert_eq!(Response::authentication_failed().code, 481);
        assert_eq!(Response::authentication_out_of_sequence().code, 482);
        assert_eq!(Response::unknown_command().code, 500);
        assert_eq!(Response::syntax_error().code, 501);
        assert_eq!(Response::command_unavailable().code, 502);
        assert_eq!(Response::program_fault().code, 503);
    }
}
