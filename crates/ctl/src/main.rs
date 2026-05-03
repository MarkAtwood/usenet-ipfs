//! stoa-ctl — operator CLI for stoa daemons.
//!
//! Talks to the admin HTTP endpoint so operators do not need to curl JSON
//! by hand. Point it at transit or reader; both speak the same base admin
//! protocol. Transit exposes additional endpoints (`peers`, `groups`,
//! `log-tip`) that reader does not.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "stoa-ctl",
    about = "Operator CLI for stoa transit and reader daemons"
)]
struct Args {
    /// Admin server address (host:port)
    #[arg(short = 'a', long = "addr", default_value = "127.0.0.1:9090")]
    addr: String,

    /// Bearer token for admin authentication
    #[arg(short = 't', long = "token", env = "STOA_CTL_TOKEN")]
    token: Option<String>,

    /// Output raw JSON instead of formatted text
    #[arg(short = 'j', long = "json")]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon health and statistics
    Status,
    /// Show daemon version
    Version,
    /// List known peers (transit only)
    Peers,
    /// List known groups (transit only)
    Groups,
    /// Show Merkle-CRDT log tip for a group (transit only)
    LogTip {
        /// Group name (e.g. comp.lang.rust)
        group: String,
    },
    /// Signal the daemon to reload its configuration
    Reload,
    /// Print Prometheus metrics
    Metrics,
}

struct AdminClient {
    base_url: String,
    token: Option<String>,
    // DECISION: stoa-ctl is a command-line tool with no concurrency needs. Using
    // reqwest::blocking avoids the overhead of spinning up a tokio runtime for a
    // single HTTP request. Project convention (CLAUDE.md) is async throughout for
    // daemons; CLIs are exempt when they make a single synchronous request.
    client: reqwest::blocking::Client,
}

impl AdminClient {
    fn new(addr: &str, token: Option<String>) -> Self {
        Self {
            base_url: format!("http://{addr}"),
            token,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn get(&self, path: &str) -> Result<String, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().map_err(|e| format!("connection error: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .unwrap_or_else(|e| format!("<body read error: {e}>"));
        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }
        Ok(body)
    }

    fn post(&self, path: &str) -> Result<String, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.post(&url).header("Content-Length", "0");
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().map_err(|e| format!("connection error: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .unwrap_or_else(|e| format!("<body read error: {e}>"));
        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }
        Ok(body)
    }
}

fn cmd_status(client: &AdminClient, json: bool) -> Result<(), String> {
    let health = client.get("/health")?;
    let stats = client.get("/stats")?;
    if json {
        let mut h: serde_json::Value = serde_json::from_str(&health).unwrap_or_default();
        let s: serde_json::Value = serde_json::from_str(&stats).unwrap_or_default();
        if let (Some(hm), Some(sm)) = (h.as_object_mut(), s.as_object()) {
            for (k, v) in sm {
                hm.insert(k.clone(), v.clone());
            }
        }
        println!("{}", serde_json::to_string_pretty(&h).unwrap_or(health));
        return Ok(());
    }
    let h: serde_json::Value = serde_json::from_str(&health).unwrap_or_default();
    let s: serde_json::Value = serde_json::from_str(&stats).unwrap_or_default();
    println!("Status:      {}", h["status"].as_str().unwrap_or("unknown"));
    println!(
        "Uptime:      {} secs",
        h["uptime_secs"].as_u64().unwrap_or(0)
    );
    println!("Articles:    {}", s["articles"].as_i64().unwrap_or(0));
    println!("Pinned CIDs: {}", s["pinned_cids"].as_i64().unwrap_or(0));
    println!("Groups:      {}", s["groups"].as_i64().unwrap_or(0));
    println!("Peers:       {}", s["peers"].as_i64().unwrap_or(0));
    Ok(())
}

fn cmd_version(client: &AdminClient, json: bool) -> Result<(), String> {
    let body = client.get("/version")?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    println!(
        "{} {}",
        v["binary"].as_str().unwrap_or("unknown"),
        v["version"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

fn cmd_peers(client: &AdminClient, json: bool) -> Result<(), String> {
    let body = client.get("/peers")?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let peers: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let arr = peers.as_array().map(Vec::as_slice).unwrap_or_default();
    if arr.is_empty() {
        println!("No peers.");
        return Ok(());
    }
    println!("{:<52} ADDRESS", "PEER ID");
    for peer in arr {
        let id = peer["peer_id"].as_str().unwrap_or("?");
        let addr = peer["addr"].as_str().unwrap_or("?");
        println!("{id:<52} {addr}");
    }
    Ok(())
}

fn cmd_groups(client: &AdminClient, json: bool) -> Result<(), String> {
    let body = client.get("/groups")?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let groups: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let arr = groups.as_array().map(Vec::as_slice).unwrap_or_default();
    if arr.is_empty() {
        println!("No groups.");
        return Ok(());
    }
    for g in arr {
        if let Some(name) = g.as_str() {
            println!("{name}");
        }
    }
    Ok(())
}

fn cmd_log_tip(client: &AdminClient, group: &str, json: bool) -> Result<(), String> {
    let path = format!("/log-tip?group={}", percent_encode(group));
    let body = client.get(&path)?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    println!("Group:       {}", v["group"].as_str().unwrap_or("?"));
    println!("Tip CID:     {}", v["tip_cid"].as_str().unwrap_or("?"));
    println!("Entry count: {}", v["entry_count"].as_i64().unwrap_or(0));
    Ok(())
}

fn cmd_reload(client: &AdminClient, json: bool) -> Result<(), String> {
    let body = client.post("/reload")?;
    if json {
        println!("{body}");
        return Ok(());
    }
    println!("Reloaded.");
    Ok(())
}

fn cmd_metrics(client: &AdminClient) -> Result<(), String> {
    let body = client.get("/metrics")?;
    print!("{body}");
    Ok(())
}

/// Percent-encode a string for use in a URL query parameter.
///
/// Characters in the RFC 3986 §2.3 unreserved set (ALPHA / DIGIT / `-` / `_`
/// / `.` / `~`) plus `+` (used in some newsgroup names) are passed through
/// unchanged.  All other bytes — including `#` (fragment delimiter), `?`
/// (query delimiter), and `/` (path delimiter) — are encoded as `%XX`.
/// RFC 3977 group names cannot contain `#` or `?`, but encoding them
/// unconditionally prevents URL-structure corruption if a malformed name is
/// passed.
///
/// Operating on bytes rather than Unicode scalar values ensures that
/// multi-byte UTF-8 sequences are encoded correctly (e.g. U+00E9 é →
/// `%C3%A9` rather than the incorrect single-byte `%E9`).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'+' => {
                out.push(byte as char);
            }
            b => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn main() {
    let args = Args::parse();
    let client = AdminClient::new(&args.addr, args.token);

    let result = match &args.command {
        Command::Status => cmd_status(&client, args.json),
        Command::Version => cmd_version(&client, args.json),
        Command::Peers => cmd_peers(&client, args.json),
        Command::Groups => cmd_groups(&client, args.json),
        Command::LogTip { group } => cmd_log_tip(&client, group, args.json),
        Command::Reload => cmd_reload(&client, args.json),
        Command::Metrics => cmd_metrics(&client),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_alphanumeric_unchanged() {
        assert_eq!(percent_encode("comp.lang.rust"), "comp.lang.rust");
    }

    #[test]
    fn percent_encode_spaces_and_slashes() {
        assert_eq!(percent_encode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn percent_encode_plus_is_preserved() {
        // '+' is valid in newsgroup names (e.g. alt.binaries+test) and must
        // not be encoded; transit's extract_query_param does not decode %2B.
        assert_eq!(percent_encode("alt.binaries+test"), "alt.binaries+test");
    }

    #[test]
    fn percent_encode_non_ascii_uses_utf8_bytes() {
        // U+00E9 (é) encodes as UTF-8 bytes 0xC3 0xA9, so the correct
        // percent-encoding is %C3%A9, not the incorrect single-byte %E9.
        assert_eq!(percent_encode("caf\u{00E9}"), "caf%C3%A9");
    }

    #[test]
    fn percent_encode_hash_and_query_are_encoded() {
        // '#' and '?' are URL-structure delimiters that must be encoded when
        // they appear inside a query-string value.  RFC 3977 group names
        // cannot contain these characters, but encoding them unconditionally
        // prevents URL-structure corruption if a malformed name is supplied.
        assert_eq!(percent_encode("a#b"), "a%23b");
        assert_eq!(percent_encode("a?b"), "a%3Fb");
    }
}
