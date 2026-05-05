//! Regression tests for config-reload correctness (stoa-bt-buvw).
//!
//! Oracle: `ReloadableState::do_reload` must:
//! 1. Return an error and leave state unchanged when the config file has a
//!    syntax error.
//! 2. Apply `groups.names` changes to the live `group_filter`.
//! 3. Apply `peering.trusted_peers` changes to the live `trusted_keys`.
//! 4. Detect `log.level` changes but report them as requiring a restart
//!    (they cannot be applied at runtime without a `tracing_subscriber::reload`
//!    handle, which is not yet wired).
//!
//! Each test creates a real temp file on disk so that `Config::from_file`
//! exercises its full validation path.

use ed25519_dalek::SigningKey;
use std::io::Write as _;
use stoa_transit::reload::ReloadableState;
use tempfile::NamedTempFile;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a complete, minimal, valid config TOML with the given parameters.
fn make_toml(groups: &[&str], trusted_peers: &[&str], log_level: &str) -> String {
    let groups_inline = groups
        .iter()
        .map(|g| format!("\"{g}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let peers_inline = trusted_peers
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = [{groups_inline}]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30

[peering]
trusted_peers = [{peers_inline}]

[log]
level = "{log_level}"
"#
    )
}

fn write_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f
}

fn rewrite_config(f: &NamedTempFile, content: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(f.path())
        .expect("reopen");
    file.write_all(content.as_bytes()).expect("rewrite");
}

/// Return the ed25519 public key for seed bytes `[byte; 32]` as `ed25519:<hex>`.
fn trusted_key_hex(byte: u8) -> String {
    let sk = SigningKey::from_bytes(&[byte; 32]);
    let vk = sk.verifying_key();
    format!("ed25519:{}", hex::encode(vk.as_bytes()))
}

// ── test 1: parse error leaves state unchanged ────────────────────────────────

/// When the config file contains invalid TOML, `do_reload` must return the
/// parse error in `errors`, leave `changed` empty, and not mutate any live
/// state.
#[tokio::test]
async fn reload_parse_error_leaves_state_unchanged() {
    let bad_file = write_config("this is NOT valid toml ][[[");
    let rs = ReloadableState::new(
        Some(bad_file.path().to_path_buf()),
        None,
        vec![],
        vec!["comp.test".to_string()],
        vec![],
        "info".to_string(),
    );

    let result = rs.do_reload().await;

    assert!(
        result.changed.is_empty(),
        "parse error: changed must be empty, got: {:?}",
        result.changed
    );
    assert!(
        !result.errors.is_empty(),
        "parse error: errors must be non-empty"
    );
    assert!(
        result.errors[0].contains("config parse error"),
        "error must mention 'config parse error', got: {:?}",
        result.errors[0]
    );
    assert!(
        rs.group_filter.read().await.is_none(),
        "group_filter must remain unchanged after parse error"
    );
    assert!(
        rs.trusted_keys.read().await.is_empty(),
        "trusted_keys must remain unchanged after parse error"
    );
}

// ── test 2: groups.names change applied ───────────────────────────────────────

/// When `groups.names` changes, `do_reload` must update the live `group_filter`
/// and record `"groups.names"` in `changed`.
#[tokio::test]
async fn reload_groups_names_applied() {
    let f = write_config(&make_toml(&["comp.test"], &[], "info"));

    let rs = ReloadableState::new(
        Some(f.path().to_path_buf()),
        None,
        vec![],
        vec!["comp.test".to_string()],
        vec![],
        "info".to_string(),
    );

    rewrite_config(&f, &make_toml(&["comp.lang.rust", "alt.test"], &[], "info"));

    let result = rs.do_reload().await;

    assert!(
        result.changed.contains(&"groups.names".to_string()),
        "expected groups.names in changed, got: {:?}",
        result.changed
    );
    assert!(
        result.errors.is_empty(),
        "expected no errors, got: {:?}",
        result.errors
    );

    let filter_guard = rs.group_filter.read().await;
    let filter = filter_guard
        .as_deref()
        .expect("group_filter must be Some after reload");
    assert!(
        filter.accepts("comp.lang.rust"),
        "filter must accept comp.lang.rust"
    );
    assert!(filter.accepts("alt.test"), "filter must accept alt.test");
    assert!(!filter.accepts("misc.test"), "filter must reject misc.test");
}

// ── test 3: trusted_peers change applied ──────────────────────────────────────

/// When `peering.trusted_peers` changes, `do_reload` must update the live
/// `trusted_keys` and record `"peering.trusted_peers"` in `changed`.
#[tokio::test]
async fn reload_trusted_peers_applied() {
    let key_hex = trusted_key_hex(0x42);
    let f = write_config(&make_toml(&[], &[], "info"));

    let rs = ReloadableState::new(
        Some(f.path().to_path_buf()),
        None,
        vec![],
        vec![],
        vec![],
        "info".to_string(),
    );

    assert!(
        rs.trusted_keys.read().await.is_empty(),
        "trusted_keys must start empty"
    );

    rewrite_config(&f, &make_toml(&[], &[&key_hex], "info"));

    let result = rs.do_reload().await;

    assert!(
        result
            .changed
            .contains(&"peering.trusted_peers".to_string()),
        "expected peering.trusted_peers in changed, got: {:?}",
        result.changed
    );
    assert!(
        result.errors.is_empty(),
        "expected no errors, got: {:?}",
        result.errors
    );

    let keys = rs.trusted_keys.read().await;
    assert_eq!(keys.len(), 1, "expected 1 trusted key after reload");

    let expected_vk = SigningKey::from_bytes(&[0x42u8; 32]).verifying_key();
    assert_eq!(
        keys[0].as_bytes(),
        expected_vk.as_bytes(),
        "loaded key must match the one written to config"
    );
}

// ── test 4: log.level change detected but not applied ─────────────────────────

/// `log.level` changes must appear in `errors` with a "requires restart"
/// message, not in `changed`.
#[tokio::test]
async fn reload_log_level_detected_not_applied() {
    let f = write_config(&make_toml(&[], &[], "info"));

    let rs = ReloadableState::new(
        Some(f.path().to_path_buf()),
        None,
        vec![],
        vec![],
        vec![],
        "info".to_string(),
    );

    rewrite_config(&f, &make_toml(&[], &[], "debug"));

    let result = rs.do_reload().await;

    assert!(
        !result.changed.contains(&"log.level".to_string()),
        "log.level must NOT be in changed (requires restart), got: {:?}",
        result.changed
    );
    let has_restart_note = result
        .errors
        .iter()
        .any(|e| e.contains("log.level") && e.contains("restart"));
    assert!(
        has_restart_note,
        "errors must mention log.level + restart, got: {:?}",
        result.errors
    );
}
