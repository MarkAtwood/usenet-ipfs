//! Integration tests for the dev-mode startup guard (stoa-90tpd).
//!
//! These tests spawn the stoa-reader binary and verify that it exits non-zero
//! when configured in dev mode on a non-loopback address, and passes the guard
//! when configured on loopback.
//!
//! Oracle: Epic acceptance criteria — "Starting with auth.bypass=true in
//! production mode fails with a fatal error at startup."
//!
//! Config format confirmed against crates/reader/src/config.rs.  Required
//! sections: [listen], [limits], [auth], [tls], and one of [backend] or [ipfs].
//!
//! Guard ordering in main.rs:
//!   1. operator.signing_key_path check (line ~351) — non-loopback without key exits 1
//!   2. auth dev-mode guard (line ~366) — dev-mode on non-loopback exits 1
//!
//! The non-loopback test supplies a signing key so execution reaches guard #2.

use std::io::Write;
use std::process::Command;
use std::time::Duration;
use tempfile::NamedTempFile;

/// Returns the path to the compiled stoa-reader binary.
///
/// Assumes `cargo build -p stoa-reader` has been run before these tests execute.
/// The integration-tests crate lists stoa-reader as a dev-dependency, so
/// `cargo test -p stoa-integration-tests` will trigger a build automatically.
fn stoa_reader_bin() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/integration-tests → crates/
    path.pop(); // crates/ → workspace root
    path.push("target");
    path.push("debug");
    path.push("stoa-reader");
    path
}

/// Generate an ephemeral Ed25519 signing key file.
///
/// Required so the non-loopback test reaches the dev-mode guard rather than
/// being short-circuited by the earlier signing_key_path check (main.rs ~351).
fn make_signing_key() -> NamedTempFile {
    // Ed25519 seed: 32 raw bytes.  Any 32 bytes form a valid seed.
    let seed: [u8; 32] = [0x42u8; 32];
    let mut f = NamedTempFile::new().expect("create signing key tempfile");
    f.write_all(&seed).expect("write signing key bytes");
    f
}

/// Minimal config: dev mode (no auth), non-loopback listen address.
///
/// Providing a [backend.sqlite] with a nonexistent path is sufficient for the
/// config to parse and validate.  The sqlite backend is chosen because it needs
/// no external daemon and fails fast if it can't open the file.
///
/// signing_key_path is set so the earlier signing-key guard (main.rs ~351) does
/// NOT fire first — we want to exercise the dev-mode guard specifically.
fn dev_mode_nonloopback_config(port: u16, signing_key_path: &str) -> String {
    format!(
        r#"
[listen]
addr = "0.0.0.0:{port}"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[operator]
signing_key_path = "{signing_key_path}"

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/stoa-integ-guard-nonexistent-{port}.db"
"#
    )
}

/// Minimal config: dev mode (no auth), loopback listen address.
///
/// No signing_key_path needed — the signing-key guard only applies to
/// non-loopback addresses.  The binary will pass the dev-mode guard and then
/// fail at store initialisation (nonexistent DB path), which is fine: the
/// test only cares that the guard itself was not triggered.
fn dev_mode_loopback_config(port: u16) -> String {
    format!(
        r#"
[listen]
addr = "127.0.0.1:{port}"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[backend]
type = "sqlite"

[backend.sqlite]
path = "/tmp/stoa-integ-guard-nonexistent-{port}.db"
"#
    )
}

/// Spawn stoa-reader with the given config file and wait up to `timeout` for
/// it to exit.  Returns `(exit_code, stdout, stderr)`.
///
/// If the process does not exit within the timeout it is killed and the test
/// panics — a hanging binary means the guard was not triggered, which is
/// itself a test failure for the non-loopback case.
fn run_with_timeout(
    config_path: &std::path::Path,
    timeout: Duration,
) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let bin = stoa_reader_bin();
    assert!(
        bin.exists(),
        "stoa-reader binary not found at {:?}; run `cargo build -p stoa-reader` first",
        bin
    );

    let mut child = Command::new(&bin)
        .arg("--config")
        .arg(config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn stoa-reader");

    let start = std::time::Instant::now();
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => {
                // Process exited — collect output.
                let output = child.wait_with_output().expect("wait_with_output failed");
                return (status.code(), output.stdout, output.stderr);
            }
            None => {
                if start.elapsed() >= timeout {
                    child.kill().expect("kill failed");
                    let output = child
                        .wait_with_output()
                        .expect("wait_with_output after kill failed");
                    panic!(
                        "stoa-reader did not exit within {:?}; killed.\nstderr: {}",
                        timeout,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Oracle: dev mode + non-loopback → exit 1 with actionable error message.
///
/// The guard in main.rs at line ~366 checks:
///   config.auth.is_dev_mode() && !is_loopback_addr(listen.addr)
/// and writes to stderr:
///   "error: stoa-reader is configured in dev mode ..."
#[test]
fn startup_guard_dev_mode_nonloopback_exits_1() {
    let signing_key = make_signing_key();
    let signing_key_path = signing_key
        .path()
        .to_str()
        .expect("signing key path is valid UTF-8");

    let mut cfg_file = NamedTempFile::new().expect("create config tempfile");
    write!(
        cfg_file,
        "{}",
        dev_mode_nonloopback_config(19990, signing_key_path)
    )
    .expect("write config");

    let (code, _stdout, stderr) = run_with_timeout(cfg_file.path(), Duration::from_secs(10));

    // Oracle: must exit non-zero.
    assert_ne!(
        code,
        Some(0),
        "stoa-reader must exit non-zero in dev mode on non-loopback; got exit 0"
    );
    // Oracle: must exit exactly 1 (not a crash/signal exit).
    assert_eq!(
        code,
        Some(1),
        "stoa-reader must exit 1 in dev mode on non-loopback; got {:?}",
        code
    );

    let stderr_str = String::from_utf8_lossy(&stderr);

    // Oracle: error message must identify the dev-mode condition.
    assert!(
        stderr_str.contains("dev mode"),
        "stderr must contain 'dev mode'; got:\n{stderr_str}"
    );
    // Oracle: error message must mention the config lever the operator can pull.
    assert!(
        stderr_str.contains("non-loopback"),
        "stderr must contain 'non-loopback'; got:\n{stderr_str}"
    );
}

/// Oracle: dev mode + loopback → guard does NOT abort.
///
/// The binary is allowed to fail after the guard for any other reason
/// (e.g., missing storage files), but the failure must not be due to the
/// dev-mode guard.  We verify: if it exits 1, stderr must NOT contain the
/// guard's specific error text.
#[test]
fn startup_guard_dev_mode_loopback_passes_guard() {
    let mut cfg_file = NamedTempFile::new().expect("create config tempfile");
    write!(cfg_file, "{}", dev_mode_loopback_config(19991)).expect("write config");

    let (code, _stdout, stderr) = run_with_timeout(cfg_file.path(), Duration::from_secs(10));

    let stderr_str = String::from_utf8_lossy(&stderr);

    // If the process exited, it must NOT be because of the dev-mode guard.
    if let Some(exit_code) = code {
        assert!(
            !stderr_str.contains("dev mode on a non-loopback")
                && !stderr_str.contains("stoa-reader is configured in dev mode"),
            "stoa-reader must not abort via dev-mode guard on loopback \
             (exit {exit_code}); stderr:\n{stderr_str}"
        );
    }
    // A process that is still running after the timeout would have been killed
    // and panicked in run_with_timeout.  Reaching here means it either exited
    // without the guard message, or had no exit at all (impossible — kill fires).
}
