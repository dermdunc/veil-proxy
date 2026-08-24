//! `vg run`'s required M3 prerequisite (masking-proxy plan §10.2): `CLAUDE_CODE_ATTRIBUTION_HEADER=0`
//! must reach the wrapped command's environment on every launch, unconditionally — proven here
//! by actually launching a stub script through `vg run` and reading back what it saw, not by
//! inspecting `vg run`'s own launch environment (that wouldn't prove the variable was actually
//! *injected into the child*, as opposed to merely present in `vg run`'s own ambient
//! environment already).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const TEST_KEY_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn vg() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vg"))
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Writes an executable shell script at `path` that dumps its own environment (`env`, one
/// `KEY=value` per line) to the file passed as its first argument.
fn write_env_dumping_stub(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nenv > \"$1\"\n").expect("write stub script");
    let mut perms = std::fs::metadata(path).expect("stat stub").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod stub");
}

#[test]
fn vg_run_injects_claude_code_attribution_header_zero_into_the_wrapped_command() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let stub = tmp.path().join("env-dump-stub.sh");
    let out = tmp.path().join("child.env");
    write_env_dumping_stub(&stub);

    // Deliberately unset in the *test process's own* environment before spawning `vg run`, so
    // a pass here can only mean `vg run` actively injected it — not that it merely happened to
    // already be set somewhere upstream (e.g. by the developer's own shell).
    let output = Command::new(vg())
        .env("VG_VAULT_KEY_HEX", TEST_KEY_HEX)
        .env("VG_STATE_DIR", &state)
        .env_remove("CLAUDE_CODE_ATTRIBUTION_HEADER")
        .args(["run", "--", stub.to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .expect("run vg");
    assert!(
        output.status.success(),
        "vg run failed: {}",
        stderr(&output)
    );

    let child_env = std::fs::read_to_string(&out).expect("stub wrote its environment");
    assert!(
        child_env.lines().any(|l| l == "CLAUDE_CODE_ATTRIBUTION_HEADER=0"),
        "wrapped command's environment must carry CLAUDE_CODE_ATTRIBUTION_HEADER=0, got:\n{child_env}"
    );
}

/// Same assertion, but with a *conflicting* ambient value already set on the launching
/// process — proves `vg run` actively overrides rather than only filling in an absent value
/// (a real difference: `BEDROCK_ENV_VARS`, this crate's other env-handling mechanism, is
/// pass-through-only and would NOT override an existing value the way this one must).
#[test]
fn vg_run_overrides_a_conflicting_ambient_attribution_header_value() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let stub = tmp.path().join("env-dump-stub.sh");
    let out = tmp.path().join("child.env");
    write_env_dumping_stub(&stub);

    let output = Command::new(vg())
        .env("VG_VAULT_KEY_HEX", TEST_KEY_HEX)
        .env("VG_STATE_DIR", &state)
        .env("CLAUDE_CODE_ATTRIBUTION_HEADER", "1")
        .args(["run", "--", stub.to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .expect("run vg");
    assert!(
        output.status.success(),
        "vg run failed: {}",
        stderr(&output)
    );

    let child_env = std::fs::read_to_string(&out).expect("stub wrote its environment");
    assert!(
        child_env
            .lines()
            .any(|l| l == "CLAUDE_CODE_ATTRIBUTION_HEADER=0"),
        "vg run must override a conflicting ambient value, got:\n{child_env}"
    );
}
