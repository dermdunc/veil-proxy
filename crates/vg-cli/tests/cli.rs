//! Integration tests driving the compiled `vg` binary (the T09 acceptance criterion asks
//! for the round trip and the demask gate at the *CLI* level, not only the library level —
//! `crates/vg-core/tests/demask.rs` covers the latter). Uses Cargo's `CARGO_BIN_EXE_vg`
//! env (set for integration tests of a bin crate) rather than an assert_cmd dependency,
//! and the `VG_VAULT_KEY_HEX` test seam so the suite never touches the real OS keychain.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const TEST_KEY_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn vg() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vg"))
}

fn run_vg(state: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(vg());
    cmd.env("VG_VAULT_KEY_HEX", TEST_KEY_HEX)
        .env("VG_STATE_DIR", state)
        .args(args);
    if let Some(input) = stdin {
        use std::io::Write;
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn vg");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait vg")
    } else {
        cmd.output().expect("run vg")
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn masked_round_trip_through_the_binary() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let original = "escalate to jane.doe@example.com about IBAN GB29 NWBK 6016 1331 9268 19";
    let note = tmp.path().join("note.txt");
    std::fs::write(&note, original).expect("write note");

    // Mask via `vg diff --masked` (which persists the pack).
    let diff = run_vg(&state, &["diff", "--masked", note.to_str().unwrap()], None);
    assert!(diff.status.success(), "diff failed: {}", stderr(&diff));
    let masked = stdout(&diff);
    assert!(masked.contains("EMAIL_001"), "masked: {masked}");
    assert!(!masked.contains("jane.doe@example.com"), "masked: {masked}");

    let packs_dir = state.join("packs");
    let pack = std::fs::read_dir(&packs_dir)
        .expect("packs dir")
        .next()
        .expect("one pack")
        .expect("entry")
        .path();

    // Demask to an allowed local destination restores the original exactly.
    let demask = run_vg(
        &state,
        &[
            "demask",
            "--from",
            pack.to_str().unwrap(),
            "--to",
            "local-patch",
        ],
        None,
    );
    assert!(
        demask.status.success(),
        "demask failed: {}",
        stderr(&demask)
    );
    assert_eq!(stdout(&demask), original);

    // The hard-deny destination is refused (exit != 0, DENIED on stderr, no raw value).
    let denied = run_vg(
        &state,
        &[
            "demask",
            "--from",
            pack.to_str().unwrap(),
            "--to",
            "remote-model-prompt",
        ],
        None,
    );
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("DENIED"), "{}", stderr(&denied));
    assert!(!stdout(&denied).contains("jane.doe@example.com"));
}

#[test]
fn hook_blocks_a_sensitive_prompt_with_the_masked_resubmit_text() {
    // v1.3: the platform cannot rewrite a prompt, so "transformed" renders as exit 0 +
    // {"decision":"block"} JSON carrying the masked version in the reason. The raw value
    // must appear nowhere.
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"email ops@example.com the incident summary"}"#;

    let hook = run_vg(&state, &["hook", "user-prompt-submit"], Some(payload));
    assert_eq!(hook.status.code(), Some(0), "stderr: {}", stderr(&hook));
    let out = stdout(&hook);
    let v: serde_json::Value = serde_json::from_str(&out).expect("JSON on stdout");
    assert_eq!(v["decision"], "block", "stdout: {out}");
    let reason = v["reason"].as_str().expect("reason");
    assert!(reason.contains("EMAIL_001"), "reason: {reason}");
    assert!(!out.contains("ops@example.com"), "stdout: {out}");
}

#[test]
fn hook_rewrites_sensitive_tool_input_via_updated_input() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/notes.txt","content":"contact ops@example.com"}}"#;

    let hook = run_vg(&state, &["hook", "pre-tool-use"], Some(payload));
    assert_eq!(hook.status.code(), Some(0), "stderr: {}", stderr(&hook));
    let v: serde_json::Value = serde_json::from_str(&stdout(&hook)).expect("JSON on stdout");
    let hso = &v["hookSpecificOutput"];
    assert_eq!(hso["hookEventName"], "PreToolUse");
    assert_eq!(hso["permissionDecision"], "allow");
    let content = hso["updatedInput"]["content"].as_str().expect("content");
    assert!(content.contains("EMAIL_001"), "{content}");
    assert!(!stdout(&hook).contains("ops@example.com"));
}

#[test]
fn hook_blocks_an_env_write_with_exit_2() {
    // Artefact-level policy Block (writing a .env) must use exit 2 — the platform's only
    // blocking code; the reason travels on stderr.
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/.env","content":"API_TOKEN=sk-live-abc"}}"#;

    let hook = run_vg(&state, &["hook", "pre-tool-use"], Some(payload));
    assert_eq!(hook.status.code(), Some(2), "stderr: {}", stderr(&hook));
    assert!(stderr(&hook).contains("blocked"), "{}", stderr(&hook));
    assert!(
        stdout(&hook).is_empty(),
        "block must emit nothing on stdout"
    );
}

#[test]
fn hook_passes_through_a_benign_prompt_with_exit_0() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"please run the test suite"}"#;

    let hook = run_vg(&state, &["hook", "user-prompt-submit"], Some(payload));
    assert_eq!(hook.status.code(), Some(0), "stderr: {}", stderr(&hook));
    assert!(stdout(&hook).is_empty(), "pass-through must emit nothing");
}

#[test]
fn inspect_never_prints_the_matched_text() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    let note = tmp.path().join("note.txt");
    std::fs::write(&note, "reach jane.doe@example.com or call +1-415-555-2671").unwrap();

    let inspect = run_vg(&state, &["inspect", note.to_str().unwrap()], None);
    assert!(inspect.status.success(), "{}", stderr(&inspect));
    let out = stdout(&inspect);
    // "EMAIL" (Display), not "Email" (the old Debug-derived variant name) -- inspect now
    // renders EntityType via Display (fixed 2026-08-01, docs/decisions.md), which also
    // collapses a Custom variant's class name instead of leaking it.
    assert!(out.contains("EMAIL"), "{out}");
    assert!(
        !out.contains("jane.doe@example.com"),
        "inspect leaked a value: {out}"
    );
    assert!(
        !out.contains("415-555-2671"),
        "inspect leaked a value: {out}"
    );
}

#[test]
fn help_is_complete_for_every_subcommand() {
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    for args in [
        vec!["--help"],
        vec!["run", "--help"],
        vec!["hook", "--help"],
        vec!["inspect", "--help"],
        vec!["diff", "--help"],
        vec!["demask", "--help"],
        vec!["audit", "--help"],
        vec!["policy", "--help"],
        vec!["vault", "--help"],
    ] {
        let out = run_vg(&state, &args, None);
        assert!(out.status.success(), "help failed for {args:?}");
        assert!(!stdout(&out).is_empty(), "empty help for {args:?}");
    }
}

#[test]
fn hook_fails_closed_when_the_engine_cannot_open() {
    // Codex round-2 High: run_hook's internal paths fail closed, but an error that
    // bubbles OUT of the hook command (engine open — e.g. a malformed policy file) used
    // to exit 1, which Claude Code treats as non-blocking (raw content continues). The
    // hook path must exit 2 on ANY error.
    let tmp = TempDir::new().expect("tempdir");
    let state = tmp.path().join(".veilgremlin");
    std::fs::create_dir_all(state.join("policy")).expect("mk policy dir");
    std::fs::write(state.join("policy").join("global.policy.json"), "{not json")
        .expect("write bad policy");
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"mail ops@example.com"}"#;

    let hook = run_vg(&state, &["hook", "user-prompt-submit"], Some(payload));
    assert_eq!(hook.status.code(), Some(2), "stderr: {}", stderr(&hook));
    assert!(!stdout(&hook).contains("ops@example.com"));
}
