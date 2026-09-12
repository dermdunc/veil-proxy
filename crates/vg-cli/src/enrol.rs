//! `vg enrol` command bodies (ADR-017, XREPO-009): device-side signing-credential install.
//!
//! Device-level, not repo-level -- these commands deliberately never touch `StatePaths`
//! (`main.rs`'s dispatch routes `Command::Enrol` here *before* `StatePaths::resolve` runs).
//! The signing credential lives in the OS keychain under a fixed per-device account, not a
//! repo-scoped `.veilgremlin/` state dir.
//!
//! Output discipline follows this CLI's existing split (`cmd_run`'s pre-send summary,
//! `cmd_demask`'s payload): `request-csr` has a real payload (the CSR PEM) on stdout, with
//! everything else -- the fingerprint, the confirmation reminder, the repro command -- on
//! stderr. `install-cert`/`cancel-csr` print nothing on stdout at all, so they compose
//! cleanly in scripts; their human summary is stderr-only. `status` is a pure read, like
//! `vg vault stats`/`vg audit`, so it uses stdout like those do.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use vg_core::telemetry::{DeviceRef, KeyRef};
use vg_vault::{
    cancel_pending_csr, credential_status, install_device_signing_certificate,
    request_device_signing_csr, EnrolError, InstallOutcome, InstalledSigningCredential,
};

/// Same two env vars and same presence check as `vg-vault::enrol`'s own (private)
/// `env_seam_active` -- duplicated here, not imported, for the identical reason `vg-vault`'s
/// own `enrol.rs` duplicates `keychain.rs`'s constants: this lets `cmd_install_cert`
/// preflight the check before touching either file, matching ADR-017 §4's ordering at the
/// CLI boundary, not only inside the library call it also makes. `var_os` (not `var`), so a
/// present-but-non-UTF-8 value still counts as "set" here too.
fn env_seam_active() -> bool {
    std::env::var_os("VG_DEVICE_SIGNING_KEY_HEX").is_some()
        || std::env::var_os("VG_DEVICE_SIGNING_CERT_PEM").is_some()
}

/// Renders an identifier type whose only public serialisation is `serde::Serialize` (no
/// `Display`/`Debug` -- `vg-core`'s own deliberate convention for `KeyRef`/`DeviceRef`) as a
/// display string, via the same `serde_json` round-trip this crate already depends on.
fn render<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unrenderable>".to_string())
}

fn render_key_ref(key_ref: &KeyRef) -> String {
    render(key_ref)
}

fn render_device_ref(device_ref: &DeviceRef) -> String {
    render(device_ref)
}

fn render_time(t: SystemTime) -> String {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            // No chrono/time dependency in this crate for one field -- a raw Unix timestamp
            // is unambiguous and sufficient for an operator to sanity-check "did this just
            // happen" / "is this about to expire", which is all this summary line is for.
            format!("{} (unix {})", humantime_like(d.as_secs()), d.as_secs())
        }
        Err(_) => "before 1970-01-01 (invalid)".to_string(),
    }
}

/// A minimal, dependency-free "seconds since epoch" -> rough UTC stamp, precise to the
/// minute. Not a full calendar implementation -- just enough for a human glancing at an
/// install summary or expiry warning to read a real date instead of a bare integer.
fn humantime_like(unix_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days_since_epoch = unix_secs / SECS_PER_DAY;
    let secs_of_day = unix_secs % SECS_PER_DAY;
    let (h, m) = (secs_of_day / 3600, (secs_of_day % 3600) / 60);
    // Civil-from-days (Howard Hinnant's algorithm) -- proleptic Gregorian, correct for any
    // date this credential's validity window could plausibly fall in.
    let z = days_since_epoch as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_ = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_ <= 2 { y + 1 } else { y };
    format!("{y:04}-{m_:02}-{d:02}T{h:02}:{m:02}Z")
}

const ENV_HINT: &str = "unset VG_DEVICE_SIGNING_KEY_HEX and VG_DEVICE_SIGNING_CERT_PEM first";

/// Round-C/round-D finding: `EnrolError::AlreadyEnrolled`'s `Display` deliberately omits
/// `key_ref`/`device_ref` (they have no `Display`/`Debug` -- `vg-core`'s own convention), but
/// nothing was actually rendering them here either, so an operator saw only a generic
/// "a different credential is already installed" with no way to tell *which* one. This is
/// the one place that was always meant to close that gap.
fn map_enrol_err(e: EnrolError) -> Box<dyn std::error::Error> {
    match &e {
        EnrolError::EnvSeamActive => format!("{e} ({ENV_HINT})").into(),
        EnrolError::AlreadyEnrolled {
            key_ref,
            device_ref,
            ..
        } => format!(
            "{e}\nveilgremlin:   currently installed: device_ref {}, key_ref {}",
            render_device_ref(device_ref),
            render_key_ref(key_ref),
        )
        .into(),
        _ => e.to_string().into(),
    }
}

pub(crate) fn cmd_request_csr(
    out: Option<PathBuf>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let pending = request_device_signing_csr().map_err(map_enrol_err)?;

    match &out {
        Some(path) => {
            std::fs::write(path, &pending.csr_pem)?;
            eprintln!("veilgremlin: CSR written to {}", path.display());
        }
        None => {
            print!("{}", pending.csr_pem);
        }
    }

    eprintln!("veilgremlin: CSR public-key fingerprint (SHA-256 of DER SubjectPublicKeyInfo)");
    eprintln!("veilgremlin:   {}", pending.spki_fingerprint);
    eprintln!("veilgremlin: confirm this value with the veil-enrol operator over a SECOND channel");
    eprintln!("veilgremlin: before they run `veil-enrol issue-signing-key`. The operator can");
    eprintln!("veilgremlin: reproduce it with:");
    eprintln!("veilgremlin:   openssl req -in device.csr -pubkey -noout \\");
    eprintln!("veilgremlin:     | openssl pkey -pubin -outform DER | sha256sum");
    eprintln!(
        "veilgremlin: the matching private key is held in the OS keychain (pending); install \
         the returned certificate with:"
    );
    eprintln!("veilgremlin:   vg enrol install-cert --cert <file> --ca-cert <file>");

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_install_cert(
    cert: PathBuf,
    ca_cert: PathBuf,
    force: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // Round-C/round-D finding: ADR-017 §4 requires the env-seam check run "first, before any
    // file or keychain access" -- `install_device_signing_certificate` already checks it
    // first *within itself*, but this function used to read both files before ever calling
    // that, so a seam-active refusal was preempted by a plain file-not-found error whenever
    // the paths happened to be missing. Pre-flighting the identical check here, before either
    // read, makes the ordering hold at the CLI boundary too, not just inside the library.
    if env_seam_active() {
        return Err(map_enrol_err(EnrolError::EnvSeamActive));
    }

    let cert_pem = std::fs::read_to_string(&cert)
        .map_err(|e| format!("failed to read {}: {e}", cert.display()))?;
    let ca_cert_pem = std::fs::read_to_string(&ca_cert)
        .map_err(|e| format!("failed to read {}: {e}", ca_cert.display()))?;

    let outcome = install_device_signing_certificate(&cert_pem, &ca_cert_pem, force)
        .map_err(map_enrol_err)?;

    let (verb, info) = match &outcome {
        InstallOutcome::Installed(info) => ("installed", info),
        InstallOutcome::AlreadyInstalled(info) => ("already installed (no change)", info),
        InstallOutcome::RecoveredPartialInstall(info) => ("recovered an interrupted install", info),
    };

    print_install_summary(verb, info);
    Ok(ExitCode::SUCCESS)
}

fn print_install_summary(verb: &str, info: &InstalledSigningCredential) {
    eprintln!("veilgremlin: {verb}");
    eprintln!("veilgremlin:   issuer      {}", info.issuer);
    eprintln!(
        "veilgremlin:   device_ref  {}",
        render_device_ref(&info.device_ref)
    );
    eprintln!(
        "veilgremlin:   key_ref     {}",
        render_key_ref(&info.key_ref)
    );
    eprintln!(
        "veilgremlin:   not_before  {}",
        render_time(info.not_before)
    );
    eprintln!("veilgremlin:   not_after   {}", render_time(info.not_after));

    let seven_days = std::time::Duration::from_secs(7 * 24 * 3600);
    match info.not_after.duration_since(SystemTime::now()) {
        Ok(remaining) if remaining < seven_days => {
            eprintln!(
                "veilgremlin: WARNING this certificate expires within 7 days ({})",
                render_time(info.not_after)
            );
        }
        Err(_) => {
            eprintln!(
                "veilgremlin: WARNING this certificate has already expired ({})",
                render_time(info.not_after)
            );
        }
        _ => {}
    }
}

pub(crate) fn cmd_cancel_csr(fingerprint: String) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // `NoPendingKey`'s shared Display text is worded for install-cert's context ("...match
    // this certificate's public key"), which doesn't fit here -- there is no certificate
    // involved in a cancellation. Reworded at this call site rather than in the shared error.
    cancel_pending_csr(&fingerprint).map_err(|e| match e {
        EnrolError::NoPendingKey => format!(
            "no pending CSR found for fingerprint {fingerprint} -- check it against \
             `request-csr`'s printed output"
        )
        .into(),
        other => map_enrol_err(other),
    })?;
    eprintln!("veilgremlin: discarded pending key for {fingerprint}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_status() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let status = credential_status().map_err(map_enrol_err)?;

    // Round-C/round-D finding: these are three independent facts (ADR-017 §8), so all three
    // print unconditionally, regardless of the others' values -- an earlier draft only
    // printed the enrolment-marker line when nothing was installed, which meant an installed
    // credential could never reveal that its marker had gone missing (or, symmetrically, hid
    // the fact that the marker line's own wording matters even when a credential *is*
    // present). "enrolment marker" wording is deliberately non-committal about whether
    // enrolment actually completed -- the marker can be written before the first credential
    // write, so "enrolled: yes" would overclaim for a state that might just be an interrupted
    // install (ADR-017 §7).
    match &status.installed {
        Some(info) => {
            println!("installed:        yes");
            println!("issuer:           {}", info.issuer);
            println!("device_ref:       {}", render_device_ref(&info.device_ref));
            println!("key_ref:          {}", render_key_ref(&info.key_ref));
            println!("not_before:       {}", render_time(info.not_before));
            println!("not_after:        {}", render_time(info.not_after));
        }
        None => {
            println!("installed:        no");
        }
    }
    println!(
        "enrolment marker: {}",
        if status.enrolment_marker_present {
            "present"
        } else {
            "absent"
        }
    );
    println!(
        "env seam:         {}",
        if status.env_seam_shadowing {
            "SHADOWING the keychain (VG_DEVICE_SIGNING_KEY_HEX/_CERT_PEM is set)"
        } else {
            "not shadowing (unset)"
        }
    );

    Ok(ExitCode::SUCCESS)
}
