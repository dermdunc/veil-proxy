//! `vg` — the VeilGremlin CLI (Task T09).
//!
//! Every subcommand runs through the same [`Engine`] the Claude Code hooks use
//! (`vg-adapters-claude`), over one repo-local `.veilgremlin/` state dir — so what the CLI
//! shows is exactly what the hooks do. Command surface per the T09 spec / README:
//!
//! - `vg run -- <cmd...>` — write the hook settings, print the pre-send summary, exec the
//!   wrapped command (Claude Code on Bedrock via its own env; no HTTP client here).
//! - `vg hook <event>` — the hook entry point Claude Code invokes (stdin JSON in, §8 exit
//!   codes out). Registered by `vg run`'s generated settings; rarely typed by hand.
//! - `vg inspect <file>` — what WOULD be masked: findings + policy classes, **never** the
//!   matched text (a preview tool must not become the leak).
//! - `vg diff --masked <file>` — the masked rendering plus masking stats.
//! - `vg demask --from <pack.json> --to <dest>` — the explicit, policy-gated reversal.
//!   Takes a **stored pack** (written by the hooks / `vg diff`), never bare text: demask
//!   resolves exclusively via the pack's own display↔`MappingRef` bindings (contract
//!   v1.2) — a placeholder-shaped string the pack never minted is left untouched.
//! - `vg audit last|<n>` — the most recent audit event(s), redaction-safe by construction.
//! - `vg policy check` — load/validate the layered packs, print the resolved summary.
//! - `vg vault stats` — mapping count only; never values.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser as ClapParser, Subcommand};

use vg_adapters_claude::{
    hook_settings_json, open_vault, run_hook, Engine, HookEvent, StatePaths, StoredPack,
    BEDROCK_ENV_VARS,
};
use vg_core::{Actor, ActorId, ArtefactHint, Destination, EntityType, HandlingClass};

#[derive(ClapParser)]
#[command(
    name = "vg",
    version,
    about = "VeilGremlin: local-first PII masking for agentic coding workflows",
    long_about = "VeilGremlin keeps real PII and sensitive identifiers out of model context.\n\
                  Masking is automatic and local (hooks); demasking is explicit, local,\n\
                  policy-gated, and audited. The cloud model only ever sees placeholders."
)]
struct Cli {
    /// Path to the .veilgremlin state directory (default: nearest .veilgremlin walking up
    /// from the current directory, else ./.veilgremlin; VG_STATE_DIR also honoured)
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a command (typically `claude`) with VeilGremlin's masking hooks
    Run {
        /// The command to wrap, after `--` (e.g. `vg run -- claude "fix the bug"`)
        #[arg(trailing_var_arg = true, required = true, value_name = "CMD")]
        cmd: Vec<String>,
    },
    /// Hook entry point invoked by Claude Code (stdin: hook JSON; exit 0/2/1 per contract)
    Hook {
        /// Which hook event to handle: user-prompt-submit | pre-tool-use | post-tool-use
        event: String,
    },
    /// Preview what WOULD be masked in a file (prints classes and spans, never values)
    Inspect {
        /// File to inspect
        file: PathBuf,
    },
    /// Show a file's masked form and masking stats
    Diff {
        /// Show the masked rendering (the only mode in Phase 1)
        #[arg(long, required = true)]
        masked: bool,
        /// File to mask-and-show
        file: PathBuf,
    },
    /// Reverse a stored masked pack for an authorised local destination (policy-gated)
    Demask {
        /// Path to a stored pack JSON (written by the hooks or `vg diff`)
        #[arg(long, value_name = "PACK")]
        from: PathBuf,
        /// Destination: local-patch | local-test-fixture | local-explanation-buffer
        /// (remote-model-prompt and observability-sink are hard-denied by design)
        #[arg(long, value_name = "DEST")]
        to: String,
        /// Actor id recorded in the audit trail
        #[arg(long, default_value = "local-user")]
        actor: String,
        /// Roles the actor holds (repeatable), matched against policy demask_roles
        #[arg(long)]
        role: Vec<String>,
    },
    /// Show recent audit events (redaction-safe: refs/counts/versions only)
    Audit {
        /// `last` or a number of most-recent events to show
        #[arg(default_value = "last")]
        which: String,
    },
    /// Policy subcommands
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Vault subcommands
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    /// Run the Go/No-Go eval harness over the seeded corpus and print the report
    Bench {
        /// Cold `vg hook` invocations to time for the end-to-end latency measurement
        #[arg(long, default_value_t = 30)]
        hook_samples: usize,
        /// Skip the cold-hook latency measurement (spawn no `vg hook` subprocesses)
        #[arg(long)]
        no_hook: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Load and validate the layered policy packs; print the resolved summary
    Check,
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Print the number of stored mappings (never values)
    Stats,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let is_hook = matches!(cli.command, Command::Hook { .. });
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vg: {e}");
            if is_hook {
                // Fail closed (Codex round-2 High): on the hook path, ANY error that
                // bubbles out — state-dir resolution, engine/vault/policy open, stdin —
                // must exit 2. Exit 1 is a NON-blocking warning to Claude Code, i.e. the
                // raw content would continue unmasked.
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let (paths, provenance) = StatePaths::resolve(cli.state_dir)?;
    // F3 hardening: never silently trust a state dir adopted from an ancestor.
    if let Some(warning) = provenance.discovered_warning(paths.root()) {
        eprintln!("{warning}");
    }
    match cli.command {
        Command::Run { cmd } => cmd_run(paths, cmd),
        Command::Hook { event } => cmd_hook(paths, &event),
        Command::Inspect { file } => cmd_inspect(paths, &file),
        Command::Diff { masked: _, file } => cmd_diff(paths, &file),
        Command::Demask {
            from,
            to,
            actor,
            role,
        } => cmd_demask(paths, &from, &to, actor, role),
        Command::Audit { which } => cmd_audit(paths, &which),
        Command::Policy {
            cmd: PolicyCmd::Check,
        } => cmd_policy_check(paths),
        Command::Vault {
            cmd: VaultCmd::Stats,
        } => cmd_vault_stats(paths),
        // `vg bench` runs in its own isolated harness (temp vault/audit + the shipped
        // default policy), so it deliberately ignores the resolved state dir — the report
        // must be reproducible and must never mutate a real vault.
        Command::Bench {
            hook_samples,
            no_hook,
        } => cmd_bench(hook_samples, no_hook),
    }
}

/// `vg run -- <cmd...>`: write the hook settings pinned to this state dir, print the
/// pre-send summary, then exec the wrapped command. When the wrapped command is Claude
/// Code (`claude*`) and no `--settings` is present, the generated settings file is
/// appended automatically so the hooks are live without extra flags.
fn cmd_run(
    paths: StatePaths,
    mut cmd: Vec<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = Engine::open(paths)?;
    let paths = engine.paths().clone();

    let vg_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "vg".to_string());
    let settings = hook_settings_json(&vg_exe, paths.root());
    let settings_path = paths.hook_config();
    std::fs::write(&settings_path, settings)?;

    // Pre-send summary: what is wired, before anything is sent anywhere.
    eprintln!("veilgremlin: state dir      {}", paths.root().display());
    eprintln!("veilgremlin: policy version {}", engine.policy_version());
    eprintln!(
        "veilgremlin: hooks          UserPromptSubmit + PreToolUse + PostToolUse -> {}",
        settings_path.display()
    );
    let bedrock: Vec<&str> = BEDROCK_ENV_VARS
        .iter()
        .copied()
        .filter(|v| std::env::var_os(v).is_some())
        .collect();
    eprintln!(
        "veilgremlin: bedrock env    {}",
        if bedrock.is_empty() {
            "(none set — wrapped CLI uses its default transport)".to_string()
        } else {
            bedrock.join(", ")
        }
    );

    let is_claude = cmd
        .first()
        .and_then(|c| std::path::Path::new(c).file_name())
        .map(|n| n.to_string_lossy().starts_with("claude"))
        .unwrap_or(false);
    // `--settings FILE` and `--settings=FILE` both count as "the user brought their own"
    // (doubt-pass finding: the `=` form previously slipped past this check and got a
    // *second* --settings appended, silently overriding the user's file or vice versa).
    let has_settings = cmd
        .iter()
        .any(|a| a == "--settings" || a.starts_with("--settings="));
    if is_claude && !has_settings {
        cmd.push("--settings".to_string());
        cmd.push(settings_path.to_string_lossy().into_owned());
        eprintln!(
            "veilgremlin: appended       --settings {}",
            settings_path.display()
        );
    } else if is_claude {
        eprintln!(
            "veilgremlin: WARNING        you passed your own --settings; VeilGremlin's hooks \
             were NOT injected. Merge {} into your settings file or the session runs unmasked.",
            settings_path.display()
        );
    } else {
        eprintln!(
            "veilgremlin: note           wrapped command is not claude*; hooks were written \
             but not auto-wired ({})",
            settings_path.display()
        );
    }

    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()?;
    Ok(exit_from_status(status))
}

/// `vg hook <event>`: stdin JSON in; exit 0 with empty stdout = pass-through, exit 0 with
/// JSON stdout = the transform (updatedInput / updatedToolOutput / decision:block per
/// event), exit 2 = block with the reason on stderr (§8 v1.3 — exit 2 is the platform's
/// only blocking code; the frozen v1 `0/2/1` scheme failed open under real semantics).
fn cmd_hook(paths: StatePaths, event: &str) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(event) = HookEvent::parse(event) else {
        return Err(format!(
            "unknown hook event {event:?} (expected user-prompt-submit | pre-tool-use | post-tool-use)"
        )
        .into());
    };
    let engine = Engine::open(paths)?;
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;

    let result = run_hook(event, &stdin, &engine);
    if let Some(out) = result.stdout {
        print!("{out}");
    }
    if let Some(err) = result.stderr {
        eprintln!("{err}");
    }
    Ok(ExitCode::from(result.exit_code.clamp(0, 255) as u8))
}

/// `vg inspect <file>`: findings + their policy classes. Prints entity type, byte span,
/// detector, confidence, and class — never the matched text.
fn cmd_inspect(paths: StatePaths, file: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = Engine::open(paths)?;
    let text = std::fs::read_to_string(file)?;
    let hint = ArtefactHint {
        path: Some(file.to_path_buf()),
        language_id: None,
        mime_type: None,
    };

    let artefact_class = engine.classify_artefact(&hint);
    println!("artefact class: {artefact_class:?}");
    if artefact_class == HandlingClass::Block {
        println!("this artefact would be BLOCKED outright — content never sent");
        return Ok(ExitCode::SUCCESS);
    }

    let findings = engine.scan_text(&text, hint);
    if findings.is_empty() {
        println!("no findings — nothing would be masked");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<14} {:>5}..{:<5} {:<20} {:>4}  class",
        "entity", "start", "end", "detector", "conf"
    );
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for f in &findings {
        let class = engine.classify_entity(f.entity_type.clone());
        // `{f.entity_type}` (Display), never `{:?}` (Debug) -- Debug on a Custom variant
        // prints the raw policy-dictionary class name verbatim, exactly the leak this
        // repo closed 2026-08-01 (docs/decisions.md). `class` (HandlingClass) has no
        // string payload, so `{class:?}` here is unaffected.
        println!(
            "{:<14} {:>5}..{:<5} {:<20} {:>4.2}  {class:?}",
            f.entity_type.to_string(),
            f.span.start,
            f.span.end,
            f.detector.0,
            f.confidence,
        );
        *counts.entry(f.entity_type.to_string()).or_insert(0) += 1;
    }
    println!();
    for (ty, n) in counts {
        println!("{ty}: {n}");
    }
    Ok(ExitCode::SUCCESS)
}

/// `vg diff --masked <file>`: mask the file through the real pipeline, print the masked
/// text (stdout) and stats (stderr), and persist the pack so the result is demaskable.
fn cmd_diff(paths: StatePaths, file: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = Engine::open(paths)?;
    let text = std::fs::read_to_string(file)?;
    let hint = ArtefactHint {
        path: Some(file.to_path_buf()),
        language_id: None,
        mime_type: None,
    };
    let (pack, _refs, _event) = engine.mask_text(&text, hint)?;

    if pack.stats.blocked_artefacts > 0 {
        eprintln!(
            "artefact BLOCKED by policy — nothing to show (policy {})",
            pack.policy_version
        );
        return Ok(ExitCode::FAILURE);
    }

    println!("{}", pack.text);
    eprintln!("--- veilgremlin ---");
    eprintln!(
        "original: {} bytes; masked: {} bytes",
        text.len(),
        pack.text.len()
    );
    for (ty, n) in &pack.stats.counts.0 {
        // `{ty}` (Display), never `{ty:?}` (Debug) -- Debug on a Custom variant prints
        // the raw policy-dictionary class name verbatim to stderr, exactly the leak
        // this repo closed 2026-08-01 (docs/decisions.md). Found reachable here
        // specifically because a wrapped agent invoking `vg diff` as a shell command
        // can read this stderr output back into its own context.
        eprintln!("masked {n} x {ty}");
    }
    if pack.bindings.is_empty() {
        eprintln!("no reversible mappings (nothing interned)");
    } else {
        let saved = engine.save_pack(&pack)?;
        eprintln!(
            "pack saved: {} (use `vg demask --from` to reverse)",
            saved.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `vg demask --from <pack.json> --to <dest>`: the explicit gate. Hard-deny destinations
/// are refused before policy or vault are consulted; substitution happens exclusively via
/// the pack's own bindings.
fn cmd_demask(
    paths: StatePaths,
    from: &Path,
    to: &str,
    actor: String,
    roles: Vec<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let dest = parse_destination(to)?;
    // Hard-deny must not DEPEND on the vault/policy being reachable (Codex round-2), but
    // when the engine opens, the denial flows through `rehydrate` so it is audited (the
    // Fable plan-critique caught that a pre-open early return silently un-audited the
    // one denial `vg demask` can produce). Only an unopenable engine denies unaudited —
    // the audit sink lives behind the engine.
    let engine = match Engine::open(paths) {
        Ok(engine) => engine,
        Err(err) if dest.is_hard_deny() => {
            eprintln!(
                "vg demask DENIED: destination {to:?} is hard-deny for raw values \
                 (engine unavailable, denial unaudited: {err})"
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(err) => return Err(err.into()),
    };
    let stored = StoredPack::load(from)?;
    let (pack, ns) = stored.into_masked_pack()?;
    let actor = Actor {
        id: ActorId(actor),
        roles,
    };
    match engine.rehydrate(&pack, &ns, dest, &actor) {
        Ok(text) => {
            print!("{text}");
            // Partial-restore detection (doubt-pass finding): rehydrate leaves a binding's
            // display in place when its ref no longer resolves (expired/purged/namespace
            // mismatch). Every minted display occurs in the pack text, so a display still
            // present after substitution means that binding did NOT restore. Silently
            // exiting 0 would let a half-restored artefact into a patch — warn + fail.
            // A binding is unresolved when its display's boundary-token count did not
            // drop from pack text to restored text (Codex round-2 refinement: a restored
            // secret that legitimately CONTAINS placeholder-shaped text would false-alarm
            // a plain presence check; a count that fails to decrease is a much narrower
            // signal).
            let unresolved: Vec<&str> = pack
                .bindings
                .iter()
                .filter(|b| {
                    let before = count_display_tokens(&pack.text, &b.display);
                    before > 0 && count_display_tokens(&text, &b.display) >= before
                })
                .map(|b| b.display.as_str())
                .collect();
            if unresolved.is_empty() {
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!(
                    "vg demask WARNING: {} of {} placeholder(s) could not be restored \
                     (expired, purged, or wrong namespace): {}",
                    unresolved.len(),
                    pack.bindings.len(),
                    unresolved.join(", ")
                );
                Ok(ExitCode::FAILURE)
            }
        }
        Err(denied) => {
            eprintln!("vg demask DENIED: {denied}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Counts boundary-token occurrences of `display` in `text` (not glued to further
/// `[A-Za-z0-9_]`), mirroring `rehydrate`'s own substitution rule — a plain `contains`
/// would false-warn on unrelated text like `EMAIL_0015` after a successful restore.
fn count_display_tokens(text: &str, display: &str) -> usize {
    if display.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut from = 0;
    while let Some(pos) = text[from..].find(display) {
        let (start, end) = (from + pos, from + pos + display.len());
        let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let before_ok = !text[..start].chars().next_back().is_some_and(is_word);
        let after_ok = !text[end..].chars().next().is_some_and(is_word);
        if before_ok && after_ok {
            count += 1;
        }
        from = start + 1;
    }
    count
}

/// `vg audit last|<n>`: print the most recent audit event(s) from the JSONL log. Events
/// are redaction-safe by construction (refs/counts/versions only), so printing them
/// verbatim leaks nothing.
fn cmd_audit(paths: StatePaths, which: &str) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let n: usize = match which {
        "last" => 1,
        other => other
            .parse()
            .map_err(|_| format!("expected `last` or a number, got {other:?}"))?,
    };
    let log = paths.audit_log();
    if !log.is_file() {
        println!("no audit log yet at {}", log.display());
        return Ok(ExitCode::SUCCESS);
    }
    let contents = std::fs::read_to_string(&log)?;
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        println!("audit log is empty");
        return Ok(ExitCode::SUCCESS);
    }
    for line in lines.iter().rev().take(n).rev() {
        // Pretty-print if it parses. An unparseable line is NOT echoed raw (doubt-pass
        // finding): only parsed events are known redaction-safe by construction; a corrupt
        // or tampered line could carry anything, and `vg audit` must never be the tool
        // that prints it.
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
            Err(e) => println!("[unparseable audit line withheld: {e}]"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `vg policy check`: loading the engine IS the validation (a malformed or
/// Phase-1-unsupported pack fails the whole load); then print the resolved summary.
fn cmd_policy_check(paths: StatePaths) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = Engine::open(paths)?;
    println!("policy version: {}", engine.policy_version());
    println!("layers dir:     {}", engine.paths().policy_dir().display());
    println!();
    println!("{:<16} class", "entity");
    for ty in FIXED_ENTITY_TYPES {
        println!(
            "{:<16} {:?}",
            format!("{ty:?}"),
            engine.classify_entity(ty.clone())
        );
    }
    println!();
    println!("policy loads and validates: OK");
    Ok(ExitCode::SUCCESS)
}

/// `vg vault stats`: mapping count via a direct inspection handle; never values.
fn cmd_vault_stats(paths: StatePaths) -> Result<ExitCode, Box<dyn std::error::Error>> {
    paths.ensure()?;
    let vault = open_vault(&paths)?;
    println!("vault db:  {}", paths.vault_db().display());
    println!("mappings:  {}", vault.mapping_count()?);
    Ok(ExitCode::SUCCESS)
}

/// `vg bench`: run the eval harness over the embedded seeded corpus and print the Go/No-Go
/// report. Uses this binary (`current_exe`) for the cold-hook latency measurement unless
/// `--no-hook`. Exits non-zero on NO-GO / INCOMPLETE so it is usable as a CI gate.
fn cmd_bench(hook_samples: usize, no_hook: bool) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !no_hook && hook_samples == 0 {
        return Err("--hook-samples must be >= 1 (or pass --no-hook)".into());
    }
    let hook_binary = if no_hook {
        None
    } else {
        // The cold-hook measurement spawns `vg hook` — this same binary. If we cannot locate
        // it, skip that measurement rather than fail the whole report.
        std::env::current_exe().ok()
    };
    let opts = vg_bench::Options {
        hook_binary,
        hook_iterations: hook_samples,
    };
    let report = vg_bench::run(&opts)?;
    print!("{}", vg_bench::render(&report));
    Ok(match report.verdict() {
        vg_bench::Verdict::Go => ExitCode::SUCCESS,
        vg_bench::Verdict::NoGo | vg_bench::Verdict::Incomplete => ExitCode::FAILURE,
    })
}

/// The 18 fixed entity types, for the `policy check` summary (the enum is
/// `#[non_exhaustive]`; `Custom` classes are pack-defined and not enumerable here).
const FIXED_ENTITY_TYPES: &[EntityType] = &[
    EntityType::Person,
    EntityType::Email,
    EntityType::Phone,
    EntityType::Address,
    EntityType::Postcode,
    EntityType::EmployeeId,
    EntityType::CustomerId,
    EntityType::AccountId,
    EntityType::Iban,
    EntityType::SortCode,
    EntityType::InternalIp,
    EntityType::Hostname,
    EntityType::ApiKey,
    EntityType::TraceId,
    EntityType::Password,
    EntityType::PrivateKey,
    EntityType::Secret,
    EntityType::AccessToken,
];

fn parse_destination(s: &str) -> Result<Destination, String> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "local-patch" => Ok(Destination::LocalPatch),
        "local-test-fixture" => Ok(Destination::LocalTestFixture),
        "local-explanation-buffer" => Ok(Destination::LocalExplanationBuffer),
        "remote-model-prompt" => Ok(Destination::RemoteModelPrompt),
        "observability-sink" => Ok(Destination::ObservabilitySink),
        other => Err(format!(
            "unknown destination {other:?} (local-patch | local-test-fixture | \
             local-explanation-buffer | remote-model-prompt | observability-sink)"
        )),
    }
}

fn exit_from_status(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, 255) as u8),
        None => ExitCode::FAILURE, // terminated by signal
    }
}
