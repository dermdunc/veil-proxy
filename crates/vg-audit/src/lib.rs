//! `vg-audit` — append-only, redaction-safe audit sink implementing `vg_core::AuditSink`.
//!
//! No raw values in any `AuditEvent` variant — refs/counts/versions only, property-tested
//! (`docs/architecture/interface-contracts.md` §7). That invariant belongs to the
//! *events* (the writers construct them; `vg_core::conformance::
//! assert_audit_event_excludes_raw_values` checks them); this crate's job is to persist
//! them append-only and versioned, and to never widen what an event carries.
//!
//! Storage is a JSON Lines file: one [`record::RecordV1`] per line, fsynced per write,
//! opened in `O_APPEND` mode and never truncated or rewritten. See `record` for the
//! versioned on-disk schema and `docs/decisions.md` (2026-07-17, T05b) for why JSONL
//! over SQLite.

mod record;
mod telemetry_sink;

pub use telemetry_sink::{
    SharedTelemetrySink, TelemetryConversionCounts, TelemetryCountingAuditSink, VariantCounts,
};

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;
use vg_core::{AuditError, AuditEvent, AuditId, AuditSink};

use record::{EventV1, RecordV1, VersionProbe, SCHEMA_VERSION};

/// Errors from [`JsonlAuditSink::open`]. A separate type from `vg_core::AuditError`
/// (which is frozen and write-shaped) because opening is this crate's own API, not part
/// of the `AuditSink` trait.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("audit log {}: io error: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The log contains a well-formed record written under a schema version this build
    /// does not know. Refusing to open is deliberate: silently skipping real records
    /// (rather than torn-write garbage) would make the audit trail quietly lossy.
    #[error(
        "audit log {}: line {line} has schema_version {version}, but this build reads \
         only up to {} — refusing to open with records it cannot represent",
        .path.display(),
        SCHEMA_VERSION
    )]
    UnknownSchemaVersion {
        path: PathBuf,
        line: usize,
        version: u32,
    },
    /// A *complete* line (newline-terminated, or an interior line) failed to parse as a
    /// record. Distinct from a torn final line (a crash mid-append, which is tolerated and
    /// counted in [`JsonlAuditSink::skipped_lines`]): a complete line that doesn't parse is
    /// corruption or tampering, and for an append-only audit trail refusing to open is the
    /// safe response — the same reasoning as `UnknownSchemaVersion`. Codex cross-model
    /// doubt-pass finding (2026-07-17): the original replay silently skipped *any*
    /// unparseable line, so a damaged interior record vanished without a trace, and a line
    /// with a malformed `schema_version` (e.g. `"2"` as a string) bypassed the strict
    /// unknown-version path entirely. No parse-error detail is included in the message: a
    /// corrupt line could contain a partially-written raw value, and this is a redaction
    /// tool — the line number is enough to locate it out-of-band.
    #[error(
        "audit log {}: line {line} is complete but does not parse as a valid audit record \
         — the log is corrupt or was tampered with; refusing to open",
        .path.display()
    )]
    CorruptLine { path: PathBuf, line: usize },
    /// Two records in the log carry the same `AuditId`. IDs are internally-generated
    /// UUIDv4s, so a collision cannot happen in normal operation — a duplicate on replay
    /// means the log was tampered with or spliced. Codex cross-model doubt-pass finding
    /// (2026-07-17): the original replay did `index.insert`, silently letting the later
    /// record shadow the earlier one in `get()` while `len()` under-counted — a
    /// tamper-hiding failure for an append-only trail.
    #[error(
        "audit log {}: line {line} repeats an AuditId already seen earlier — the \
         append-only log was tampered with or spliced; refusing to open",
        .path.display()
    )]
    DuplicateId { path: PathBuf, line: usize },
}

struct Inner {
    file: File,
    index: HashMap<AuditId, AuditEvent>,
    skipped_lines: usize,
}

/// Append-only [`AuditSink`] over a JSON Lines file.
///
/// - Every `write` appends one line and fsyncs before returning; the file is opened in
///   append mode and never truncated.
/// - `get` serves from an in-memory index built by replaying the file at `open`. **This
///   assumes a single live sink per file within one process** (fine for Phase 1's
///   in-process, per-invocation lifetime): a second `JsonlAuditSink` on the same path, or
///   another process appending, will not be reflected in this sink's index until it is
///   reopened — `O_APPEND` keeps writes from tearing each other, but does not keep separate
///   in-memory indexes coherent. An offset index / shared coordination would replace this
///   if logs outgrow memory or need concurrent openers (out of Phase 1 scope).
/// - Recovery at `open` distinguishes a **torn final line** (a crash mid-append — tolerated,
///   counted in [`skipped_lines`](Self::skipped_lines), then truncated away so later appends
///   start from the last complete record) from a **complete line that fails to parse** (an
///   interior line, or
///   the final line when the file ends in a newline): the latter is corruption or tampering
///   and is a hard [`OpenError::CorruptLine`], never silently skipped. An unknown *schema
///   version* on a complete line is a hard [`OpenError::UnknownSchemaVersion`]; a repeated
///   `AuditId` is a hard [`OpenError::DuplicateId`]. The bias throughout is "refuse to open a
///   damaged audit trail" over "quietly open a lossy one."
///
/// **Redaction-safety boundary (this crate does not enforce it, by design):** the "no raw
/// value ever persisted" guarantee is a property of the *events* — the masking pipeline that
/// constructs them (Task T07) must not put raw detected values into a free-text field like
/// `Block.reason`, and `vg_core::conformance::assert_audit_event_excludes_raw_values` checks
/// that at construction time. This sink faithfully persists whatever event it is handed and
/// has no oracle for what is "raw" (it never sees the vault or the original values), so it
/// cannot and does not scrub. A caller that hands it a leaky event will persist a leaky
/// event; keeping events clean is the caller's contract, not the sink's.
pub struct JsonlAuditSink {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for JsonlAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlAuditSink")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl JsonlAuditSink {
    /// Opens (creating if absent) the audit log at `path` and replays it into the
    /// in-memory index.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref().to_path_buf();
        let io_err = |source| OpenError::Io {
            path: path.clone(),
            source,
        };

        let created = !path.exists();

        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(io_err)?;

        // If we just created the file, fsync the parent directory so the new dirent
        // survives a crash — file-level fsync alone doesn't guarantee the directory entry
        // is durable on filesystems that require an explicit directory sync (Codex
        // doubt-pass finding, 2026-07-17).
        if created {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        // Read raw bytes, not `read_to_string`: a crash mid-multibyte-UTF-8-sequence in the
        // torn final line would make a whole-file `read_to_string` fail, bricking an
        // otherwise-recoverable log (Codex doubt-pass finding, 2026-07-17). Decode per line
        // instead, so invalid UTF-8 can be confined to (and tolerated in) the torn tail.
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).map_err(io_err)?;

        let ends_with_newline = raw.last() == Some(&b'\n');
        // `split` on b'\n': a trailing newline yields a final empty element (dropped
        // below); no trailing newline means the last element is a *possibly torn* tail. A
        // line is tolerable-if-unparseable ONLY when it is that torn tail; every complete
        // line (interior, or the last one when the file ends in a newline) must parse or
        // the log is corrupt.
        let mut byte_lines: Vec<&[u8]> = raw.split(|&b| b == b'\n').collect();
        if ends_with_newline {
            byte_lines.pop(); // drop the empty element after the final newline
        }
        let torn_tail_idx = if ends_with_newline {
            None
        } else {
            // The last element is the torn tail (unless the file was empty).
            byte_lines.len().checked_sub(1)
        };

        let mut index: HashMap<AuditId, AuditEvent> = HashMap::new();
        let mut skipped_lines = 0;
        for (i, line_bytes) in byte_lines.iter().enumerate() {
            let line_no = i + 1;
            let is_torn_tail = torn_tail_idx == Some(i);

            // The torn final line is an incomplete write that gets truncated below (see the
            // recovery block). Skip it here *unconditionally* — even if it happens to be a
            // complete, parseable record. Codex critique (2026-07-17): the earlier version
            // indexed a torn tail that parsed, then truncated it off disk, so `get()` and
            // `len()` reported an event that a reopen would then lose — an index/disk
            // inconsistency. A record whose terminating newline never landed was never a
            // durably-committed record for this sink (writes are `record + '\n'` + fsync), so
            // discarding it is correct, and now index and disk agree.
            if is_torn_tail {
                skipped_lines += 1;
                continue;
            }

            // A blank complete line is benign — skip without counting it as a torn write.
            if line_bytes.is_empty() {
                continue;
            }

            // Every line reaching here is a *complete* line (the torn tail was skipped
            // above), so an unparseable one is corruption/tampering, never tolerable.
            macro_rules! corrupt {
                () => {
                    return Err(OpenError::CorruptLine {
                        path: path.clone(),
                        line: line_no,
                    })
                };
            }

            let Ok(line) = std::str::from_utf8(line_bytes) else {
                corrupt!();
            };
            let Ok(probe) = serde_json::from_str::<VersionProbe>(line) else {
                corrupt!();
            };
            if probe.schema_version != SCHEMA_VERSION {
                return Err(OpenError::UnknownSchemaVersion {
                    path: path.clone(),
                    line: line_no,
                    version: probe.schema_version,
                });
            }
            let Ok(rec) = serde_json::from_str::<RecordV1>(line) else {
                corrupt!();
            };
            if index.insert(AuditId(rec.id), rec.event.into()).is_some() {
                return Err(OpenError::DuplicateId {
                    path: path.clone(),
                    line: line_no,
                });
            }
        }

        // Recover a torn final line by *truncating* it back to the last complete record,
        // rather than newline-healing it. This sink appends `record + '\n'` and fsyncs per
        // write, so a durable record always ends in a newline; a tail without one is an
        // incomplete write the crash left behind — never a committed record, so removing it
        // is honest recovery, not history rewriting. Truncating (vs. the earlier
        // newline-heal) also keeps the file all-complete-lines, so the strict "a complete
        // line must parse or the log is corrupt" rule above holds cleanly on every reopen
        // instead of tripping over an immortalised, forever-skipped garbage fragment (Codex
        // doubt-pass, 2026-07-17).
        if !raw.is_empty() && !ends_with_newline {
            let keep = match raw.iter().rposition(|&b| b == b'\n') {
                Some(idx) => idx + 1, // keep everything through the last newline
                None => 0,            // the whole file is a single torn line
            };
            file.set_len(keep as u64).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }

        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                file,
                index,
                skipped_lines,
            }),
        })
    }

    /// Path of the underlying JSONL file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of events currently retrievable via `get`.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.index.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lines skipped as unparseable when the log was opened (torn writes). Nonzero means
    /// a previous writer crashed mid-append; the events before and after are intact.
    pub fn skipped_lines(&self) -> usize {
        self.inner.lock().map(|i| i.skipped_lines).unwrap_or(0)
    }
}

impl AuditSink for JsonlAuditSink {
    fn write(&self, event: AuditEvent) -> Result<AuditId, AuditError> {
        let event_v1 = EventV1::try_from(&event)?;
        let id = AuditId(Uuid::new_v4());
        let mut line = serde_json::to_string(&RecordV1 {
            schema_version: SCHEMA_VERSION,
            id: id.0,
            event: event_v1,
        })
        .map_err(|e| AuditError::Write(format!("serialize audit record: {e}")))?;
        line.push('\n');

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| AuditError::Write("audit sink mutex poisoned".to_string()))?;
        inner
            .file
            .write_all(line.as_bytes())
            .map_err(|e| AuditError::Write(format!("append audit record: {e}")))?;
        inner
            .file
            .sync_all()
            .map_err(|e| AuditError::Write(format!("fsync audit log: {e}")))?;

        // Index what the *storage schema* round-trips to, not the caller's original
        // value — so `get` answers identically before and after a reopen, and a lossy
        // conversion would fail the conformance roundtrip test instead of hiding until
        // the first restart.
        let line = line.trim_end();
        let rec: RecordV1 = serde_json::from_str(line)
            .map_err(|e| AuditError::Write(format!("reparse audit record: {e}")))?;
        inner.index.insert(id, rec.event.into());
        Ok(id)
    }

    fn get(&self, id: AuditId) -> Option<AuditEvent> {
        self.inner.lock().ok()?.index.get(&id).cloned()
    }
}
