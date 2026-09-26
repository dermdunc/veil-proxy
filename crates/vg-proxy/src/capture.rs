//! Dev-only wire capture for `handle_mask` (veil-demo's `/agent` plan, §4.1 component 1 as
//! amended by its §10 Q1 ruling). **Compiled only with `--features capture`**; a default build
//! does not contain this module at all, so a production daemon cannot be switched into
//! capturing by an environment variable, because there is nothing to switch on.
//!
//! With the feature compiled in, capture is still off unless `VG_PROXY_CAPTURE_DIR` names a
//! directory (read once, on the first masked request). Each `Mask`-route round trip then writes
//! two files, numbered in arrival order:
//!
//! - `NNNNNN-request.masked.json`: the exact bytes `upstream::forward` sends upstream, i.e.
//!   after masking. This is what "nothing raw crossed the wire" is asserted against.
//! - `NNNNNN-response.raw.{sse,json}`: the exact buffered upstream response bytes, **before**
//!   demasking. This is what the upstream actually returned.
//!
//! **Bodies only, never headers.** vg-proxy holds the client's credential regardless (it forwards
//! `authorization`/`x-api-key`), so this is not a safety boundary; it keeps the credential out of
//! the artifact.
//!
//! **`handle_mask` only.** `handle_pass` forwards bodies *unmasked* (`server.rs`), and it
//! deliberately has no call into this module: capturing there would put raw bytes into an
//! artifact whose whole claim is that no raw value crossed the wire. That is also why the hook
//! lives in `handle_mask` rather than in `upstream::forward`, which both handlers call.
//!
//! **Failure posture:** a write failure is reported on stderr (file name only) and never fails
//! or alters the proxied request. A capture tool must not change the behaviour it records. The
//! consumer detects a gap by checking that every request file has its response file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// The environment variable naming the capture directory.
pub const CAPTURE_DIR_ENV: &str = "VG_PROXY_CAPTURE_DIR";

static CAPTURE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

/// One `Mask`-route round trip's capture slot: the directory and this exchange's sequence number.
pub(crate) struct CaptureSlot {
    dir: &'static Path,
    seq: u64,
}

/// Returns a slot for this round trip if capture is enabled, `None` otherwise. The environment
/// is read once per process; creating the directory is attempted on that first read.
pub(crate) fn begin() -> Option<CaptureSlot> {
    let dir = CAPTURE_DIR
        .get_or_init(|| {
            let dir = std::env::var_os(CAPTURE_DIR_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)?;
            if let Err(err) = std::fs::create_dir_all(&dir) {
                eprintln!("vg-proxy capture: cannot create capture dir, capture disabled: {err}");
                return None;
            }
            Some(dir)
        })
        .as_deref()?;
    Some(CaptureSlot {
        dir,
        seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
    })
}

impl CaptureSlot {
    /// Writes the exact masked request body about to be sent upstream.
    pub(crate) fn write_request(&self, masked_body: &[u8]) {
        self.write(&format!("{:06}-request.masked.json", self.seq), masked_body);
    }

    /// Writes the exact buffered upstream response body, before any demasking.
    pub(crate) fn write_response(&self, raw_body: &[u8], is_sse: bool) {
        let ext = if is_sse { "sse" } else { "json" };
        self.write(&format!("{:06}-response.raw.{ext}", self.seq), raw_body);
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        if let Err(err) = std::fs::write(self.dir.join(name), bytes) {
            eprintln!("vg-proxy capture: failed to write {name}: {err}");
        }
    }
}
