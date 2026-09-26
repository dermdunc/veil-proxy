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
//! **Bodies from `handle_mask` only.** `handle_pass` forwards bodies *unmasked* (`server.rs`), so
//! its bodies are never captured: that would put raw bytes into an artifact whose whole claim is
//! that no raw value crossed the wire. That is also why the body hooks live in `handle_mask`
//! rather than in `upstream::forward`, which both handlers call. But a Pass route is still
//! egress, so each Pass exchange is recorded as **metadata only** in
//! `PNNNNNN-pass.meta.json`: method, path-and-query, and body length, never the body. A consumer
//! can then refuse to vouch for a capture in which any Pass request carried a body. (Adversarial
//! review of veil-proxy#88: without this, Pass-route egress was invisible to every check.)
//!
//! On first use, `capture-info.json` is written to the directory, declaring this format. A
//! consumer can require it and so reject captures from a build without Pass-route metadata.
//!
//! **Known trade-offs (dev-only feature):** the request file is written just *before*
//! `upstream::forward`, so if the send then fails (connect, TLS, timeout) a request file exists
//! without a response file. Consumers must treat an unpaired request as a failed or incomplete
//! exchange, never as evidence of egress. The writes are synchronous `std::fs` calls on the async
//! worker: fine for a local capture directory, but a stalled filesystem would stall the proxy.
//!
//! **Failure posture:** a write failure is reported on stderr (file name only) and never fails
//! or alters the proxied request. A capture tool must not change the behaviour it records. The
//! consumer detects a gap by checking that every request file has its response file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// The environment variable naming the capture directory.
pub const CAPTURE_DIR_ENV: &str = "VG_PROXY_CAPTURE_DIR";

/// Version of the on-disk layout; bumped when a consumer-visible file kind changes.
pub const CAPTURE_FORMAT: u32 = 2;

static CAPTURE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
static NEXT_PASS_SEQ: AtomicU64 = AtomicU64::new(1);

/// One `Mask`-route round trip's capture slot: the directory and this exchange's sequence number.
pub(crate) struct CaptureSlot {
    dir: &'static Path,
    seq: u64,
}

/// The capture directory, if capture is enabled. The environment is read once per process;
/// creating the directory and writing `capture-info.json` happen on that first read.
fn capture_dir() -> Option<&'static Path> {
    CAPTURE_DIR
        .get_or_init(|| {
            let dir = std::env::var_os(CAPTURE_DIR_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)?;
            if let Err(err) = std::fs::create_dir_all(&dir) {
                eprintln!("vg-proxy capture: cannot create capture dir, capture disabled: {err}");
                return None;
            }
            let info = serde_json::json!({
                "format": CAPTURE_FORMAT,
                "pass_route_metadata": true,
                "request_written_before_send": true,
            });
            write_file(&dir, "capture-info.json", info.to_string().as_bytes());
            Some(dir)
        })
        .as_deref()
}

/// Returns a slot for this `Mask` round trip if capture is enabled, `None` otherwise.
pub(crate) fn begin() -> Option<CaptureSlot> {
    Some(CaptureSlot {
        dir: capture_dir()?,
        seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
    })
}

/// Records one `Pass` exchange as metadata only (never the body, which is forwarded unmasked).
pub(crate) fn record_pass(method: &str, path_and_query: &str, body_len: usize) {
    let Some(dir) = capture_dir() else { return };
    let seq = NEXT_PASS_SEQ.fetch_add(1, Ordering::Relaxed);
    let meta = serde_json::json!({
        "method": method,
        "path_and_query": path_and_query,
        "body_len": body_len,
    });
    write_file(
        dir,
        &format!("P{seq:06}-pass.meta.json"),
        meta.to_string().as_bytes(),
    );
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) {
    if let Err(err) = std::fs::write(dir.join(name), bytes) {
        eprintln!("vg-proxy capture: failed to write {name}: {err}");
    }
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
        write_file(self.dir, name, bytes);
    }
}
