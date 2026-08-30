//! Fire-and-forget, fail-open HTTP transport for a signed `veil.edge_event.v1` record
//! ([`super::signing::sign_edge_event_record`]'s output) to `veil-observatory`.
//!
//! **The trust-boundary rule this module exists to enforce**: telemetry only crosses the
//! process boundary if an organisation has opted in to *both* a signing key
//! ([`super::signing::VEIL_RECEIPT_KEY_ENV_VAR`]) and an observatory endpoint
//! ([`VEIL_OBSERVATORY_ENDPOINT_ENV_VAR`]). [`edge_event_emitter_from_env`] returns
//! `Ok(None)` — a documented no-op, not an error — whenever *either* is unset. Critically,
//! this is a **structural** guarantee, not a policy one: the branch that returns early on
//! a missing var runs before [`EdgeEventEmitterHandle::connect`] is ever called, so no
//! channel, no background thread, and no HTTP client are constructed at all when
//! telemetry is opted out (see `edge_event_emitter_from_env_is_a_structural_no_op_when...`
//! in this module's own tests, which proves this by calling the pure, env-free core
//! directly rather than only checking that nothing gets sent).
//!
//! **Fire-and-forget, by construction.** `vg-audit`'s `AuditSink::write` is a synchronous
//! API called from proxy hot paths and must never block on, slow down for, or fail
//! because of a network call. [`EdgeEventEmitterHandle::try_emit`] therefore never blocks:
//! it does a non-blocking `try_send` onto a bounded `std::sync::mpsc` channel and returns
//! immediately, dropping (and counting) the record if the channel is full or the
//! background worker is gone. A dedicated background OS thread — not the caller's runtime,
//! and not a shared pool — owns a single-threaded Tokio runtime and drains the channel,
//! POSTing each record's canonical JSON to the configured endpoint with a short fixed
//! timeout. Any failure (connection refused, timeout, non-2xx) is counted and dropped:
//! no retry, no backpressure, no panic.
//!
//! **Why a dedicated thread + runtime, not `tokio::spawn` onto an ambient runtime**:
//! `TelemetryCountingAuditSink` (`vg-audit`) is constructed and called from both an async
//! context (`vg-proxy`'s daemon, already inside a multi-thread Tokio runtime — see
//! `crates/vg-proxy/src/upstream.rs`'s `hyper::client::conn::http1` pattern, reused
//! here almost verbatim) *and* a fully synchronous one
//! (`vg-adapters-claude::runtime::Engine::open`/`write`, invoked per-hook from a plain,
//! non-async CLI binary with no ambient runtime at all). `tokio::spawn` panics outside a
//! runtime context, so the emitter cannot assume one exists — it brings its own,
//! unconditionally, only when actually opted in.
//!
//! **What signs the record is not this module.** `envelope.rs`'s own doc states the
//! architectural rule this module respects: "`vg-core` has no timestamp source of its own
//! ... `vg-core` never reads the clock itself." Building the `EdgeEventRecordInput`
//! (fresh `record_id`/`nonce` via `uuid::Uuid::new_v4`, `issued_at_us` via
//! `SystemTime::now`, a monotonic `sequence`) and calling
//! [`super::signing::sign_edge_event_record`] both happen in the caller
//! (`vg-audit::telemetry_sink`), which is not bound by that rule. This module only ever
//! receives an already-signed `canonical_json` `String` and transports it; it exposes the
//! caller's [`ReceiptSigningKey`] back out via [`EdgeEventEmitterHandle::signing_key`] so
//! the caller can sign with the same key this handle was built from, without a second
//! `VEIL_RECEIPT_KEY` read.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::TcpStream;

use super::signing::{
    parse_receipt_signing_key, ReceiptSigningKey, SigningError, VEIL_RECEIPT_KEY_ENV_VAR,
};

/// The env var [`edge_event_emitter_from_env`] reads for the observatory's full URL
/// (scheme + host + port + path, e.g. `http://127.0.0.1:8787/v1/edge-events`) — the whole
/// string is used verbatim as the POST target, no path suffix is appended here.
pub const VEIL_OBSERVATORY_ENDPOINT_ENV_VAR: &str = "VEIL_OBSERVATORY_ENDPOINT";

/// Bounded channel capacity between `AuditSink::write` (producer) and the background
/// poster thread (consumer). A generous burst allowance, not a durability guarantee —
/// this MVP is explicitly fire-and-forget (no retry, no persistence): once full, new
/// records are dropped and counted, never queued indefinitely or blocked on.
const CHANNEL_CAPACITY: usize = 256;

/// Fixed per-request timeout: long enough that a healthy loopback observatory always
/// responds well within it, short enough that a hung/unreachable endpoint can never tie up
/// the background worker (or leak a socket) for more than a few seconds. Not
/// configurable — retry/backoff tuning is explicitly out of scope for this MVP.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// How long [`EdgeEventEmitterHandle`]'s `Drop` impl waits for already-`try_emit`ted
/// records to actually be sent before giving up. Exists specifically for the short-lived
/// CLI hook process this module's doc names as one of two call contexts: with no explicit
/// flush, that process's `main` can return and exit before the background thread's own
/// connect+handshake+POST sequence ever gets scheduled, silently dropping telemetry despite
/// every existing test passing (they all run inside a long-lived `cargo test` process and
/// poll for the outcome, which has no analogue in the real short-lived binary). Short enough
/// that a healthy loopback delivery (the common case) finishes well within it and a hung one
/// doesn't meaningfully delay a CLI process's own exit.
const FLUSH_ON_DROP_TIMEOUT: Duration = Duration::from_millis(500);

/// Extra grace period, after [`FLUSH_ON_DROP_TIMEOUT`], for the background thread to
/// actually finish and be joined once its channel is closed. If it still hasn't finished
/// after this, the thread is abandoned rather than joined — `std::thread::JoinHandle` has
/// no timed join in `std`, and blocking a caller's shutdown path indefinitely would be
/// worse than leaking one thread that will still run to completion (or be killed by the
/// process's own exit) on its own.
const JOIN_GRACE_PERIOD: Duration = Duration::from_millis(200);

/// The observatory's full POST target, as configured via [`VEIL_OBSERVATORY_ENDPOINT_ENV_VAR`].
/// A type alias, not a newtype: this is `vg-core`'s only HTTP-client-facing surface, and
/// wrapping `hyper::Uri` further would add ceremony without adding any validation this
/// module doesn't already do at parse time (see [`parse_observatory_endpoint`]).
pub type ObservatoryEndpoint = hyper::Uri;

/// Why [`edge_event_emitter_from_env`] could not build an emitter, for a `VEIL_RECEIPT_KEY`
/// / `VEIL_OBSERVATORY_ENDPOINT` pair where *both* vars are actually present (an *absent*
/// var is never an error — see this module's own doc). Every variant here reflects a real
/// misconfiguration of an already-opted-in feature, not an opt-out.
#[derive(Debug, Error)]
pub enum EmitterInitError {
    #[error("{VEIL_RECEIPT_KEY_ENV_VAR} environment variable is not valid UTF-8")]
    KeyEnvVarNotUnicode,
    #[error("{VEIL_OBSERVATORY_ENDPOINT_ENV_VAR} environment variable is not valid UTF-8")]
    EndpointEnvVarNotUnicode,
    #[error("failed to parse {VEIL_RECEIPT_KEY_ENV_VAR}: {0}")]
    Signing(SigningError),
    #[error("{VEIL_OBSERVATORY_ENDPOINT_ENV_VAR} is not a valid absolute URL")]
    EndpointInvalidUri,
    #[error(
        "{VEIL_OBSERVATORY_ENDPOINT_ENV_VAR} must use the http scheme (TLS is out of scope \
         for this MVP -- see `emitter.rs`'s module doc)"
    )]
    EndpointNotHttp,
    #[error("{VEIL_OBSERVATORY_ENDPOINT_ENV_VAR} must include a host")]
    EndpointMissingHost,
    #[error("failed to spawn the edge-event emitter's background thread: {0}")]
    ThreadSpawnFailed(std::io::Error),
}

/// A snapshot of one [`EdgeEventEmitterHandle`]'s outcome counters. Cheap to read
/// (relaxed atomic loads) — safe to call from a hot path or a test assertion alike.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmitterStats {
    /// Records dropped by [`EdgeEventEmitterHandle::try_emit`] because the channel was
    /// full or the background worker had already exited.
    pub queue_full_dropped: u64,
    /// Records the background worker successfully POSTed and received a 2xx for.
    pub sent_ok: u64,
    /// Records the background worker attempted to POST but failed (connect error,
    /// timeout, non-2xx response) — dropped after exactly one attempt, never retried.
    pub send_failed: u64,
}

#[derive(Default)]
struct EmitterStatsInner {
    queue_full_dropped: AtomicU64,
    sent_ok: AtomicU64,
    send_failed: AtomicU64,
}

/// A live, opted-in edge-event emitter: a signing key (for the caller to sign with) plus
/// a handle onto a bounded channel feeding a dedicated background poster thread/runtime.
/// Constructed only by [`edge_event_emitter_from_env`] (env-gated) or
/// [`EdgeEventEmitterHandle::connect`] (explicit, for tests) — never implicitly.
///
/// `Send + Sync`: `mpsc::SyncSender<String>` is `Send + Sync` for a `Send` payload (`String`)
/// on this crate's Rust edition (std's mpsc has been `Sync` since the 1.72 rewrite), and
/// every other field is a plain `Arc`/key value — required for use behind
/// `Box<dyn AuditSink>` (`AuditSink: Send + Sync`, `crate::traits`).
pub struct EdgeEventEmitterHandle {
    key: ReceiptSigningKey,
    // `Option` so `Drop` can close the channel (by taking and dropping the sender) before
    // joining the background thread -- the thread's `recv()` loop only returns `Err` and
    // exits once every sender side is gone, so joining first would hang forever.
    sender: Option<mpsc::SyncSender<String>>,
    stats: Arc<EmitterStatsInner>,
    // How many `try_emit` calls this handle has successfully enqueued (queue-full drops
    // excluded) -- what `flush` waits for `stats.sent_ok + stats.send_failed` to catch up
    // to. Plain, not `Arc`: only ever read/written from calls on this same handle (never
    // shared with the background thread directly), so no cross-thread ownership is needed.
    enqueued: AtomicU64,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl EdgeEventEmitterHandle {
    /// Builds a live emitter and spawns its background poster thread immediately.
    /// Intended for [`edge_event_emitter_from_env`]'s Some/Some branch and for tests that
    /// want to construct a handle explicitly (a real local test server, an unreachable
    /// port, ...) without mutating real process environment variables.
    ///
    /// Fallible, deliberately: under OS thread exhaustion (`ulimit` hit, `ENOMEM`/`EAGAIN`
    /// from `pthread_create` -- realistic under load on a busy `vg-proxy` host), spawning
    /// can fail. This module's whole reason to exist is "fail open, never panic" for a
    /// telemetry-only condition; the caller (`edge_event_emitter_from_env`, ultimately
    /// `vg-audit`'s `TelemetryCountingAuditSink::new`) already has a real error path for
    /// "this opted-in feature is misconfigured, disable it and keep going" -- panicking here
    /// instead of returning into that path would let a telemetry-only failure crash an
    /// entire hook invocation or daemon startup, precisely under the resource pressure where
    /// inert-by-default matters most.
    pub fn connect(key: ReceiptSigningKey, endpoint: ObservatoryEndpoint) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<String>(CHANNEL_CAPACITY);
        let stats = Arc::new(EmitterStatsInner::default());
        let worker_stats = Arc::clone(&stats);
        // Deliberately not `tokio::spawn` onto an ambient runtime -- see this module's
        // own doc for why a caller-supplied runtime cannot be assumed to exist.
        let join_handle = std::thread::Builder::new()
            .name("veil-edge-event-emitter".to_string())
            .spawn(move || run_poster_loop(endpoint, receiver, worker_stats))?;
        Ok(Self {
            key,
            sender: Some(sender),
            stats,
            enqueued: AtomicU64::new(0),
            join_handle: Some(join_handle),
        })
    }

    /// The signing key this handle was built from, so the caller (`vg-audit`) can sign an
    /// `EdgeEventRecordInput` with the exact same key without re-reading
    /// `VEIL_RECEIPT_KEY` itself.
    pub fn signing_key(&self) -> &ReceiptSigningKey {
        &self.key
    }

    /// Hands `canonical_json` (a [`super::signing::SignedEdgeEventRecord::canonical_json`])
    /// to the background poster. Never blocks: a full channel or a gone worker both count
    /// as a drop and return `false` immediately. Returns `true` only if the record was
    /// successfully enqueued — delivery is still not guaranteed even then (the background
    /// worker may yet fail to send it; see [`EmitterStats::send_failed`]).
    pub fn try_emit(&self, canonical_json: String) -> bool {
        // `None` only once `Drop` has started, which only happens once this handle's last
        // owning reference is gone (it lives behind one `Arc`, via `vg-audit`'s
        // `SharedTelemetrySink`) -- so no other call can race a `try_emit` against that.
        // Guarded rather than assumed anyway: failing open (report "dropped", same as a
        // full channel) is the correct degradation for a call that somehow still happens.
        let Some(sender) = self.sender.as_ref() else {
            self.stats
                .queue_full_dropped
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        match sender.try_send(canonical_json) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.stats
                    .queue_full_dropped
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// A snapshot of this handle's outcome counters.
    pub fn stats(&self) -> EmitterStats {
        EmitterStats {
            queue_full_dropped: self.stats.queue_full_dropped.load(Ordering::Relaxed),
            sent_ok: self.stats.sent_ok.load(Ordering::Relaxed),
            send_failed: self.stats.send_failed.load(Ordering::Relaxed),
        }
    }

    /// Waits, up to `timeout`, for every record already handed to [`try_emit`] to be either
    /// sent or given up on. Does not stop `try_emit` from enqueueing further work in the
    /// meantime -- this is a best-effort drain, not a barrier. Exposed mainly so `Drop` can
    /// call it with a short, fixed bound; `pub(crate)` since no caller outside this crate
    /// should need to reach for it directly (dropping the handle is the intended trigger).
    pub(crate) fn flush(&self, timeout: Duration) {
        let target = self.enqueued.load(Ordering::Relaxed);
        let started = std::time::Instant::now();
        loop {
            let stats = self.stats();
            if stats.sent_ok + stats.send_failed >= target {
                return;
            }
            if started.elapsed() >= timeout {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for EdgeEventEmitterHandle {
    /// Best-effort, bounded drain on drop — see [`FLUSH_ON_DROP_TIMEOUT`]'s own doc for why
    /// this exists (the short-lived CLI hook process is one of this module's two designed-for
    /// call contexts, and without this, its `main` can return and exit before the background
    /// thread's connect+handshake+POST ever gets scheduled, silently dropping telemetry).
    ///
    /// Still fire-and-forget in spirit: this is a best effort to WIN the race against process
    /// exit within a short, bounded window, not a durability guarantee for an arbitrarily
    /// large burst queued right before shutdown.
    fn drop(&mut self) {
        self.flush(FLUSH_ON_DROP_TIMEOUT);
        // Close the channel so the background loop's `recv()` returns `Err` and the thread
        // exits, once whatever's already queued (if `flush` timed out before it all drained)
        // is done. Must happen before the join attempt below, or a still-open channel with no
        // sender activity blocks `recv()` -- and therefore the thread's exit -- forever.
        self.sender.take();
        let Some(handle) = self.join_handle.take() else {
            return;
        };
        // `std::thread::JoinHandle` has no timed join in `std`. Poll `is_finished()` for a
        // short grace period instead of blocking indefinitely on `join()`: a caller's
        // shutdown path (notably `vg-cli`'s hook process) must never hang because one
        // background thread is slow to unwind, even though the common case (an already-
        // flushed, idle thread) finishes this loop on its first check.
        let deadline = std::time::Instant::now() + JOIN_GRACE_PERIOD;
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
        // else: the thread is abandoned, not leaked in the sense that matters here -- it
        // will still run to completion (bounded by `REQUEST_TIMEOUT` per remaining record)
        // or be reclaimed by the OS at process exit, whichever comes first.
    }
}

/// The background poster's whole life: owns a single-threaded Tokio runtime, drains
/// `receiver` until every [`EdgeEventEmitterHandle::try_emit`] side has been dropped (at
/// which point `recv()` returns `Err` and the loop, and thread, exit cleanly), POSTing
/// each record in turn. One POST at a time, sequentially -- batching/concurrency is
/// explicitly out of scope for this fire-and-forget MVP.
fn run_poster_loop(
    endpoint: ObservatoryEndpoint,
    receiver: mpsc::Receiver<String>,
    stats: Arc<EmitterStatsInner>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!(
                "veilgremlin: edge-event emitter thread failed to start a Tokio runtime, \
                 telemetry POSTs will not be sent: {err}"
            );
            return;
        }
    };
    rt.block_on(async move {
        while let Ok(body) = receiver.recv() {
            match post_edge_event(&endpoint, body).await {
                Ok(()) => {
                    stats.sent_ok.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    stats.send_failed.fetch_add(1, Ordering::Relaxed);
                    // Logged for operator visibility only -- never the body itself
                    // (already-signed telemetry, but this module has no business
                    // deciding it's safe to print).
                    eprintln!("veilgremlin: edge-event POST failed, dropping: {err}");
                }
            }
        }
    });
}

/// Why one POST attempt failed. Never retried, never propagated to `try_emit`'s caller —
/// this exists purely so [`run_poster_loop`]'s one log line can say something useful.
#[derive(Debug, Error)]
enum PostError {
    #[error("request timed out after {REQUEST_TIMEOUT:?}")]
    Timeout,
    #[error("connect failed: {0}")]
    Connect(#[from] std::io::Error),
    #[error("HTTP/1.1 handshake failed: {0}")]
    Handshake(hyper::Error),
    #[error("failed to build request: {0}")]
    BuildRequest(#[from] hyper::http::Error),
    #[error("request send failed: {0}")]
    Send(hyper::Error),
    #[error("observatory returned non-success status {0}")]
    NonSuccess(hyper::StatusCode),
}

async fn post_edge_event(endpoint: &ObservatoryEndpoint, body: String) -> Result<(), PostError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, post_edge_event_inner(endpoint, body)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(PostError::Timeout),
    }
}

async fn post_edge_event_inner(
    endpoint: &ObservatoryEndpoint,
    body: String,
) -> Result<(), PostError> {
    // Same low-level `hyper::client::conn::http1` shape `vg-proxy`'s own
    // `upstream.rs::forward` already uses for its outbound leg -- one connection per
    // request, no pooling, deliberately (this crate's own doc explains why: a
    // fire-and-forget MVP, not a durable/high-throughput delivery path).
    let host = endpoint.host().ok_or_else(|| {
        // Unreachable in practice: `parse_observatory_endpoint` already rejects a
        // hostless URI before an `EdgeEventEmitterHandle` can ever be constructed with
        // one. Guarded anyway rather than `.unwrap()`-ing, since `EdgeEventEmitterHandle::
        // connect` is a public, test-reachable constructor that does not itself
        // re-validate its `endpoint` argument.
        PostError::Connect(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "observatory endpoint has no host",
        ))
    })?;
    let port = endpoint.port_u16().unwrap_or(80);
    let path = endpoint.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    let stream = TcpStream::connect((host, port)).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(PostError::Handshake)?;
    // Detached, exactly like `upstream.rs::forward`: nothing after `send_request` below
    // needs the connection driven any further than that one response.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let host_header = match endpoint.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(path)
        .header("host", host_header)
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .body(Full::new(Bytes::from(body)))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(PostError::Send)?;
    if !response.status().is_success() {
        return Err(PostError::NonSuccess(response.status()));
    }
    // Body is not needed, but must still be driven to completion so the connection task
    // above can finish cleanly rather than being dropped mid-response.
    use http_body_util::BodyExt;
    let _ = response.into_body().collect().await;
    Ok(())
}

/// Real entry point: reads both [`VEIL_RECEIPT_KEY_ENV_VAR`] and
/// [`VEIL_OBSERVATORY_ENDPOINT_ENV_VAR`] from the process environment and, if both are
/// present and valid, builds a live [`EdgeEventEmitterHandle`]. Returns `Ok(None)` — never
/// an error — if either var is absent: see this module's own doc for why that's a
/// structural, not merely conventional, opt-out.
pub fn edge_event_emitter_from_env() -> Result<Option<EdgeEventEmitterHandle>, EmitterInitError> {
    build_edge_event_emitter(
        std::env::var(VEIL_RECEIPT_KEY_ENV_VAR),
        std::env::var(VEIL_OBSERVATORY_ENDPOINT_ENV_VAR),
    )
}

/// The testable core of [`edge_event_emitter_from_env`]: given the two env vars' already-
/// read raw results, decides whether to build an emitter at all and, if so, builds it.
/// Split out for the same parallel-`cargo test`-safety reason
/// `signing::parse_receipt_signing_key` was: lets a test exercise every branch (both
/// unset, one unset, both set-and-valid, both set-and-invalid) without mutating real
/// process environment state.
fn build_edge_event_emitter(
    key_var: Result<String, std::env::VarError>,
    endpoint_var: Result<String, std::env::VarError>,
) -> Result<Option<EdgeEventEmitterHandle>, EmitterInitError> {
    use std::env::VarError;

    let key_raw = match key_var {
        Ok(v) => Some(v),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => return Err(EmitterInitError::KeyEnvVarNotUnicode),
    };
    let endpoint_raw = match endpoint_var {
        Ok(v) => Some(v),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => return Err(EmitterInitError::EndpointEnvVarNotUnicode),
    };

    // The opt-in gate itself: *either* var absent is a documented no-op, full stop --
    // this branch returns before `EdgeEventEmitterHandle::connect` (channel + thread +
    // client construction) is ever reached, which is exactly the structural guarantee
    // this module's doc comment describes.
    let (key_raw, endpoint_raw) = match (key_raw, endpoint_raw) {
        (Some(k), Some(e)) => (k, e),
        _ => return Ok(None),
    };

    let key = parse_receipt_signing_key(Some(key_raw)).map_err(EmitterInitError::Signing)?;
    let endpoint = parse_observatory_endpoint(&endpoint_raw)?;
    let handle = EdgeEventEmitterHandle::connect(key, endpoint)
        .map_err(EmitterInitError::ThreadSpawnFailed)?;
    Ok(Some(handle))
}

/// Parses and validates [`VEIL_OBSERVATORY_ENDPOINT_ENV_VAR`]'s raw value: must be an
/// absolute `http://` URL with a host. The whole string is the POST target verbatim (task
/// scope: "assume this is the FULL URL including path... do not hardcode a path suffix").
fn parse_observatory_endpoint(raw: &str) -> Result<ObservatoryEndpoint, EmitterInitError> {
    let uri: hyper::Uri = raw
        .trim()
        .parse()
        .map_err(|_| EmitterInitError::EndpointInvalidUri)?;
    match uri.scheme_str() {
        Some("http") => {}
        _ => return Err(EmitterInitError::EndpointNotHttp),
    }
    if uri.host().is_none() {
        return Err(EmitterInitError::EndpointMissingHost);
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn sample_key() -> ReceiptSigningKey {
        ReceiptSigningKey::from_bytes(vec![7u8; 32]).unwrap()
    }

    // -- opt-in gating (structural, not merely behavioural) --

    #[test]
    fn both_env_vars_unset_is_a_structural_no_op() {
        // Calls the pure, env-free core directly with both vars "not present" -- proves
        // by the function's own control flow (see `build_edge_event_emitter`'s own
        // comment on this exact branch) that `EdgeEventEmitterHandle::connect` -- and
        // therefore the channel, the background thread, and the HTTP client -- is never
        // reached, not merely that nothing ends up being sent.
        let result = build_edge_event_emitter(
            Err(std::env::VarError::NotPresent),
            Err(std::env::VarError::NotPresent),
        );
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn key_set_but_endpoint_unset_is_still_a_no_op() {
        let result =
            build_edge_event_emitter(Ok("ab".repeat(32)), Err(std::env::VarError::NotPresent));
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn endpoint_set_but_key_unset_is_still_a_no_op() {
        let result = build_edge_event_emitter(
            Err(std::env::VarError::NotPresent),
            Ok("http://127.0.0.1:8787/v1/edge-events".to_string()),
        );
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn both_set_and_valid_builds_a_live_handle() {
        let result = build_edge_event_emitter(
            Ok("ab".repeat(32)),
            Ok("http://127.0.0.1:8787/v1/edge-events".to_string()),
        );
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn both_set_but_key_invalid_is_a_real_error_not_a_silent_no_op() {
        let result = build_edge_event_emitter(
            Ok("not-hex".to_string()),
            Ok("http://127.0.0.1:8787/v1/edge-events".to_string()),
        );
        assert!(matches!(result, Err(EmitterInitError::Signing(_))));
    }

    #[test]
    fn both_set_but_endpoint_missing_scheme_is_a_real_error() {
        let result = build_edge_event_emitter(Ok("ab".repeat(32)), Ok("not a url".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn https_endpoint_is_rejected_tls_is_out_of_scope() {
        let result = parse_observatory_endpoint("https://observatory.example/v1/edge-events");
        assert!(matches!(result, Err(EmitterInitError::EndpointNotHttp)));
    }

    // -- real HTTP transport --

    /// A minimal, single-request HTTP/1.1 server: accepts one connection, reads the
    /// request until the full `Content-Length` body has arrived, records the exact bytes
    /// received, and replies `204 No Content`. Manual `TcpListener` parsing rather than a
    /// second `hyper` server (this module's own doc's stated preference) -- keeps
    /// `vg-core`'s `hyper` dependency client-only, in both production and tests.
    fn spawn_single_request_test_server() -> (
        std::net::SocketAddr,
        std::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (headers_end, content_length) = loop {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "peer closed before sending a full request");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let header_text = String::from_utf8_lossy(&buf[..pos]);
                    let len = header_text
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    break (pos + 4, len);
                }
            };
            while buf.len() < headers_end + content_length {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "peer closed before sending the full declared body");
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..headers_end]).to_string();
            let body = buf[headers_end..headers_end + content_length].to_vec();
            let _ = tx.send((head, body));
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        (addr, rx)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn end_to_end_posts_the_exact_signed_bytes_to_a_real_local_server() {
        let (addr, rx) = spawn_single_request_test_server();
        let endpoint: ObservatoryEndpoint =
            format!("http://{addr}/v1/edge-events").parse().unwrap();
        let handle = EdgeEventEmitterHandle::connect(sample_key(), endpoint).unwrap();

        let sent_body = r#"{"envelope":{},"edge_event":{}}"#.to_string();
        assert!(handle.try_emit(sent_body.clone()));

        let (head, received_body) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("test server never received a request");
        assert_eq!(received_body, sent_body.as_bytes());
        assert!(head
            .to_ascii_lowercase()
            .contains("content-type: application/json"));
        assert!(head.starts_with("POST /v1/edge-events"));

        // Wait for the background worker to record the outcome (it replies after the
        // channel already returned `true`, so poll briefly rather than racing it).
        wait_for(Duration::from_secs(2), || handle.stats().sent_ok == 1);
        let stats = handle.stats();
        assert_eq!(stats.sent_ok, 1);
        assert_eq!(stats.send_failed, 0);
        assert_eq!(stats.queue_full_dropped, 0);
    }

    #[test]
    fn dropping_the_handle_right_after_emit_still_delivers_the_record() {
        // Mimics `vg-cli`'s short-lived hook process: `try_emit`, then immediately let the
        // handle go out of scope, with NO polling/waiting in between -- unlike every other
        // test in this file, which calls `wait_for` before checking the outcome. Before the
        // `Drop` impl's bounded flush existed, this raced process exit against the
        // background thread's own connect+handshake+POST and could silently lose the
        // record; `cargo test`'s long-lived process never exercised that race because it
        // never exits between `try_emit` and the assertions.
        let (addr, rx) = spawn_single_request_test_server();
        let endpoint: ObservatoryEndpoint =
            format!("http://{addr}/v1/edge-events").parse().unwrap();
        let sent_body = r#"{"envelope":{},"edge_event":{}}"#.to_string();

        {
            let handle = EdgeEventEmitterHandle::connect(sample_key(), endpoint).unwrap();
            assert!(handle.try_emit(sent_body.clone()));
            // `handle` drops here, at the end of this block -- no `wait_for`, no sleep.
        }

        let (_head, received_body) = rx.recv_timeout(Duration::from_secs(1)).expect(
            "the record was lost: Drop's flush did not win the race against the handle going away",
        );
        assert_eq!(received_body, sent_body.as_bytes());
    }

    #[test]
    fn unreachable_endpoint_does_not_block_try_emit_and_counts_a_failure() {
        // Port 0 binds to an ephemeral free port and is immediately dropped, so nothing
        // is listening on it once we read back its address -- a real "connection
        // refused," not merely a slow/unroutable address (which could hide a genuine
        // hang behind the OS's own connect-refused speed rather than this module's own
        // timeout).
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let endpoint: ObservatoryEndpoint =
            format!("http://{addr}/v1/edge-events").parse().unwrap();
        let handle = EdgeEventEmitterHandle::connect(sample_key(), endpoint).unwrap();

        let started = std::time::Instant::now();
        let queued = handle.try_emit("{}".to_string());
        let elapsed = started.elapsed();

        assert!(
            queued,
            "try_emit must enqueue promptly, not block on the dead connection"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "try_emit blocked for {elapsed:?} -- it must return immediately regardless of \
             the endpoint's reachability"
        );

        wait_for(Duration::from_secs(5), || handle.stats().send_failed == 1);
        let stats = handle.stats();
        assert_eq!(stats.send_failed, 1);
        assert_eq!(stats.sent_ok, 0);
    }

    #[test]
    fn a_full_channel_drops_and_counts_rather_than_blocking() {
        // No listener at all on this address: every POST attempt will hang trying to
        // connect (nothing ever refuses or accepts), so the single-request-at-a-time
        // background worker stays stuck on record #1 for this test's whole duration,
        // proving the *channel* itself (not luck in the worker draining fast enough) is
        // what's under test. `192.0.2.0/24` is TEST-NET-1 (RFC 5737) -- reserved for
        // documentation/testing, guaranteed unroutable, so the connect attempt blocks
        // instead of getting a fast "connection refused."
        let endpoint: ObservatoryEndpoint = "http://192.0.2.1:9/v1/edge-events".parse().unwrap();
        let handle = EdgeEventEmitterHandle::connect(sample_key(), endpoint).unwrap();

        let mut queued = 0;
        let mut dropped = 0;
        // One extra than capacity: the first is very likely already pulled off the
        // channel by the background worker and left "in flight" mid-connect, so send
        // enough to be sure the channel itself fills regardless of that race.
        for i in 0..(CHANNEL_CAPACITY + 8) {
            if handle.try_emit(format!("{{\"n\":{i}}}")) {
                queued += 1;
            } else {
                dropped += 1;
            }
        }

        assert!(
            dropped > 0,
            "expected at least one drop once the channel filled up"
        );
        assert_eq!(queued + dropped, CHANNEL_CAPACITY + 8);
        assert_eq!(
            handle.stats().queue_full_dropped,
            dropped as u64,
            "queue_full_dropped must match try_emit's own false-returns exactly"
        );
    }

    fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let started = std::time::Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < timeout,
                "condition did not become true in time"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
