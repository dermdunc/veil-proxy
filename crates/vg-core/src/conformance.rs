//! Contract-conformance helpers.
//!
//! Wave B squads (`vg-detectors`, `vg-parsers`, `vg-vault`, `vg-policy`, `vg-audit`) call
//! these from their own crate's test suite to check a trait impl against the invariants
//! named in `docs/architecture/interface-contracts.md`, without `vg-core` needing to
//! know about any concrete impl. Each function asserts internally, so it reads naturally
//! inside a `#[test]`:
//!
//! ```ignore
//! #[test]
//! fn my_detector_is_conformant() {
//!     let d = MyDetector::default();
//!     vg_core::conformance::assert_detector_contract(&d, b"...", &[]);
//! }
//! ```
//!
//! See `crates/vg-core/tests/conformance_stubs.rs` for a full worked example against
//! mock implementations of every trait.

use crate::api::{Actor, Destination};
use crate::audit::AuditEvent;
use crate::traits::{AuditSink, Detector, Parser, PolicyEngine, Secret, VaultStore};
use crate::types::{EntityType, MaskedPack, Namespace, Span};

/// `Detector::detect` must be deterministic, only return entity types it declares, with
/// confidence in `0.0..=1.0`, and every returned `Span` must be a valid byte range into
/// `buf` (`start <= end <= buf.len()`) — later pipeline code slices `buf` by these spans
/// and a detector that returns an out-of-bounds span is not conformant, even if it never
/// panics itself.
///
/// `?Sized` so this can be called on `&dyn Detector` (the library API holds detectors as
/// trait objects in `Context`), not only on a concrete sized type.
pub fn assert_detector_contract<D: Detector + ?Sized>(detector: &D, buf: &[u8], spans: &[Span]) {
    let first = detector.detect(buf, spans);
    let second = detector.detect(buf, spans);
    assert_eq!(
        first, second,
        "Detector::detect must be deterministic for the same input"
    );

    let declared = detector.entity_types();
    for finding in &first {
        assert!(
            declared.contains(&finding.entity_type),
            "Finding {finding:?} has an entity_type not declared by Detector::entity_types()"
        );
        assert!(
            (0.0..=1.0).contains(&finding.confidence),
            "Finding confidence {} out of 0.0..=1.0",
            finding.confidence
        );
        assert!(
            finding.span.start <= finding.span.end && finding.span.end <= buf.len(),
            "Finding {finding:?} has an out-of-bounds span (start={}, end={}, buf.len()={})",
            finding.span.start,
            finding.span.end,
            buf.len()
        );
    }
}

/// `Parser::parse` must never panic, even on malformed input. Callers should exercise
/// this with genuinely adversarial buffers (empty, truncated UTF-8, unbalanced
/// delimiters) for their real parser — a trivial mock that can't panic by construction
/// (see `tests/conformance_stubs.rs`'s `MockParser`) only proves the harness call
/// itself doesn't crash, not that any real implementation is panic-safe.
///
/// `?Sized` so this can be called on `&dyn Parser`.
pub fn assert_parser_never_panics<P: Parser + ?Sized>(parser: &P, buf: &[u8]) {
    let _ = parser.parse(buf);
}

/// A value interned into a `VaultStore` must resolve back to the same raw value under
/// the same namespace; interning the same `(value, ty, ns)` twice must yield the same
/// placeholder (the stable-placeholder invariant); and — the namespace-isolation half of
/// the contract, per `VaultStore`'s trait doc — resolving the same placeholder under a
/// *different* namespace must fail, not silently return the value.
///
/// `other_ns` must be a namespace distinct from `ns` (the caller picks one relevant to
/// their impl, e.g. a different `Session`/`Repo`/`Org`).
///
/// `?Sized` so this can be called on `&dyn VaultStore`.
pub fn assert_vault_roundtrip<V: VaultStore + ?Sized>(
    vault: &V,
    value: &str,
    ty: EntityType,
    ns: &Namespace,
    other_ns: &Namespace,
) {
    assert_ne!(
        ns, other_ns,
        "assert_vault_roundtrip requires two distinct namespaces to test isolation"
    );

    let first = vault
        .intern(&Secret::new(value.to_string()), ty.clone(), ns)
        .expect("intern should succeed");
    let second = vault
        .intern(&Secret::new(value.to_string()), ty, ns)
        .expect("intern should succeed");
    assert_eq!(
        first.mapping_ref, second.mapping_ref,
        "interning the same (value, type, namespace) twice must yield the same placeholder"
    );

    let resolved = vault.resolve(&first, ns).expect("resolve should succeed");
    assert_eq!(
        resolved.expose_secret(),
        value,
        "resolve must return the original raw value"
    );

    assert!(
        vault.resolve(&first, other_ns).is_err(),
        "resolve must fail when called with a namespace different from the one the \
         placeholder was interned under — a value must never leak across namespaces"
    );
}

/// A written `AuditEvent` must be returned unchanged by `get`.
///
/// `?Sized` so this can be called on `&dyn AuditSink`.
pub fn assert_audit_sink_roundtrip<A: AuditSink + ?Sized>(sink: &A, event: AuditEvent) {
    let id = sink.write(event.clone()).expect("write should succeed");
    let fetched = sink
        .get(id)
        .expect("get must return the event just written");
    assert_eq!(
        fetched, event,
        "AuditSink::get must return exactly what was written"
    );
}

/// `PolicyEngine::demask_allowed` must deny `RemoteModelPrompt` and `ObservabilitySink`
/// in default policy, regardless of actor — the same hard-deny invariant
/// [`crate::rehydrate`] enforces unconditionally in `vg-core` itself. A `PolicyEngine`
/// impl that permitted these would still be blocked by `rehydrate`'s own gate, but the
/// engine's own `demask_allowed` should agree, not rely solely on that outer gate.
pub fn assert_policy_engine_denies_hard_deny_destinations<P: PolicyEngine + ?Sized>(
    engine: &P,
    actor: &Actor,
) {
    assert!(
        !engine.demask_allowed(Destination::RemoteModelPrompt, actor),
        "PolicyEngine::demask_allowed must deny RemoteModelPrompt in default policy"
    );
    assert!(
        !engine.demask_allowed(Destination::ObservabilitySink, actor),
        "PolicyEngine::demask_allowed must deny ObservabilitySink in default policy"
    );
}

/// No `AuditEvent` variant may embed a known raw value — audit events carry only refs,
/// counts, and versions.
///
/// Checks both the literal raw value and its `Debug`-escaped form (e.g. a raw value
/// containing a newline renders as the two characters `\`+`n` in `{event:?}`'s output,
/// not a literal newline byte — checking only the unescaped literal would false-negative
/// on exactly that class of input).
pub fn assert_audit_event_excludes_raw_values(event: &AuditEvent, raw_values: &[&str]) {
    let rendered = format!("{event:?}");
    for raw in raw_values {
        let escaped = format!("{raw:?}");
        let escaped = escaped.trim_start_matches('"').trim_end_matches('"');
        assert!(
            !rendered.contains(raw) && !rendered.contains(escaped),
            "AuditEvent {event:?} appears to embed a raw value ({raw:?})"
        );
    }
}

/// Proves a bounded-token constructor (e.g. `telemetry::VersionToken::try_from`)
/// actually rejects non-conforming input, rather than that a successfully-constructed
/// instance hides it.
///
/// This is the deliberate mirror image of [`assert_audit_event_excludes_raw_values`]:
/// `AuditEvent`'s fields are public and string-shaped, so that helper can construct an
/// event carrying a real raw value and assert it's absent from `Debug` output —
/// meaningful because the type *could* have carried it. `telemetry::TelemetryEvent`'s
/// bounded-token types have no public constructor that accepts an unvalidated `String`
/// at all, so the only property left to check is that the fallible constructor itself
/// actually enforces its bound.
pub fn assert_telemetry_token_rejects_raw_value<T, E>(
    try_from: impl Fn(&str) -> Result<T, E>,
    raw_values: &[&str],
) {
    for raw in raw_values {
        assert!(
            try_from(raw).is_err(),
            "token constructor accepted a raw-looking value {raw:?} — bounding is not enforced"
        );
    }
}

/// `MaskedPack` must never contain a raw detected value or a vault key, in any of its
/// string-bearing fields (`text`, `policy_version`, and each `bindings[].display`).
/// `mapping_refs` (and each binding's `mapping_ref`) holds only opaque `MappingRef(Uuid)`
/// handles — never a real vault key — so that half of the invariant is true by
/// construction of the type itself, not something this check needs to verify.
///
/// `bindings` (contract v1.2) carries the display strings `mask` minted (`EMAIL_001`),
/// which are typed placeholders by construction, not raw values — but they are now a
/// serialized-toward-callers field of the pack, so this check covers them too rather than
/// trusting `mask` never to have put a raw value there.
pub fn assert_masked_pack_excludes_raw_values(pack: &MaskedPack, raw_values: &[&str]) {
    for raw in raw_values {
        assert!(
            !pack.text.contains(raw),
            "MaskedPack.text appears to embed a raw value ({raw:?}) — must be placeholders only"
        );
        assert!(
            !pack.policy_version.contains(raw),
            "MaskedPack.policy_version appears to embed a raw value ({raw:?})"
        );
        for binding in &pack.bindings {
            assert!(
                !binding.display.contains(raw),
                "MaskedPack.bindings display {:?} appears to embed a raw value ({raw:?})",
                binding.display
            );
        }
    }
}
