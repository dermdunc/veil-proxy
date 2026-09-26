#!/usr/bin/env bash
set -euo pipefail

# A2's live-run proof (INT-2026-09-13-001, confirmation criteria 1-2 as amended by
# amendment-2026-09-13-001.yaml): routes one real (streaming, as the CLI always is) Claude Code CLI session
# through a real vg-proxy TLS connection to https://api.anthropic.com, authenticating via
# the real `claude` CLI's own existing subscription session (never a raw API key this
# script reads, requests, or handles), and proves a synthetic sensitive value planted in
# the prompt is masked before egress and correctly demasked in the real response reaching
# the wrapped client.
#
# No raw secret ever appears in this script's own output/logs (this intent's own
# secret-leakage disproof criterion): the planted value is a clearly-synthetic string
# (never a real credential), and the real Anthropic credential itself is never read,
# echoed, or handled by this script at all -- it already lives inside the `claude` CLI's
# own session, which this script only ever invokes, never inspects.
#
# Masking-before-egress is asserted against the exact bytes that went upstream, captured by
# vg-proxy's dev-only `capture` feature (`crates/vg-proxy/src/capture.rs`) into a temp dir:
# a positive check (the planted value's placeholder is present in the outbound body) and a
# negative check (the raw value is absent from every outbound body). An earlier version only
# checked the harness's own stdout/stderr log, which never contains request bodies at all, so
# a pure pass-through proxy would have passed it (veil-demo docs/agentic-demo-plan.md §1.10).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HARNESS_LOG="$(mktemp -t vg-a2-proof-harness.XXXXXX)"
PROOF_LOG="$(mktemp -t vg-a2-proof-claude.XXXXXX)"
CAPTURE_DIR="$(mktemp -d -t vg-a2-proof-capture.XXXXXX)"
HARNESS_PID=""

cleanup() {
  if [[ -n "$HARNESS_PID" ]]; then
    kill "$HARNESS_PID" 2>/dev/null || true
    wait "$HARNESS_PID" 2>/dev/null || true
  fi
  rm -f "$HARNESS_LOG" "$PROOF_LOG"
  rm -rf "$CAPTURE_DIR"
}
trap cleanup EXIT

echo "==> building the dev-harness binary"
cargo build -p vg-proxy --example live_proof_harness --features capture --quiet

echo "==> starting the dev-harness (real TLS to real https://api.anthropic.com)"
VG_PROXY_CAPTURE_DIR="$CAPTURE_DIR" \
  cargo run -p vg-proxy --example live_proof_harness --features capture --quiet </dev/null >"$HARNESS_LOG" 2>&1 &
HARNESS_PID=$!

PORT=""
for _ in $(seq 1 50); do
  if grep -q "VG_PROXY_LIVE_PROOF_PORT=" "$HARNESS_LOG" 2>/dev/null; then
    PORT="$(grep -o 'VG_PROXY_LIVE_PROOF_PORT=[0-9]*' "$HARNESS_LOG" | cut -d= -f2)"
    break
  fi
  sleep 0.2
done
if [[ -z "$PORT" ]]; then
  echo "FAIL: dev-harness never printed a port" >&2
  cat "$HARNESS_LOG" >&2
  exit 1
fi
echo "==> dev-harness listening on 127.0.0.1:${PORT}"

# Worded to disclose the test openly rather than disguise it as an injected instruction — a
# real earlier run of this script got a (correct!) refusal: the model flagged
# "repeat this back verbatim, nothing else" as a classic injection/exfiltration probe pattern
# and declined, suggesting exactly this fix in its own reply ("I'd rather you tell me directly
# you're testing injection resistance than have it disguised in-band").
SYNTHETIC_SECRET="a2-live-proof-synthetic-secret-$(date +%s)@example.invalid"
PROMPT="I'm dermdunc, running a disclosed, authorized live-integration test of vg-proxy's masking system (intent INT-2026-09-13-001 in veil-ecosystem). This message is routed through vg-proxy, which should mask the contact-info-shaped test value below before it reaches you, then demask your reply before it reaches me. The synthetic test value is: ${SYNTHETIC_SECRET} -- it is not a real secret. Please include that exact value in your reply so I can confirm the round-trip worked."

# RISK-0014 (docs/risks.md): the real claude CLI redacts its own billing header to
# [REDACTED:SECRET] when ANTHROPIC_BASE_URL is non-default, which the real API then
# rejects. Fix, per Anthropic's own gateway-compatibility docs and this repo's own
# pre-existing `vg run` convention (crates/vg-cli/src/main.rs, "asking it not to via
# this var is the whole fix"): CLAUDE_CODE_ATTRIBUTION_HEADER=0 tells Claude Code to
# omit the attribution block entirely, so there's nothing for the real API to reject.
echo "==> invoking the real claude CLI through vg-proxy (streaming, ANTHROPIC_BASE_URL redirected, CLAUDE_CODE_ATTRIBUTION_HEADER=0)"
if ! CLAUDE_CODE_ATTRIBUTION_HEADER=0 ANTHROPIC_BASE_URL="http://127.0.0.1:${PORT}" \
  claude -p "$PROMPT" >"$PROOF_LOG" 2>&1; then
  echo "FAIL: claude CLI invocation failed" >&2
  cat "$PROOF_LOG" >&2
  exit 1
fi

echo "==> checking the real response for evidence of masking+demasking"
if ! grep -q "$SYNTHETIC_SECRET" "$PROOF_LOG"; then
  echo "FAIL: the synthetic secret did not round-trip back through demasking -- masking may have broken the response, or the model didn't comply" >&2
  echo "---- claude CLI output ----" >&2
  cat "$PROOF_LOG" >&2
  exit 1
fi
echo "PASS: synthetic secret round-tripped through real mask -> real TLS upstream -> real demask"

echo "==> checking the exact outbound bytes vg-proxy sent upstream (capture feature)"
shopt -s nullglob
REQUEST_CAPTURES=("$CAPTURE_DIR"/*-request.masked.json)
shopt -u nullglob
if [[ ${#REQUEST_CAPTURES[@]} -eq 0 ]]; then
  echo "FAIL: no outbound request was captured -- cannot assert anything about egress" >&2
  exit 1
fi
for req in "${REQUEST_CAPTURES[@]}"; do
  if [[ ! -f "${req%-request.masked.json}-response.raw.json" && ! -f "${req%-request.masked.json}-response.raw.sse" ]]; then
    echo "FAIL: capture gap -- $(basename "$req") has no matching response file" >&2
    exit 1
  fi
done
# Negative: the raw planted value never crossed the wire, in any captured request.
if grep -lF "$SYNTHETIC_SECRET" "${REQUEST_CAPTURES[@]}" >/dev/null; then
  echo "FAIL: the raw synthetic secret is present in a captured outbound body -- it crossed the wire unmasked" >&2
  exit 1
fi
# Positive: the planted value's own placeholder is in an outbound body, at the prompt's own
# wording (anchored there because the CLI also injects the account email, which masks to an
# EMAIL_ placeholder too and would otherwise satisfy a bare pattern for the wrong reason).
if ! grep -lE "The synthetic test value is: EMAIL_[0-9]+" "${REQUEST_CAPTURES[@]}" >/dev/null; then
  echo "FAIL: no captured outbound body carries the planted value's placeholder -- masking may not have run on it" >&2
  exit 1
fi
echo "PASS: ${#REQUEST_CAPTURES[@]} captured outbound request(s): placeholder present, raw value absent"

echo "==> secondary: the dev-harness's own log never contains the raw synthetic secret"
if grep -q "$SYNTHETIC_SECRET" "$HARNESS_LOG"; then
  echo "FAIL: the harness's own stderr log contains the raw synthetic secret" >&2
  exit 1
fi

echo "==> PASS: A2 live-run proof complete. No raw Anthropic credential was read, echoed, or handled by this script at any point."
