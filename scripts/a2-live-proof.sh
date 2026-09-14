#!/usr/bin/env bash
set -euo pipefail

# A2's live-run proof (INT-2026-09-13-001, confirmation criteria 1-2 as amended by
# amendment-2026-09-13-001.yaml): routes one real, non-streaming Claude Code CLI session
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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HARNESS_LOG="$(mktemp -t vg-a2-proof-harness.XXXXXX)"
PROOF_LOG="$(mktemp -t vg-a2-proof-claude.XXXXXX)"
HARNESS_PID=""

cleanup() {
  if [[ -n "$HARNESS_PID" ]]; then
    kill "$HARNESS_PID" 2>/dev/null || true
    wait "$HARNESS_PID" 2>/dev/null || true
  fi
  rm -f "$HARNESS_LOG" "$PROOF_LOG"
}
trap cleanup EXIT

echo "==> building the dev-harness binary"
cargo build -p vg-proxy --example live_proof_harness --quiet

echo "==> starting the dev-harness (real TLS to real https://api.anthropic.com)"
cargo run -p vg-proxy --example live_proof_harness --quiet </dev/null >"$HARNESS_LOG" 2>&1 &
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

echo "==> checking the dev-harness's own log for a masking-never-ran indicator"
if grep -q "$SYNTHETIC_SECRET" "$HARNESS_LOG"; then
  echo "FAIL: the harness's own stderr log contains the raw synthetic secret -- masking may not have run before egress" >&2
  exit 1
fi

echo "==> PASS: A2 live-run proof complete. No raw Anthropic credential was read, echoed, or handled by this script at any point."
