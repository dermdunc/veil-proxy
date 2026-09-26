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
# Write failures are only ever reported on the harness's stderr; any one means the capture
# may be missing an exchange, so nothing below could be trusted.
if grep -q "vg-proxy capture:" "$HARNESS_LOG"; then
  echo "FAIL: the harness reported a capture write failure:" >&2
  grep "vg-proxy capture:" "$HARNESS_LOG" >&2
  exit 1
fi
# Structure: format marker present, Mask exchanges numbered 1..N with no holes and every request
# paired with a response and its metadata (and no orphan responses), no Pass-route request that
# carried a body (Pass bodies go upstream unmasked and are never captured, so they could not be
# checked), and the raw value in no recorded path or query string (those cross the wire unmasked).
python3 - "$CAPTURE_DIR" "$SYNTHETIC_SECRET" <<'PYEOF'
import json, os, re, sys
d, secret = sys.argv[1], sys.argv[2]
names = os.listdir(d)
fail = lambda msg: sys.exit(f"FAIL: {msg}")
if "capture-info.json" not in names:
    fail("capture-info.json missing: this vg-proxy build cannot vouch for Pass-route egress")
info = json.load(open(os.path.join(d, "capture-info.json")))
if info.get("format", 0) < 3 or not info.get("pass_route_metadata") or not info.get("mask_request_metadata"):
    fail(f"capture format too old to vouch for every egress path: {info}")
req = {int(m.group(1)) for n in names if (m := re.fullmatch(r"(\d{6,})-request\.masked\.json", n))}
resp = {int(m.group(1)) for n in names if (m := re.fullmatch(r"(\d{6,})-response\.raw\.(?:sse|json)", n))}
if not req:
    fail("no outbound request was captured")
if req != set(range(1, max(req) + 1)):
    fail(f"capture gap: request numbers are not contiguous: {sorted(req)}")
if req != resp:
    fail(f"capture gap: unpaired exchanges (requests {sorted(req - resp)}, responses {sorted(resp - req)})")
req_meta = {int(m.group(1)) for n in names if (m := re.fullmatch(r"(\d{6,})-request\.meta\.json", n))}
if req_meta != req:
    fail(f"capture gap: Mask request metadata does not match requests ({sorted(req_meta ^ req)})")
for n in names:
    is_pass = re.fullmatch(r"P\d{6,}-pass\.meta\.json", n)
    if is_pass or re.fullmatch(r"\d{6,}-request\.meta\.json", n):
        meta = json.load(open(os.path.join(d, n)))
        if secret in str(meta.get("path_and_query", "")):
            fail(f"the raw synthetic secret is in a recorded path/query string ({n}) -- it crossed the wire unmasked")
        if is_pass and meta.get("body_len", 1) != 0:
            fail(f"Pass-route request {meta.get('path_and_query')} carried a {meta.get('body_len')}-byte body upstream unmasked")
print(f"    structure ok: {len(req)} paired Mask exchange(s), capture format {info['format']}")
PYEOF
REQUEST_CAPTURES=("$CAPTURE_DIR"/*-request.masked.json)
# Negative: the raw planted value never crossed the wire, in any captured request. grep exits 1
# for "no match" and 2 for a read error; only 1 is a pass.
set +e
grep -qF "$SYNTHETIC_SECRET" "${REQUEST_CAPTURES[@]}"
NEG_RC=$?
# Positive: the planted value's own placeholder is in an outbound body, at the prompt's own
# wording (anchored there because the CLI also injects the account email, which masks to an
# EMAIL_ placeholder too and would otherwise satisfy a bare pattern for the wrong reason).
grep -qE "The synthetic test value is: EMAIL_[0-9]+" "${REQUEST_CAPTURES[@]}"
POS_RC=$?
set -e
if [[ $NEG_RC -eq 0 ]]; then
  echo "FAIL: the raw synthetic secret is present in a captured outbound body -- it crossed the wire unmasked" >&2
  exit 1
elif [[ $NEG_RC -ne 1 ]]; then
  echo "FAIL: could not read the captured outbound bodies (grep exit $NEG_RC)" >&2
  exit 1
fi
if [[ $POS_RC -ne 0 ]]; then
  echo "FAIL: no captured outbound body carries the planted value's placeholder (grep exit $POS_RC) -- masking may not have run on it" >&2
  exit 1
fi
echo "PASS: ${#REQUEST_CAPTURES[@]} captured outbound request(s): placeholder present, raw value absent"

echo "==> secondary: the dev-harness's own log never contains the raw synthetic secret"
if grep -q "$SYNTHETIC_SECRET" "$HARNESS_LOG"; then
  echo "FAIL: the harness's own stderr log contains the raw synthetic secret" >&2
  exit 1
fi

echo "==> PASS: A2 live-run proof complete. No raw Anthropic credential was read, echoed, or handled by this script at any point."
