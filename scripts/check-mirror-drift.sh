#!/usr/bin/env bash
# check-mirror-drift.sh: Detect when a repo-local mind-palace mirror has fallen
# behind the repo's own docs. Read-only. Schema-agnostic across project types.
#
# Usage:
#   scripts/check-mirror-drift.sh           # human report
#   scripts/check-mirror-drift.sh --check   # hook mode: exit 1 if drift is found
#
# Network: none. Pure local file inspection.
set -uo pipefail

CHECK_MODE=false
[[ "${1:-}" == "--check" ]] && CHECK_MODE=true

ROOT=""
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ "$dir" != "/" ]]; do
  if [[ -f "$dir/.hekton/project.yaml" ]]; then ROOT="$dir"; break; fi
  dir="$(dirname "$dir")"
done
if [[ -z "$ROOT" ]]; then
  echo "check-mirror-drift: no .hekton/project.yaml found above this script." >&2
  exit 0
fi

MP_REL="$(grep '^mind_palace_path:' "$ROOT/.hekton/project.yaml" 2>/dev/null \
  | sed 's/mind_palace_path: *//' | tr -d '"')"
DOCS="$ROOT/docs"
MIRROR="$ROOT/mind-palace/${MP_REL}"

DRIFT=0
warn() { printf '  WARN: %s\n' "$*"; }
ok() { printf '  OK: %s\n' "$*"; }
bad() { printf '  FAIL: %s\n' "$*"; }

echo "-- Mirror drift check --------------------------------------------------"
echo "  repo docs: $DOCS"
echo "  mirror:    $MIRROR"
echo ""

if [[ ! -d "$MIRROR" ]]; then
  bad "mirror directory missing"
  exit 1
fi
for f in index.md decisions.md session-log.md; do
  if [[ ! -f "$MIRROR/$f" ]]; then
    bad "mirror/$f missing"
    DRIFT=1
  fi
done

count_dated_rows() { [[ -f "$1" ]] && grep -cE '^\|.*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$1" || echo 0; }
# Matches both session-log header styles: the old `## YYYY-MM-DD - Title` form and the
# `## Session: Title` + `**Date:** YYYY-MM-DD` form end-session.sh (and every recent manual
# entry) actually writes — the old regex alone never matched current-format entries, so this
# check could never pass regardless of how current the mirror actually was.
latest_log_date() {
  [[ -f "$1" ]] || { echo ""; return; }
  { grep -oE '##[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}' "$1"
    grep -oE '\*\*Date:\*\*[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}' "$1"; } \
    | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort | tail -1
}
latest_adr() { [[ -f "$1" ]] && grep -oE '^#+[[:space:]]*ADR-[0-9]+' "$1" | grep -oE '[0-9]+' | sort -n | tail -1 || echo ""; }

REPO_DEC=$(count_dated_rows "$DOCS/decisions.md")
MIR_DEC=$(count_dated_rows "$MIRROR/decisions.md")
if [[ "$REPO_DEC" -gt "$MIR_DEC" ]]; then
  warn "decisions: repo has $REPO_DEC dated rows, mirror has $MIR_DEC"
  DRIFT=1
else
  ok "decisions: mirror current ($MIR_DEC rows)"
fi

REPO_LOG=$(latest_log_date "$DOCS/session-log.md")
MIR_LOG=$(latest_log_date "$MIRROR/session-log.md")
if [[ -n "$REPO_LOG" && "$REPO_LOG" > "$MIR_LOG" ]]; then
  warn "session-log: repo latest $REPO_LOG, mirror latest ${MIR_LOG:-none}"
  DRIFT=1
else
  ok "session-log: mirror current (${MIR_LOG:-none})"
fi

REPO_ADR=$(latest_adr "$DOCS/decisions.md")
if [[ -n "$REPO_ADR" ]]; then
  if grep -q "ADR-${REPO_ADR}\b" "$MIRROR/index.md" 2>/dev/null || grep -qE "ADR-0*${REPO_ADR}" "$MIRROR/decisions.md" 2>/dev/null; then
    ok "index/decisions reference latest ADR-${REPO_ADR}"
  else
    warn "index does not reference latest decision ADR-${REPO_ADR}"
    DRIFT=1
  fi
fi

echo ""
if [[ "$DRIFT" -eq 0 ]]; then
  echo "Mirror is current."
else
  echo "Mirror has drifted. Update summary files in:"
  echo "  $MIRROR"
fi

if [[ "$CHECK_MODE" == true ]]; then
  exit "$DRIFT"
fi
exit 0
