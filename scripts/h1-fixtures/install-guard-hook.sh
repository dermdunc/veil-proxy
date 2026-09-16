#!/usr/bin/env bash
# install-guard-hook.sh: pre-commit backstop for Track H fork F15's fixture-governance
# entry gate — raw H1 Codex-spike captures (scripts/h1-fixtures/raw/) must never reach a
# commit, even via `git add -f` overriding the .gitignore entry.
#
# .gitignore is the primary control; this is defense in depth, same posture as
# scrub.py's own doc comment ("a backstop, not the primary control").
#
# Chains any pre-existing pre-commit hook rather than replacing it — same convention
# .git/hooks/pre-commit's own header documents for the protected-path hook. Idempotent:
# safe to re-run: detects its own marker and does not double-chain.
#
# Usage: scripts/h1-fixtures/install-guard-hook.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOKS_DIR="$ROOT/.git/hooks"
DEST="$HOOKS_DIR/pre-commit"
MARKER="# hekton-h1-fixture-guard"

if [[ ! -d "$HOOKS_DIR" ]]; then
  echo "ERROR: $HOOKS_DIR not found; is this a git repo?" >&2
  exit 1
fi

if [[ -f "$DEST" ]] && grep -qF "$MARKER" "$DEST"; then
  echo "H1 fixture guard already installed in $DEST"
  exit 0
fi

if [[ -f "$DEST" ]]; then
  PREV="$HOOKS_DIR/pre-commit.pre-h1-guard"
  if [[ ! -f "$PREV" ]]; then
    cp "$DEST" "$PREV"
    chmod +x "$PREV"
    echo "Chained existing pre-commit hook to $PREV"
  fi
fi

cat > "$DEST" <<HOOK
#!/usr/bin/env bash
$MARKER — installed by scripts/h1-fixtures/install-guard-hook.sh
# Blocks any staged file under scripts/h1-fixtures/raw/ (Track H fork F15). See that
# script's header comment for why. Chains the pre-existing pre-commit hook, if any.
set -euo pipefail

PREV_HOOK="\$(dirname "\$0")/pre-commit.pre-h1-guard"
if [[ -x "\$PREV_HOOK" ]]; then
  "\$PREV_HOOK" "\$@"
fi

staged="\$(git diff --cached --name-only --diff-filter=ACMR || true)"
hits="\$(printf '%s\n' "\$staged" | grep -E '^scripts/h1-fixtures/raw/' || true)"
if [[ -n "\$hits" ]]; then
  cat >&2 <<EOF

[h1-fixture-guard] BLOCKED — this commit stages raw H1 capture file(s):

\$(printf '  %s\n' \$hits)

Track H fork F15: raw captures may contain real upstream account/session-shaped
values and must never be committed. Run scrub.py and commit the sanitized output
under scripts/h1-fixtures/sanitized/ instead.

EOF
  exit 1
fi

exit 0
HOOK

chmod +x "$DEST"
echo "Installed H1 fixture guard in $DEST"
