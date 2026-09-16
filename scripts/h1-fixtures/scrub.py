#!/usr/bin/env python3
"""Scrubs a raw H1 capture (JSONL, one HTTP request/response pair per line, produced by
`relay.py`) into a sanitized corpus safe to commit — the mechanism fork F15's own
governance decision requires (Track H, `docs/architecture/multi-harness-proxy-plan.md`
§7, decided 2026-09-14: "synthetic seeded prompts under a disclosed-test framing... a
scrub step with its own test").

Redacts, never merely tolerates:
  - Header VALUES for any header name that is credential- or session-shaped
    (authorization, cookie/set-cookie, x-api-key, openai-organization) — the NAME stays
    (useful for the corpus to show which headers a real request/response actually
    carried), only the value is replaced.
  - Any bearer-token-, OpenAI-API-key-, or JWT-shaped substring found anywhere in a
    request or response BODY, even if not inside a header we already redact.

This is a defense-in-depth backstop, not the primary control: F15's own primary
control is that only synthetic seeded prompts are ever sent through `relay.py` in the
first place, so body CONTENT should already contain nothing sensitive. This pass exists
because the upstream (a real OpenAI/ChatGPT backend) can itself echo real
account/session-shaped values in RESPONSE headers or bodies that this mission's own
prompts never asked for and don't control.

KNOWN, UNFIXED BLIND SPOT (found by adversarial review, 2026-09-15/16, after this
scrubber was run against a real capture): the real `codex` CLI embeds real environment
context — repo path, username, git remote/commit hash, `prompt_cache_key`, and other
identity-bearing fields — as ordinary, legitimate-looking structured JSON inside real
request BODIES, not as token-shaped secrets. Neither the header-name allowlist above nor
`TOKEN_PATTERN` below can catch this class of content, because it isn't credential-shaped
— it's real personal/environment data sitting in an otherwise well-formed JSON value.
This is why H1's retained corpus (`sanitized/h1-spike-01.jsonl`) is a hand-authored
synthetic artifact, not the output of running this script against a real capture — see
that file's own `provenance` fields, and `relay.py`'s module doc. Do not treat this
script's output as safe to commit without a human reviewing the actual content; it was
proven not to be sufficient on its own.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REDACTED = "[REDACTED]"

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "openai-organization",
    "openai-project",
    # Real, live-run gap found by adversarial review of the first H1 capture (2026-09-15):
    # a real ChatGPT account id and real session/thread/window UUIDs were passing through
    # this scrubber untouched because the original set above only covered credential-
    # shaped headers, not account/session-shaped ones — exactly what F15's own governance
    # text names. Header NAMES below carry account/session/turn identity; values redacted,
    # names kept, same as the rest of this list.
    "chatgpt-account-id",
    "session-id",
    "thread-id",
    "x-client-request-id",
    "sec-websocket-key",
    "x-codex-window-id",
    "x-codex-turn-metadata",
}

# Deliberately broad, not narrow: an OpenAI-style secret key (`sk-...`), a bearer token
# of any shape, and a JWT (three base64url segments separated by dots, `eyJ...` is the
# base64 encoding of `{"` which every real JWT header starts with) — false positives
# (redacting something that wasn't actually sensitive) are the safe direction of error
# for a corpus meant to be committed to a public repo.
TOKEN_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_-]{10,}"
    r"|Bearer\s+[A-Za-z0-9._-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)


def scrub_headers(headers: dict | None) -> dict | None:
    if not headers:
        return headers
    return {
        name: (REDACTED if name.lower() in SENSITIVE_HEADER_NAMES else value)
        for name, value in headers.items()
    }


def scrub_text(text: str | None) -> str | None:
    if text is None:
        return text
    return TOKEN_PATTERN.sub(REDACTED, text)


def scrub_entry(entry: dict) -> dict:
    scrubbed = dict(entry)
    scrubbed["req_headers"] = scrub_headers(entry.get("req_headers"))
    scrubbed["resp_headers"] = scrub_headers(entry.get("resp_headers"))
    scrubbed["req_body"] = scrub_text(entry.get("req_body"))
    scrubbed["resp_body"] = scrub_text(entry.get("resp_body"))
    return scrubbed


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <raw.jsonl> <sanitized.jsonl>", file=sys.stderr)
        return 2
    raw_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    with raw_path.open() as f_in, out_path.open("w") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            f_out.write(json.dumps(scrub_entry(entry)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
