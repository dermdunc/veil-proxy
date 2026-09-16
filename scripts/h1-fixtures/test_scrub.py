#!/usr/bin/env python3
"""Regression test for scrub.py — Track H fork F15's own required "scrub step with its
own test". Run directly: `python3 scripts/h1-fixtures/test_scrub.py`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRUB_PY = Path(__file__).parent / "scrub.py"


def run_scrub(raw_entry: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / "raw.jsonl"
        out_path = Path(tmp) / "sanitized.jsonl"
        raw_path.write_text(json.dumps(raw_entry) + "\n")
        subprocess.run(
            [sys.executable, str(SCRUB_PY), str(raw_path), str(out_path)],
            check=True,
        )
        return json.loads(out_path.read_text().splitlines()[0])


def test_sensitive_header_values_are_redacted_names_preserved() -> None:
    result = run_scrub(
        {
            "method": "POST",
            "path": "/v1/responses",
            "req_headers": {
                "authorization": "Bearer sk-realsecretvalue1234567890",
                "content-type": "application/json",
            },
            "resp_headers": {"set-cookie": "session=abc123realvalue; Path=/"},
            "req_body": "a synthetic prompt, nothing sensitive here",
            "resp_body": "a synthetic response, nothing sensitive here",
        }
    )
    assert result["req_headers"]["authorization"] == "[REDACTED]", result
    assert result["resp_headers"]["set-cookie"] == "[REDACTED]", result
    # Non-sensitive headers/bodies must pass through byte-for-byte, not just "not error".
    assert result["req_headers"]["content-type"] == "application/json", result
    assert result["req_body"] == "a synthetic prompt, nothing sensitive here", result
    assert result["resp_body"] == "a synthetic response, nothing sensitive here", result
    print("PASS: sensitive header VALUES redacted, names and other headers preserved")


def test_token_shaped_substrings_in_bodies_are_redacted_even_outside_headers() -> None:
    result = run_scrub(
        {
            "method": "POST",
            "path": "/v1/responses",
            "req_headers": {},
            "resp_headers": {},
            "req_body": "here is a key sk-abcdefghij1234567890 embedded in body text",
            "resp_body": (
                "a jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U appeared in the response"
            ),
        }
    )
    assert "sk-abcdefghij1234567890" not in result["req_body"], result
    assert "[REDACTED]" in result["req_body"], result
    assert "eyJhbGciOiJIUzI1NiJ9" not in result["resp_body"], result
    assert "[REDACTED]" in result["resp_body"], result
    print("PASS: token-shaped substrings in bodies redacted even outside headers")


def test_missing_response_fields_pass_through_unchanged() -> None:
    # relay.py records `resp_headers`/`resp_body` as None on a relay error — scrub.py
    # must not crash on that shape.
    result = run_scrub(
        {
            "method": "GET",
            "path": "/v1/responses",
            "req_headers": {"content-type": "application/json"},
            "req_body": "",
            "resp_headers": None,
            "resp_body": None,
            "error": "connection refused",
        }
    )
    assert result["resp_headers"] is None, result
    assert result["resp_body"] is None, result
    assert result["error"] == "connection refused", result
    print("PASS: a relay-error entry (no response captured) round-trips without crashing")


def test_account_and_session_identifying_headers_are_redacted() -> None:
    # Regression for a real gap found by adversarial review of the first H1 capture
    # (2026-09-15): a real ChatGPT account id and real session/thread/window UUIDs were
    # passing through this scrubber untouched, because the original SENSITIVE_HEADER_NAMES
    # only covered credential-shaped headers. These are account/session-shaped, which
    # F15's own governance text names explicitly.
    #
    # CRITICAL: the values below are deliberately obviously-fake placeholders
    # (`ffffffff-...`), NOT copied from any real capture. A cross-model review of an
    # earlier version of this test found it had accidentally embedded the actual real
    # ChatGPT account id from this session's own capture as "example" data — a real
    # personal identifier sitting in source about to be committed. Never copy a value
    # out of a real raw/sanitized capture into this file; construct fakes instead.
    result = run_scrub(
        {
            "method": "POST",
            "path": "/v1/responses",
            "req_headers": {
                "chatgpt-account-id": "ffffffff-0000-0000-0000-000000000001",
                "session-id": "ffffffff-0000-0000-0000-000000000002",
                "thread-id": "ffffffff-0000-0000-0000-000000000003",
                "x-client-request-id": "ffffffff-0000-0000-0000-000000000004",
                "sec-websocket-key": "ZmFrZS13ZWJzb2NrZXQta2V5LQ==",
                "x-codex-window-id": "ffffffff-0000-0000-0000-000000000005",
                "x-codex-turn-metadata": '{"id": "fake-turn-metadata-blob-not-real"}',
                "content-type": "application/json",
            },
            "resp_headers": {},
            "req_body": "",
            "resp_body": "",
        }
    )
    rh = result["req_headers"]
    for name in (
        "chatgpt-account-id",
        "session-id",
        "thread-id",
        "x-client-request-id",
        "sec-websocket-key",
        "x-codex-window-id",
        "x-codex-turn-metadata",
    ):
        assert rh[name] == "[REDACTED]", (name, result)
    # Non-identifying headers must still pass through untouched.
    assert rh["content-type"] == "application/json", result
    print("PASS: account/session/turn-identifying header VALUES redacted, names preserved")


if __name__ == "__main__":
    test_sensitive_header_values_are_redacted_names_preserved()
    test_token_shaped_substrings_in_bodies_are_redacted_even_outside_headers()
    test_missing_response_fields_pass_through_unchanged()
    test_account_and_session_identifying_headers_are_redacted()
    print("ALL PASS")
