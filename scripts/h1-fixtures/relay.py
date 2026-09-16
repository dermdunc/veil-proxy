#!/usr/bin/env python3
"""Throwaway record-and-relay listener for Track H, H1 (Codex interception + auth spike).

Explicitly allowed to be throwaway (plan §4, H1 row: "throwaway-code-allowed") — this is
a spike tool, not shipped product code. Plain stdlib Python, deliberately: no new
dependency of any kind, matching this intent's own disproof criterion.

Per critique #16 (adopted in the plan): a BARE recorder can't validate auth end to end or
capture a real upstream corpus — this one actually forwards every request to the real
upstream (`--upstream-host`) over real TLS (Python's stdlib `http.client.HTTPSConnection`,
real WebPKI verification, never disabled) and returns the real response, while recording
the full exchange as one JSON line per request/response pair into `raw/capture.jsonl`
(gitignored — never committed; see `scrub.py` and `.gitignore`'s own H1 entry).

Usage:
    python3 scripts/h1-fixtures/relay.py --upstream-host api.openai.com [--port 0]
    python3 scripts/h1-fixtures/relay.py --upstream-host chatgpt.com [--port 0]

Prints the bound port to stdout on startup so a caller (or a human) can read it back
before pointing `codex` at it via `-c openai_base_url=http://127.0.0.1:<port>/v1` or a
custom `-c model_providers.veil.base_url=...` override.

DO NOT run this against a real `codex` CLI / real Codex backend again. Two independent
adversarial reviews (2026-09-15/16) of this spike's first real captures found real ChatGPT
account/session identifiers and real environment data (repo path, username, git commit
hash) embedded in captured request BODIES that no practical scrubber could reliably catch
— see `scrub.py`'s own module doc for why. The corpus this tooling now ships
(`sanitized/h1-spike-01.jsonl`) is hand-authored and synthetic, not derived from a real
capture. This script is kept for its structural value (it demonstrates a working
record-and-relay design and is the reference for H2a/H3's real interception work) but a
real re-run risks reproducing the same class of leak this session found twice.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import ssl
import sys
import time

RAW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw")
RAW_LOG = os.path.join(RAW_DIR, "capture.jsonl")


class RelayHandler(http.server.BaseHTTPRequestHandler):
    upstream_host: str = ""
    upstream_port: int = 443
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A002 - stdlib override
        sys.stderr.write(f"[relay] {self.address_string()} - {fmt % args}\n")

    rewrite_from: str = ""
    rewrite_to: str = ""
    mechanism_label: str = ""

    def _rewritten_path(self) -> str:
        if self.rewrite_from and self.path.startswith(self.rewrite_from):
            return self.rewrite_to + self.path[len(self.rewrite_from):]
        return self.path

    def _relay(self) -> None:
        length = int(self.headers.get("content-length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        forward_headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in ("host", "content-length")
        }
        forward_headers["Host"] = self.upstream_host
        forward_path = self._rewritten_path()

        # Real TLS, real WebPKI verification via the OS trust store — `ssl.create_default_context()`
        # never disables certificate/hostname checking. Matches this family's own "never
        # bypass verification" discipline (A2, `upstream.rs`).
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            self.upstream_host, self.upstream_port, timeout=60, context=context
        )
        status: int | None = None
        resp_headers: dict | None = None
        resp_body: bytes | None = None
        error: str | None = None
        try:
            conn.request(self.command, forward_path, body=body, headers=forward_headers)
            resp = conn.getresponse()
            # Recorded as soon as they're known, before the body read that can itself
            # fail — otherwise a body-read failure looks identical to a connect/request
            # failure in the capture (both left `status`/`resp_headers` as None), which
            # a real review found made "the upstream never responded" and "the upstream
            # responded but we couldn't read the body" indistinguishable after the fact.
            status = resp.status
            resp_headers = dict(resp.getheaders())
            resp_body = resp.read()
            self.send_response(resp.status)
            for name, value in resp.getheaders():
                if name.lower() in ("transfer-encoding", "content-length", "connection"):
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as exc:  # noqa: BLE001 - a spike tool; report and record any failure
            error = repr(exc)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"relay error: {exc}".encode())
        finally:
            conn.close()
            self._record(forward_path, forward_headers, body, status, resp_headers, resp_body, error)

    def _record(
        self,
        forward_path: str,
        req_headers: dict,
        req_body: bytes,
        status: int | None,
        resp_headers: dict | None,
        resp_body: bytes | None,
        error: str | None,
    ) -> None:
        os.makedirs(RAW_DIR, exist_ok=True)
        entry = {
            "ts": time.time(),
            "mechanism": self.mechanism_label,
            "method": self.command,
            "path": self.path,
            "forward_path": forward_path,
            "upstream_host": self.upstream_host,
            "req_headers": req_headers,
            "req_body": req_body.decode("utf-8", "replace"),
            "status": status,
            "resp_headers": resp_headers,
            "resp_body": resp_body.decode("utf-8", "replace") if resp_body is not None else None,
            "error": error,
        }
        with open(RAW_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming convention
        self._relay()

    def do_POST(self) -> None:  # noqa: N802
        self._relay()

    def do_PUT(self) -> None:  # noqa: N802
        self._relay()

    def do_DELETE(self) -> None:  # noqa: N802
        self._relay()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0, help="0 = OS-assigned ephemeral port")
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, default=443)
    parser.add_argument(
        "--rewrite-from",
        default="",
        help="Rewrite a leading path prefix before forwarding, e.g. /v1/",
    )
    parser.add_argument(
        "--rewrite-to",
        default="",
        help="Replacement for --rewrite-from, e.g. /backend-api/codex/",
    )
    parser.add_argument(
        "--label",
        default="",
        required=True,
        help=(
            "Mechanism label stamped into every captured entry's 'mechanism' field "
            "(e.g. 'openai-base-url-override'). Required: a corpus entry with no "
            "machine-checkable mechanism tag can't be attributed to a specific test "
            "after the fact — run one relay process per mechanism under test."
        ),
    )
    args = parser.parse_args()

    RelayHandler.upstream_host = args.upstream_host
    RelayHandler.upstream_port = args.upstream_port
    RelayHandler.rewrite_from = args.rewrite_from
    RelayHandler.rewrite_to = args.rewrite_to
    RelayHandler.mechanism_label = args.label

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), RelayHandler)
    print(
        f"[relay] listening on 127.0.0.1:{server.server_port} -> "
        f"https://{args.upstream_host}:{args.upstream_port} "
        f"(raw capture: {RAW_LOG})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
