# The client asked for /v1. The server only understood /backend-api/codex.

Track H's plan named a real test order for the Codex interception spike (H1): try
`openai_base_url`, try a custom provider entry, see which one actually reaches a real
backend. The plan also named a fixture-governance gate that had to exist and be
*demonstrated* — not just described — before any of that testing could start: a scrub
script with its own test, a `.gitignore` entry, and a pre-commit hook, proven by
deliberately committing a raw-looking file and watching it get rejected. That part went
first, cleanly, and produced a small, satisfying moment: `git commit` refusing a file
that had a fake bearer token sitting in it, with a message naming exactly why.

Then came the actual spike, and the first real surprise. Pointing Codex's CLI at a local
listener via a custom `model_providers.veil` entry worked, in the sense that Codex
accepted the config and tried to talk to the listener. But nothing came back cleanly:
the model-catalog fetch failed with an honest, visible 404 (the client's own log said
so), and the real completion request came back redirect-shaped instead, which the
client obligingly followed straight into `chatgpt.com`'s ordinary web app shell — an
HTML page, not an API response, for both failure shapes. The listener was faithfully
forwarding whatever path the client asked for — `/v1/models`, `/v1/responses` — straight
through to `chatgpt.com`. The client was speaking the public OpenAI API's path
convention. The real backend behind ChatGPT-authenticated Codex traffic doesn't live
there at all; it lives under `/backend-api/codex/`. `codex doctor`'s own reachability
check had said as much all along, just with the path partially redacted in its
human-readable report — the shape was visible before the failure was, in retrospect.

One `--rewrite-from /v1/ --rewrite-to /backend-api/codex/` flag later, the same setup
produced a real response: a genuine model catalog, then a real streamed answer to a
throwaway prompt, `pong`, billed at a few thousand real tokens. That rewrite is now a
named, real requirement for any future Codex codec — something the existing Anthropic
codec never needed, because it forwards the client's path unchanged and that happens to
already be correct for Anthropic's API.

The second surprise came from `openai_base_url` specifically, and answered a question
the plan had flagged but not resolved: does Codex's `wire_api` negotiation actually fall
back cleanly from WebSocket to HTTP? The built-in provider tried a WebSocket upgrade
first — real `Sec-WebSocket-Key` headers, a real five-retry loop — failed against a
listener that only spoke plain HTTP, and then said so out loud: "Falling back from
WebSockets to HTTPS transport," and finished the request anyway. That's not a guess from
reading vendor docs; that's the actual client, this session, doing the actual thing the
docs claimed it would do.

A third result looked, at first, like the best one: setting `HTTPS_PROXY` with no
Codex-specific configuration at all appeared to route every real request — model catalog
fetch, WebSocket attempts, HTTP fallback — through the same local listener, using
nothing but a standard environment variable. That would have been the same shape of
interception this proxy already uses for Claude Code, and a genuinely appealing
finding. It didn't survive a second look — the attempt that produced it was killed
before it finished and never re-verified. Re-run the identical command three more times
and the real behavior was different: Codex issued a genuine `CONNECT chatgpt.com:443`
tunnel request, the listener (which only ever spoke plain `GET`/`POST`, never
`CONNECT`) answered `501 Unsupported method`, and Codex retried the `CONNECT` forever —
`ERROR: Reconnecting... waiting for network`, with no cap seen across several real
minutes of waiting and one live, real-time log-tail watching it happen. Whatever
produced the first, unverified result never reproduced across three careful attempts.
The honest finding isn't "the proxy variable works" — it's that a real interception
layer sitting behind `HTTPS_PROXY` needs to actually speak `CONNECT`, and this
session's listener never did.

That inconsistency was the smaller of two things an adversarial review caught before
any of this reached a commit. The bigger one: a scrubber built to redact bearer tokens
by name had missed real account and session identifiers entirely, and those were
sitting unredacted in a corpus about to be retained. Fixed, corpus regenerated — and
then a second, independent review (a different model, reading the corrected version
cold) found the fix itself had a defect worse than the original: the *regression test*
written to prove the redaction worked had, without anyone noticing, used the actual
real captured account ID as its "example" input. A privacy fix had almost shipped a
real personal identifier into source, disguised as a unit test. That got replaced with
obviously-fake placeholders, and a third, deeper problem surfaced alongside it: the
real request *bodies* Codex sends carry a full real environment envelope — repo path,
username, commit hash — as ordinary structured JSON, which no header list or
token-shaped pattern was ever going to catch, because none of it looks like a secret.
It looks like normal data, because it is normal data; it just isn't supposed to leave
this machine. At that point retaining any real capture at all stopped looking like a
scrubbing problem and started looking like the wrong plan. A second model (asked
directly: given this, how would you satisfy the requirement for a corpus without
another leak?) recommended dropping real-capture retention entirely in favor of a
hand-authored, clearly-labeled synthetic one — real header names and paths and event
types, preserved because they're not sensitive, everything else invented and marked as
such. A third model, asked only to validate the resulting plan before anything was
built, caught one more thing: quietly swapping "a redacted real corpus" for "a
synthetic one" was itself a real deviation from what this milestone had originally
promised to produce, and deserved to be said out loud to the person who'd actually
asked for that corpus, not just written into a file only this project reads. So it was
— along with the other three places this session's own scope had quietly narrowed —
and accepted, on the record, in the same place the mission's original promises live.

Full mechanism decision, with the exact log lines and every correction above, in
`docs/decisions.md`, "Track H, H1: Codex interception + auth spike." The corpus behind
it is small on purpose now — five hand-authored entries, two real throwaway prompts
(`hi` for the path-discovery probe, `pong` for everything after) — but the real
evidence is in the write-up, not the file: what Codex actually does on the wire, twice
corrected before anyone but this project ever saw it.
