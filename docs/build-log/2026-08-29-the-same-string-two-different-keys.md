# The same string, two different keys

Today the proxy finally had something to send. `EdgeEvent` — a single record for one
demask decision or blocked attempt — got real serialization, a canonical JSON form, and
an HMAC-SHA256 signature. On the other end, veil-observatory (a separate, private repo)
got a matching schema and a verifier that could check that signature for real. Both
sides tested clean on their own: 176 tests here, 547 there, a shared golden vector
byte-for-byte identical between a Rust process and a Python one.

Then it was time to actually point one at the other.

The obvious way to do that is to start a real `veil-observatory serve` process, export
the same `VEIL_RECEIPT_KEY` in both terminals, and run something real against it. So
that's what happened — except "the same key" turned out to be doing more work than the
sentence implies. This crate reads `VEIL_RECEIPT_KEY` as a hex string and decodes it into
bytes. veil-observatory reads the exact same environment variable name and UTF-8 encodes
whatever string is there, directly, no decoding. Set the identical string in both
terminals and you get two completely different keys — sixteen real bytes on one side,
thirty-two ASCII bytes on the other — and every signature fails forever, silently, with
nothing on either side to say why.

Nobody's an idiot for doing this. It's the natural thing to try: same variable name,
copy the value, done. The bug is quiet in exactly the way this whole project keeps
finding quiet bugs — no exception, no obviously wrong output, just two processes that
agree they're using "the same key" while actually using two different ones.

Caught before it caused anything, by writing down each side's actual parsing code before
trusting the plan to "set the same key on both ends." Once that was clear, the fix was
just picking a 32-byte value in advance and expressing it twice — the plain ASCII string
for veil-observatory's side, the hex encoding of those same bytes for this side. Then the
real thing worked: a genuine `DemaskDecision`, signed by a real signer, sent by a real
background emitter, over a real HTTP connection, to a real separate process, which logged
`202 Accepted` and wrote the record to its own evidence store — with the actor field
showing up as a pseudonym hash, never the name it started as.

The lesson isn't "read the source before you trust an env var," although that's true.
It's narrower: a shared name is not a shared contract. Two sides of an integration can
each be completely correct on their own terms and still disagree about what a piece of
configuration means, and the place that shows up is never in either side's own tests —
only in the one place both sides actually meet.

See `docs/decisions.md`'s 2026-08-29 entries and
`crates/vg-audit/tests/live_edge_event_integration.rs` for the exact repeatable version
of this, key format spelled out so nobody has to rediscover it by watching a signature
fail.
