# The fix was already in the repo

Yesterday's entry ended on a blocked note: `vg-proxy`'s TLS, certificate validation, and
streaming support all worked, but the one thing that mattered most — a real Claude Code
session completing end to end through the proxy — didn't, because the real `claude` CLI
redacts its own billing header the moment `ANTHROPIC_BASE_URL` points anywhere but the
default Anthropic endpoint. That felt like it might undo the premise of the whole beta:
the mechanism the product depends on, refused by the client it depends on.

It didn't take new code to fix. It took asking the right question of someone else.

Rather than guess at a workaround, this session asked Codex for an independent read on a
bigger question than the immediate blocker: not "how do we get this one proof script
working," but "what does it actually take for `vg-proxy` to sit in front of AI coding
harnesses generally." Codex's answer to that bigger question happened to name a small,
concrete thing worth trying first: the redacted line isn't a bare credential at all — it's
Claude Code's own *attribution* block, a client-version-plus-fingerprint tag, and
Anthropic's own gateway-compatibility documentation names an environment variable,
`CLAUDE_CODE_ATTRIBUTION_HEADER=0`, that tells the CLI to omit it entirely.

That variable was already sitting in this repo, doing its job somewhere else. `vg run` —
the command that wraps a real coding-agent invocation in `vg-proxy` — has injected exactly
that variable into every launch since M1, with its own passing regression test proving it.
Nobody had connected it to the live-run proof's own separate `claude -p` invocation,
because the proof was written to drive the CLI directly, not through `vg run`. The fix was
setting the same variable in one more place.

Re-run the proof, and it goes all the way through: real TLS to the real API, real
streaming, a synthetic secret masked before it leaves the machine and correctly demasked
in the real reply that comes back. `RISK-0014`, filed less than a day earlier as
Critical/High, closes the same day it was opened.

The bigger question Codex was actually asked about is still open. Its own recommendation —
a proxy scoped to one wrapped process rather than one that intercepts system-wide traffic,
built around a transport layer generic enough to hold more than one provider's protocol —
is real design work, not started. `server.rs` today only knows plaintext HTTP and one
provider's shape. That's honestly named as follow-on work, not folded into this closure to
make the milestone look more finished than it is.

The smaller lesson is the one worth keeping: the answer to "is there a real workaround"
was worth checking with the same rigor as "does the code work" — and in this case, part of
the answer had already been built, tested, and merged for an unrelated reason, waiting to
be reused.
