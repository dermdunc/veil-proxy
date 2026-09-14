# The proxy worked. The product didn't.

The plan called this milestone "real Claude Code, Anthropic API-key mode, non-streaming."
Both halves of that description turned out to be wrong, and neither wrongness showed up
until the code actually ran against something real.

The build itself went cleanly. `vg-proxy`'s upstream client had never spoken TLS — it
only ever reached a mock server over plain HTTP, by design, since M3. Adding a real
`rustls` client, verifying certificates against a real local TLS server standing in for
a real CA, was the straightforward part: three tests, one proving a validly-signed
certificate for the right host is accepted, two proving a wrong-hostname or
untrusted-issuer certificate is refused. All three passed on the first real run.

Then came the part that only a live run can teach you. The plan's own framing —
"non-streaming" — assumed the real Claude Code CLI could be asked not to stream. It
can't. Every invocation, regardless of output format, sends `stream: true` to the real
API. `vg-proxy`'s own streaming guard, built earlier this same session specifically to
stop a streaming response from silently defeating masking, did exactly its job: it
refused every single attempt. Correct behavior, wrong plan — no real Claude Code session
was ever going to get through.

So the scope grew, on purpose and out loud: a minimal SSE demasker, not the full
streaming milestone this repo had deliberately deferred. Buffer the whole event stream,
reconstruct each content block's complete text before ever touching a placeholder, then
re-emit the stream with the consolidated result. The one interesting design question —
what happens when a masked placeholder gets torn across two separate delta chunks — got
its own test, deliberately splitting a real placeholder mid-token. It passed.

The live proof didn't. Not because of placeholders — because the reconstructed stream
was missing something dumber: every frame this module passed through unchanged, rather
than rewriting, was silently missing its own blank-line terminator. The real `claude`
CLI's SSE parser choked on the result immediately: "Could not parse message into JSON."
A hand-written unit test with `.contains()` assertions had waved this through, because
checking that some text is present in a string doesn't check that the string is still
well-formed SSE. Only a real parser, reading a real reconstructed stream, caught it. The
fix was two lines — restore the separator the parser had stripped off, on every code
path that emits a frame, not just the rewritten ones — but only the live run found it.
Fixed, tested with a stricter assertion that actually re-parses every emitted frame, not
just checks substrings.

The next attempt got further and hit something genuinely interesting: the model refused
to comply. The proof prompt asked it to repeat a synthetic value back "verbatim, and
nothing else" — which is precisely the shape of a prompt-injection probe, and Claude
correctly said so, declining to comply with an unexplained instruction disguised as data.
It even suggested the fix in its own refusal: say what the test actually is, instead of
hiding it. The rewritten prompt did that — named the intent, named the mission, asked
directly — and the model complied, reasoning out loud that it had found the matching
proof script already sitting in the working tree and treated that as real corroboration
rather than blind trust.

Then, on a third attempt, everything failed again — including a request as trivial as
"say hi." Not a masking bug this time. Not a `vg-proxy` bug at all. The real Claude Code
CLI's own system prompt carries a line that looks like an HTTP header dressed up as text:
`x-anthropic-billing-header: [REDACTED:SECRET]; cc_entrypoint=sdk-cli;`. Point
`ANTHROPIC_BASE_URL` anywhere other than the real Anthropic endpoint, and the CLI
substitutes that redaction sentinel for its own real internal billing token before the
request ever leaves the machine — a defensive move, presumably, against handing a
real credential to an arbitrary local endpoint. `vg-proxy` forwards it faithfully,
because forwarding faithfully is the whole job. The real API, on the other end, rejects
the sentinel outright: not a real billing header, so not a request it will process.

That single fact undoes the premise sitting underneath this milestone, and arguably
underneath the whole beta: pointing `ANTHROPIC_BASE_URL` at a local daemon is exactly
the mechanism this product exists to use, and the CLI itself won't let a real session
complete through it. Not a vg-proxy defect — nothing in this repo's own code can fix a
decision made inside a binary this repo doesn't build. A short detour into `claude
gateway`, an enterprise auth/telemetry subcommand with its own separate config file,
didn't turn up an obvious way around it either; it looks like a different, heavier
integration shape than "redirect one CLI invocation at one local proxy."

So the session ends with two honest, separate facts recorded side by side rather than
one blurred into the other: `vg-proxy`'s own TLS, certificate validation, and streaming
support are real, tested, and working — proven by a live run that caught two genuine
bugs before they could ship. And the thing that live run was ultimately trying to prove —
a real Claude Code session working end to end through this proxy — remains blocked by a
decision made somewhere this repo can't reach into. Filed as `RISK-0014`, not smoothed
over as "M5 done."
