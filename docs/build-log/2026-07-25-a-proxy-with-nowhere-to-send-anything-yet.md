# A proxy with nowhere to send anything yet

VeilGremlin's T11 sign-off in July was a NO-GO with a specific, narrow complaint: the hook
adapter proves the mask/demask mechanism works, but it can't deliver on the actual promise —
"PII never leaves this machine" — because Claude Code's hooks only ever see the latest typed
prompt, not the real request going out the door, and they can block it or let it pass, never
rewrite it. The fix everyone already agreed on was a local proxy sitting where the request
actually leaves the machine. What took three more weeks was figuring out, with evidence
instead of assumption, exactly how that proxy has to behave — the plan for it went through
three major revisions and a doubt-driven-development pass that fetched Claude Code's own
gateway documentation directly rather than trusting a research summary of it, because that
summary turned out to misquote both the plan and the docs it was citing.

Today was the first line of code against that plan, and it's deliberately the least
interesting milestone in it: a proxy that can't talk to anything.

`crates/vg-proxy`'s M1 is a plain HTTP server on loopback with a route table and nothing else.
Point a request at `/v1/messages` and it gets classified as "this would need masking" and
handed back a canned response saying so. Point one at `/model/some-model/converse` — a real
Bedrock endpoint, just one Claude Code never calls — and it gets a 403. There's no upstream
client anywhere in the crate. `cargo tree` confirms it: nothing in the dependency graph is
even capable of making an outbound HTTP call yet. That's not an accident of scope-cutting, it's
the actual design property this milestone exists to establish — every later milestone that
adds real credentials, real masking, real forwarding, builds on top of something that was
already proven incapable of leaking anything, rather than something that's supposed to be
correctly configured not to.

The route table itself is a small case study in why the plan needed three revisions. An
earlier research pass claimed "the Batch API" needed masking support — carried forward from a
generic API reference, never checked against what Claude Code's CLI actually calls. It
doesn't call it. A doubt-driven-development pass that fetched Anthropic's actual gateway
protocol page found no batch route anywhere on it, and found a route nobody had accounted for
instead (`/v1/models`, a real, documented, opt-in model-discovery endpoint that the proxy's
own fail-closed design would otherwise have silently broken for anyone who enabled it). Both
corrections are just table rows now. Getting them right before any masking logic exists means
nobody has to remember to go back and fix the route table later, under the pressure of a
feature that's already half-built on top of the wrong one.

Verified it the boring way, too: ran the server, hit it with `curl` for each of the three
outcomes, watched a `mask`-classified request come back saying so, a `pass` HEAD request
return correctly (after tripping over a `curl -X HEAD` gotcha that isn't a server bug — the
flag has to be `--head` for curl to know not to wait for a body HTTP correctly never sends),
and a blocked route come back `403`. Small milestone, but the point of building it small was
to be able to trust it completely before anything gets stacked on it.

See `docs/decisions.md` (2026-07-25) for the two scoping calls, and
`~/hekton/docs/plans/veilgremlin-masking-proxy-plan-v1.md` for the plan this implements.
