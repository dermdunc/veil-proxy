# The same gate, broken twice

The rule this function exists to enforce is small: telemetry never leaves the machine
unless someone has opted in to *both* a signing key and a destination to send it to. If
either one is missing, do nothing — silently, not as an error. A process that never
configured telemetry should never notice this code exists.

Today's session added a second way to supply that signing key — a real per-device
certificate, auto-detected from the OS keychain, instead of the existing key pulled from
an environment variable. The plumbing for the opt-in gate had to change shape to make
room for it. Twice, changing that shape broke the one guarantee the gate exists for, and
both times the break was the same *shape* of mistake wearing a different disguise.

The first time: the rewritten gate checked "is a key present" before it checked "is a
destination configured." That ordering looks harmless — both checks still happen — but a
key that's present-and-broken (a stale, malformed value left over from an old config) now
got *parsed* before anyone asked whether a destination existed at all. Parsing a broken
key returns an error. So a process that had never configured a destination — meaning it
had never opted in to anything — started failing at startup over a key it was never going
to use. The fix was to check that both things exist *before* looking closely at either
one.

That fix used two separate checks, one per environment variable, each of which could
itself fail in its own way if the variable was set to something that wasn't valid text.
And each of those individual checks still returned early on its own failure — which is
the exact same mistake as before, just moved one layer down. "Destination is set but not
valid text" would bail out before ever asking whether a key was configured at all, even
though the honest answer, for a process with no key, was still supposed to be "do
nothing," not "error."

Neither bug was found by the same reviewer. The first came from a routine adversarial
pass. The second came from a colder second opinion — a different model, asked to find
what the first review missed — which is exactly the scenario that second opinion exists
for. The actual fix, once seen, was to stop treating "is it there" and "is it valid" as
one question. Splitting them into two separate results — presence as one layer, validity
nested inside it — meant the gate could check that both variables exist *at all* without
ever having to look at whether either one was well-formed. Only once both were confirmed
present did their validity matter, and by then a bad value produces a real, deserved
error instead of masquerading as a false "not configured."

The class of mistake is worth naming plainly: whenever a gate is supposed to fire on
"is X configured," checking anything more specific than presence — even in passing, even
symmetrically for both sides — reopens the exact hole the gate exists to close. It took
finding the same hole twice, in the same function, in the same afternoon, to make that
rule feel less like a style preference and more like a structural one.

Full technical detail — the exact code, the doubt-driven-development findings that caught
both instances, and the fixes applied alongside them — is in `docs/decisions.md`'s
2026-08-31 "Config surface" entry.
