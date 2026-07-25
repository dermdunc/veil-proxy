# The fix that broke what it was fixing

M2's job was small on paper: open the vault once instead of once per request, and give the
proxy a way to figure out which of many concurrent Claude Code sessions a given HTTP request
belongs to. The daemon core. The part that turns "a mechanism that works" into "a mechanism
that stays open and keeps track of who's who."

The "who's who" part is where it got interesting.

The plan calls for two ways to identify a session: a header Claude Code carries on every
request, or — for callers that can't thread a custom header through — a dedicated loopback
port per session. The header path is simple. The port path looked simple too, right up until
the obvious implementation turned out to be actively wrong. The tempting version derives a
session's identity straight from the port number: hash the port, get a UUID, done, no state to
manage. It also silently breaks the first time the OS reuses that port for an unrelated later
session, because the daemon would keep resolving requests on that port to whoever used it
first. Isolation is the entire point of this shim. A stateless shortcut that quietly
un-isolates two different users' data the moment a port gets recycled isn't a simplification,
it's a bug wearing a simplification's clothes. So: registration instead. Something has to
explicitly tell the daemon "this port belongs to this session now," and something has to tell
it when that's no longer true.

That "when it's no longer true" part is where a real bug showed up — not in the obvious
place.

A single-model review pass went through the daemon core first and found seven real things:
a mutex that would permanently wedge every session in the process if anything ever panicked
while holding it, a session-registry key that only stored a port number and would silently
collide two sessions if the daemon ever bound both `127.0.0.1` and `::1`, an unbounded string
getting echoed into an error message, missing concurrency tests despite two separate locks
guarding shared state. Genuine findings, cheap fixes, exactly the kind of thing this process is
for. Among the fixes: a small new method, `unregister_port`, so that whichever future code
manages a session's lifecycle has a clean way to release its port mapping when the session
ends.

Then a second, independently-run review — a different model, no memory of writing the first
fix — went through *that* fix specifically. And found that `unregister_port` had its own bug:
it removed a port's mapping by address alone, with no check on which session currently owned
it. Which means a session's own delayed cleanup call — arriving late, as cleanup calls do —
could delete a *different*, newer session's live mapping, if that newer session had already
taken over the same port in the meantime. The very function built to make port reuse safer
had a path where it made a live session's isolation *worse*: not the original derivation bug,
but a close cousin of it, hiding inside the fix.

That's the finding worth writing down, not because it was dramatic — it wasn't, the whole
thing lives in about four lines of a `HashMap` lookup — but because of what it says about
review order. The first pass caught real problems in the daemon's original code. It did not,
and structurally could not, catch a problem in code that pass itself wrote, because the pass
that writes a fix and the pass that would doubt it were the same pass. It took a second,
independent look — one deliberately pointed at "what did the last round just add," not "what's
wrong with this file in general" — to find the bug in the fix. The repo's already been doing
this for detector work for weeks; this is the first time it caught something in the proxy's
own new code, and it's a decent argument for why the pattern earns its cost: the interesting
bugs increasingly hide in the layer that was supposed to be the safety net.

Fixed with a compare-and-remove: `unregister_port` now takes the namespace the caller believes
it owns, and only actually removes the mapping if that's still what's registered. A stale
cleanup call that no longer matches current reality becomes a no-op instead of a deletion.
Regression-tested directly — register session A, hand the port to session B, call A's stale
cleanup, confirm B's mapping survives.

Two rounds, twelve real fixes between them, all landing before any of this code touches a real
HTTP request. See `docs/decisions.md` (2026-07-25) for the full findings list, including the
ones that turned out not to be bugs at all — a few things a reviewer flagged as suspicious were
actually just the plan's own already-decided trust model, working as designed.
