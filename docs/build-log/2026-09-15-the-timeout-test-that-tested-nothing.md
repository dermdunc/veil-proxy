# The timeout test that tested nothing

**Date:** 2026-09-15

Same-day follow-up to the codec extraction — this time closing a gap the proxy had carried
since its first real network egress: no timeouts, no size limits. A slow or hostile upstream
could hold a connection open forever, or send a response that grew until the process ran out of
memory. Fixing it meant five separate clocks (connecting, waiting for headers, waiting for more
body, waiting for more of a streaming body specifically, and an overall ceiling) plus two size
caps, one per direction.

The interesting part wasn't the production code. It was how many ways there turned out to be to
write a timeout test that looks correct and proves nothing.

The first attempt at testing "does the connect timeout actually fire" used a timeout of one
nanosecond against a real, working local server, reasoning that a real network connection could
never complete faster than that. It couldn't — usually. Running the whole test suite together,
under real system load, the connection won the race often enough that the test failed with the
wrong error entirely, 30 seconds later, because it had fallen through to a *different* timeout
waiting for a response that was never coming. A near-zero deadline racing a fast operation isn't
a test of the timeout; it's a coin flip that happens to land the same way most of the time.

The fix for that one seemed obvious: point the connection at an address reserved by internet
standards for exactly this purpose — one no real router is supposed to forward anywhere. Except
"supposed to" isn't "guaranteed to." A second, independent review actually tried connecting to
that address from its own sandboxed environment and got an immediate, hard rejection instead of
the expected silence. The address wasn't unreachable in some abstract sense; it was unreachable
*here*, on *this* network, under *this* firewall — which is a property of the test's environment,
not of the code being tested. The eventual fix didn't reach for the network at all: a real local
server that accepts the connection, then simply never speaks the encryption handshake back. The
client hangs waiting for a reply that was never going to come, entirely on the loopback
interface, with nothing external in the loop.

A third test — proving that a slow-but-still-progressing response doesn't get killed — paused
for a fraction of a second under a multi-second allowance. It passed. It would also have passed
if the underlying timer had been implemented completely wrong, computing one fixed deadline at
the start of the response instead of resetting every time new data arrived, because the pause
was nowhere near long enough to expose the difference. A test that can't fail under the bug it's
supposed to catch isn't testing that bug. The fix split one comfortable pause into two shorter
ones whose *sum* exceeded the budget while neither one alone did — the only shape that actually
tells the two implementations apart.

None of these were bugs in the feature being shipped. All three were bugs in the proof that the
feature worked, each one plausible enough to read as correct on a first pass, and each one found
only because something colder — a full test run under load, a different sandbox's network
rules, a reviewer asking "would this test still pass if the code were wrong" — actually went
looking. The shipped code's own real defect count for this session was smaller: a genuinely
inaccurate doc comment, a duplicated formatting bug in how one HTTP header value gets compared,
and a case-sensitivity mismatch nobody had corrected since the header comparisons in this file
were first written.

Full technical detail: `docs/decisions.md`, 2026-09-15 entries.
