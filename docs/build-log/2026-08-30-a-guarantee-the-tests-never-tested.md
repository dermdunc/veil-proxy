# A guarantee the tests never tested

The emitter's whole pitch is "fire-and-forget, fail-open." Every test for it passed. It
still had a real hole, and the reason is almost embarrassing once you see it: the tests
never actually exited.

`cargo test` runs inside one long-lived process. Every emitter test that mattered wrote a
record, then called a little polling helper — `wait_for(timeout, || condition)` — before
checking anything. That pattern is correct and deliberate: the background thread that
actually sends the HTTP request runs concurrently, so you have to wait for it before you
can assert on the outcome. Nothing wrong with that, in a test.

But one of this module's two stated jobs is running inside `vg`, the CLI — a process that
opens, does one thing, and exits. There's no `wait_for` in a hook invocation. There's just
`try_emit`, then `main` returning, then the process going away. And a background OS thread
does not get to finish its sentence when the process exits. It gets killed, mid-word,
whatever it was doing.

So the actual production path — the one the tests were supposedly proving worked — had
never been exercised as itself. It had only ever been exercised wrapped in a polling loop
that doesn't exist in the real binary. A hook could `try_emit` a genuine, correctly signed
record, get `true` back, and lose it anyway, because the connect-handshake-POST sequence
never got scheduled before the process was gone. Passing every test the whole time.

The fix is not complicated once you see the actual gap: give `EdgeEventEmitterHandle` a
`Drop` impl that waits, briefly, for what's already queued to actually go out, then joins
the thread if it can. Bounded on both ends, so a stuck connection can't hang a CLI
invocation — it can cost it half a second, never indefinitely. The interesting part isn't
the fix. It's that "every test passes" and "the thing works in production" turned out to
be two different claims, and the gap between them was exactly the one difference between a
test process and a real one: whether anything sticks around long enough to wait.

The new test that actually proves this doesn't poll. It emits, then drops the handle
immediately, in the same scope, with nothing in between — the one thing every other test
in the file carefully avoided doing. That's the whole trick. Not a cleverer assertion.
Just finally doing the thing a real short-lived process actually does.

See `docs/decisions.md`'s 2026-08-30 entry for the second defect found the same pass (a
panic on thread-spawn failure, which is a more ordinary kind of bug — this one earned its
own writeup because the shape of the miss is worth remembering past this one module).
