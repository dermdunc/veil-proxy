# The comparison that gave the secret away

The task was small on paper: give `mask()` a trace id, and sketch a buffer that could
one day group events by trace. Mint a UUID, return it, write a `BTreeMap`. An afternoon's
work, the kind of thing that doesn't usually make it into this log.

The `BTreeMap` needed its key type to have an order, and the trace id's type didn't have
one — by design. Months earlier, a different review round had gone to real trouble to
strip an `Ord`-adjacent trait, `Hash`, off every identifier type in this part of the
codebase, after proving that deriving it over a private field let anyone holding the
value recover it byte-for-byte through nothing but the ordinary, safe `Hash` trait. No
unsafe code, no privacy violation the compiler could see — just a `Hasher` that recorded
what it was handed instead of hashing it. That fix is still there, with a paragraph of
doc comment explaining exactly why.

So the obvious move — derive `Ord` on the trace id so the map could use it as a key —
needed its own justification, and one got written on the spot: a single `Ord::cmp` call
only ever returns `Less`, `Equal`, or `Greater`. It can't hand back the bytes it compared.
That's true. It went in as a doc comment right next to the derive, explaining why this
wasn't the same mistake as before.

It shipped that way for about an hour of session time, past a clean build, a passing test
suite, and a first read-through that had nothing to flag.

Then a second, unrelated reader — fresh context, told only what the code was supposed to
do and asked to find what was wrong with it — read that same doc comment and didn't buy
the argument. Not because the sentence was false. Because it only accounted for one call.
Nothing stops a caller from making a hundred and twenty-eight of them. Feed the type a
self-chosen candidate value, compare it against the real one, keep half of what's left
depending on which way the comparison falls, and repeat. That's an ordinary binary
search, and it recovers the entire private value — every bit of it — using nothing but a
trait that was defended, in writing, as safe because it "only returns an ordering."

It's the same hole as before, wearing a slower disguise. One comparison tells you almost
nothing. A hundred and twenty-eight of them, chosen adaptively, tell you everything.

The fix kept the map working without reopening the door: the trace id still has no public
order at all, but it now hands out a `u128` sort key through a method the rest of the
codebase can't call from outside this one crate. The map sorts on that instead. Anyone
holding a trace id from outside still can't compare two of them to each other — the
capability that made the binary search possible in the first place simply isn't there to
use.

A second, differently-built model looked at the fixed version afterward and found one
more thing, smaller: a comment claiming "only two callers use this function" that had
been true when it was written and stopped being true two files later in the same change,
once a third caller got updated and the comment didn't. Not a security finding. Just a
reminder that a sentence defending a decision is only as good as the audit that produced
it, and a change that grows after the sentence is written makes the sentence wrong,
however carefully reasoned it was at the time.

Full findings and the fix are in `docs/decisions.md`'s 2026-08-24 entry.
