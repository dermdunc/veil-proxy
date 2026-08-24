# The warning nobody was in the room to hear

A month earlier, a review of the daemon's session-namespace shim went looking for trouble and
found some: a header value pulled off the wire could, in principle, be garbled — not absent,
just malformed, a few bytes of nonsense where a session token should be. The obvious-looking fix
for that, `HeaderValue::to_str().ok()`, treats "couldn't parse" and "wasn't there" as the same
thing. They aren't. A missing header is supposed to fall back to a second resolution path, keyed
off which port the connection came in on. A garbled header is supposed to fail outright — the
one thing a governance-sensitive proxy cannot afford is silently downgrading "something is wrong
with this request" into "proceed as if nothing was said at all."

At the time there was no header-extraction code anywhere in the crate to fix. The daemon didn't
read a single header yet; it just held an open vault and answered fake requests in tests. So the
finding went into the module's own documentation instead of into a patch, addressed to whoever
would eventually write that code: don't map an invalid value to `None`. Map it to a real error.
The warning even named its own audience — "whichever milestone adds header-extraction code" —
because nobody writing it yet knew who that would be.

A month later, someone did. Building the milestone that finally makes the proxy read a real
request — pull the body off the wire, extract whatever session header came with it, hand both to
the code that used to only see fabricated test input — the header extraction got written the
straightforward way. `.to_str().ok()`. Exactly the shape the warning had described, because
nobody writing this pass had the old finding open in front of them; it lived in a doc comment on
a struct three files away, in a milestone that felt, correctly, like it was done and shouldn't
need revisiting.

It shipped. It passed its own tests, because the tests exercised a well-formed header and a
missing one, and both of those already worked. Full clippy and fmt were clean. A first review
pass — a fresh model, told to find problems, not confirm them — went looking at everything else
first: the JSON tree-walk that masks a request body field by field, the recursive descent into
tool calls, the code that decides which HTTP headers get copied to the outbound connection. That
pass ran for the better part of an hour and never finished; it stalled out mid-experiment,
running its own throwaway tests to check a hunch, and left behind only a fragment of what it had
been about to say.

A second reviewer — a different model entirely, shown the same code with no memory of the first
attempt — found it. Not by reading the old warning; there was no reason to go looking at
`session.rs`'s doc comments while reviewing `server.rs`. It found it by treating "a header can be
malformed, not just missing" as an obvious case worth checking on its own, the same instinct that
had written the original warning down a month before. Different model, different session,
same question, same answer: this collapses to `None` when it should fail closed.

Read side by side, the two findings are close to identical in wording. That's not a coincidence
worth being impressed by — it's what the practice is supposed to produce. The first review
existed specifically so a later builder wouldn't have to rediscover this from scratch; the second
review existed specifically because the first builder didn't have it in view when the moment
predicted actually arrived. Neither review made the mechanism airtight on its own. Together they
closed a gap that a single unbroken chain of attention — one person, one session, remembering
everything — was always going to be the wrong thing to rely on.

Three smaller findings came back in the same pass: a recursively-masked tool result could carry
a nested image block that the masker would happily treat as ordinary text instead of refusing to
forward it; an unrecognized content-block type got echoed back into the client's own error
message, including whatever string a malformed block happened to put there; a tool call missing
its required input field was waved through as "nothing to mask" instead of being treated as the
malformed request it was. All three fixed the same afternoon, each with a test that fails first
and passes after.

Full findings, and what changed, are in `docs/decisions.md`'s 2026-08-24 entry.
