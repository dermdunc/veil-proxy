# A name that looked like a secret

The bug was real and worth fixing: the code that puts a masked value back the way it was, once
a model's answer comes home, only knew how to look inside two shapes of thing a response could
contain. Everything else — a block of the model's own reasoning, a call out to a tool running on
the provider's own servers, anything newer than the two shapes the code was written to expect —
passed through untouched. If a placeholder happened to end up inside one of those, it would stay
a placeholder forever. Not dangerous. Just broken, quietly, in a way nothing would ever announce.

The fix looked clean: stop trying to guess what a response block might contain, and just look
everywhere. Walk the whole thing, restore anything that matches something already known, leave
everything else alone. No more list of shapes to keep up to date by hand. Whatever the provider
ships next year, this code would already handle it.

It shipped that way, briefly. Tests passed. The build was clean.

A second reviewer, given nothing but the fixed code and no memory of how it got there, found the
edge the first fix had walked past. "Look everywhere" doesn't know the difference between the
text a model actually wrote and the small print around it — the field that just says what *kind*
of block this is, the field that names which tool got called, the field that's really just an ID.
Those aren't sentences. They're labels. And the thing this whole system generates to replace a
real value with something safe to say out loud isn't a random string — it's a short, predictable
one. The first email in a conversation becomes a label like the fifth item in a numbered list. The
second becomes the sixth. There's no scrambling involved; that's the whole design, so a human can
tell at a glance that two mentions are the same person without ever seeing who.

Predictable, it turns out, cuts both ways. A label chosen for being easy to recognize is, for the
exact same reason, easy to accidentally already exist somewhere else. A tool can be named almost
anything. Across a long enough conversation, with enough of these short labels minted, the odds
that one of them lines up with a tool's actual name aren't the coincidence they'd need to be to
ignore. And "look everywhere" doesn't check whether a string is prose or a label before deciding
to replace it. If a tool happened to be called the same short label already standing in for
someone's email address, that tool would quietly get renamed, mid-response, to the address itself
— and the program on the other end that was supposed to call it by its original name would fail
to find it.

The fix for the fix was smaller than the fix itself: a short list of the field names on a block
that are never prose — what kind of block this is, its id, the tool it names, the signature
attached to a thought — and everywhere else, look as broadly as before. Not a return to guessing
what shape a response might take. Just a line between what a model wrote and what merely labels
what it wrote, drawn once, cheaply, instead of never.

Full findings and the fix are in `docs/decisions.md`'s 2026-08-24 M4 entry.
