# The safety net that moved

**Date:** 2026-09-15

For a while, `vg-proxy`'s upstream forwarder had exactly one job when it came to headers:
copy five specific ones — `content-type`, `x-api-key`, `authorization`, `anthropic-version`,
`anthropic-beta` — and drop everything else. That allow-list lived inside the function that
actually sent bytes over the wire. It didn't matter who called it or what they passed in;
the function itself was the last line of defense, and it always ran.

Today's work was supposed to be tidying, not security work. The whole proxy had grown
Anthropic-shaped assumptions everywhere — in the routing table, in how it walked a request
body, in how it stitched a streaming response back together, and yes, in that header list.
The plan (this project's own "Track H") wants to support more than one AI coding assistant
someday, and you can't do that with Anthropic's specific shapes wired into the transport
layer. So the job was: pull all of that into one place, call it a "codec," and leave the
transport layer holding nothing but bytes and an origin.

Mechanically, this went fine. The move was clean, the tests passed, a real live session
against the real Anthropic API worked exactly as before. But moving the header list out of
the transport function meant something had to decide, somewhere else, which headers were
safe — and that decision now happens *before* the transport function is called, not inside
it. The function itself became honest: "give me headers, I'll send them." No more built-in
opinion.

In today's production code path, nothing changed. The one caller that matters always asks
the codec first. But a second, independent reviewer — a different model, given nothing but
the diff and told to find what was wrong with it — noticed something the first pass missed
entirely: that function is still public, and a test file already calls it directly, headers
and all. The refactor hadn't introduced a live bug. It had quietly moved a guarantee from
"this is always true, by construction" to "this is true today, because the one caller who
matters happens to behave." Those are very different claims to make about a masking proxy
whose entire purpose is not leaking things by accident.

The fix wasn't to reverse the refactor — putting Anthropic-shaped policy back into the
transport layer would have undone the actual point of the work. The fix was to say the
quiet part loudly: a comment on the function itself, spelling out exactly what changed,
who's responsible for it now, and what a future caller needs to do before reaching for it.
Not a solved problem. A named one, which in a project with this much of a paper trail
turns out to be most of what "solved" means anyway.

Two smaller things came out of the same pass. A denylist meant to catch "anything that
looks like a credential" had a gap where the two credentials it was explicitly built to
protect — an API key header and an auth header — weren't reflected in the *pattern* that
was supposed to generalize from them. And a header-classification bug meant two entirely
legitimate, already-reviewed headers were about to get logged as "suspicious, please
review" on literally every single request forever, which is the kind of alert that trains
everyone to stop reading alerts.

Full technical detail: `docs/decisions.md`, 2026-09-15 entry.
