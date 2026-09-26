# The bug report that measured the wrong thing

**Date:** 2026-09-26

The proxy's first real test by someone else's project arrived as a bug report. veil-demo, the
public demo for this family, ran a real Claude Code session through vg-proxy: several turns, real
tools, a small billing codebase with fake customer data planted in it. Everything before this had
been one question and one answer. This time the session died at turn three, and the report listed
five reasons why.

The blocking one was simple once seen. When Claude "thinks" before answering, the thinking comes
back as its own kind of content block, and the client sends it back on every later turn as part
of the conversation history. The proxy had never been taught that block type, and it refuses
anything it doesn't recognise. That is the right default for a privacy tool, and here it was
fatal. Accepting the block had a catch: each thinking block carries a cryptographic signature
over its exact text. The proxy's job is to change text on the way out, and changing signed text
risks breaking it. The design that shipped never rewrites a thinking block's text on the way back
to the user, remembers every block the model actually sent, and returns those blocks verbatim.
The model wrote them, so sending them back reveals nothing new.

The more instructive finding was the third. The report said the secret detector was flagging
ordinary file paths, and it included a table: path, entropy score, flagged or not. The table was
careful and specific. It was also partly wrong. Running those exact paths through the real
detector showed that the plain ones, like `/Users/alice/Development/acme-billing`, had been
excluded for months. The table had computed a raw score without the exclusion rule that runs
first. The real trigger was narrower: a single path segment mixing letters and digits, such as
`phase-1a`, `run3` or `v2`. That is exactly what the spike's working directory contained. Fixing
the table's version of the problem would have changed nothing.

The first fix for the real trigger was wrong too, in a more dangerous direction. The goal was to
let short segments like `v2` through inside paths. A fresh reviewer with no stake in the change
found that it also let through `postgres://app:Xk9mQ2vL@db.internal/prod`, a database password
sitting in a URL, along with password-reset links and grouped licence keys, all of which the
detector caught before. A precision fix that quietly costs recall is the worst kind for a privacy
tool, because nothing visibly breaks. Each counterexample the reviewer produced is now a
permanent test. A second reviewer then found that the tightened rule could still be walked
around by putting a slash between each group of a key, so the limit now applies to the whole
token: at most two short, lowercase, letters-and-digits pieces, a few bytes in total. That is
enough for `phase-1a/run3` and not enough for a key.

One finding was deliberately not fixed. When the model couldn't make an edit, it dumped the file
byte by byte (`od -c`), and the planted IBAN came back as single characters separated by spaces.
No detector sees that, the model reassembled it, and the value went upstream in its next message.
The number was fake, but the gap is real and general. It is now a named risk with tests that
assert "not detected", so the day someone closes it, those tests have to be changed on purpose.

Full technical record: `docs/decisions.md`, 2026-09-26 entry; issue `dermdunc/veil-proxy#86`.
