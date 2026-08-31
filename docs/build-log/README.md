# Build Log

A dated, deliberately written, build-in-public journal of how VeilGremlin gets built —
distinct from `docs/session-log.md`.

`docs/session-log.md` is the internal technical record: every session, every verify
command, every risk, written for whoever picks up this project next. It is complete on
purpose, and it reads like an engineering log because that's what it is.

This directory is different. Each entry is a short, human-readable story about one real
event in the build — a decision, a failure, a fix, a surprising result — written for a
reader who doesn't already have the context, not generated from the session log by
summarizing it mechanically. If an entry could have been produced by piping
`docs/decisions.md` through a formatter, it isn't doing its job.

Convention borrowed from the Hekton Workshop Gremlin's `docs/build-log/YYYY-MM-DD-*.md`
pattern (see `<hekton-machinery>/gremlins/workshop/workshop-gremlin.md`), scaled down: no Astro
site or Pages deploy for VeilGremlin yet, just the dated files, linked from `README.md`.
That can grow into a published site later if it earns one — see
`docs/next-actions.md`.

## Rules

1. **One entry per real event, not per session.** A quiet session that only ran tests
   doesn't need an entry. A session with a real decision, failure, or finding does —
   even if it also did five other quieter things.
2. **Write it like a person telling another person what happened.** Named files, dated
   `YYYY-MM-DD-<slug>.md`, a real title, a few paragraphs. Not a bullet-point changelog.
3. **The interesting part is the point.** A clean success is worth one line. A wrong
   assumption caught and fixed, a bug found in someone else's tool, a measurement that
   contradicted a guess — that's the actual story. Don't smooth those out to look tidier
   than they were.
4. **Link back to the technical record**, don't duplicate it. Point at the relevant
   `docs/decisions.md` section or PR for anyone who wants the full detail.
5. **No raw secrets, no unredacted internal paths that don't already appear in this
   public repo's own docs.** This repo is public; write accordingly. Nothing here should
   say more than `docs/decisions.md` already says publicly — it should just say it more
   readably.

## Entries

- [2026-06-30 — Scaffolding a privacy shield before it has any privacy logic](2026-06-30-scaffolding-a-privacy-shield.md)
- [2026-07-04 — Going public before there was anything to leak](2026-07-04-a-real-name-to-say-out-loud.md)
- [2026-07-14 — The workspace that almost built itself](2026-07-14-the-workspace-that-almost-built-itself.md)
- [2026-07-15 — Freezing the contract everyone else builds on](2026-07-15-freezing-the-contract-everyone-else-builds-on.md)
- [2026-07-15 — The detector that asked a question instead of writing code](2026-07-15-the-detector-that-asked-a-question-instead-of-writing-code.md)
- [2026-07-16 — Teaching the fan-out to test itself](2026-07-16-teaching-the-fan-out-to-test-itself.md)
- [2026-07-16 — The fix that was wrong, and how we found out](2026-07-16-the-fix-that-was-wrong-and-how-we-found-out.md)
- [2026-07-17 — A keying module built without a compiler in the room](2026-07-17-a-keying-module-built-without-a-compiler-in-the-room.md)
- [2026-07-17 — Three bugs a compiler would never have caught](2026-07-17-three-bugs-a-compiler-would-never-have-caught.md)
- [2026-07-17 — The vault that had to remember its counting](2026-07-17-the-vault-that-had-to-remember-its-counting.md)
- [2026-07-17 — An audit log sized to fit its lockfile](2026-07-17-an-audit-log-sized-to-fit-its-lockfile.md)
- [2026-07-17 — The policy format the sandbox chose](2026-07-17-the-policy-format-the-sandbox-chose.md)
- [2026-07-17 — Parsers that refuse to panic](2026-07-17-parsers-that-refuse-to-panic.md)
- [2026-07-18 — The seam that needed one more argument](2026-07-18-the-seam-that-needed-one-more-argument.md)
- [2026-07-25 — A proxy with nowhere to send anything yet](2026-07-25-a-proxy-with-nowhere-to-send-anything-yet.md)
- [2026-07-25 — The fix that broke what it was fixing](2026-07-25-the-fix-that-broke-what-it-was-fixing.md)
- [2026-08-23 — The fix that only moved the window](2026-08-23-the-fix-that-only-moved-the-window.md)
- [2026-08-24 — The comparison that gave the secret away](2026-08-24-the-comparison-that-gave-the-secret-away.md)
- [2026-08-24 — The warning nobody was in the room to hear](2026-08-24-the-warning-nobody-was-in-the-room-to-hear.md)
- [2026-08-24 — A name that looked like a secret](2026-08-24-a-name-that-looked-like-a-secret.md)
- [2026-08-29 — The same string, two different keys](2026-08-29-the-same-string-two-different-keys.md)
- [2026-08-30 — A guarantee the tests never tested](2026-08-30-a-guarantee-the-tests-never-tested.md)
- [2026-08-31 — The cast that always agreed](2026-08-31-the-cast-that-always-agreed.md)
- [2026-08-31 — The same gate, broken twice](2026-08-31-the-same-gate-broken-twice.md)
