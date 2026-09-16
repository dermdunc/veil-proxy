# The corpus that git clean ate

**Date:** 2026-09-16

The idea was small: build a hand-authored knowledge mirror of this repo's own decisions and
risks, gitignored, read by a separate tool (`scriptorium context`) to pull task-scoped context
into a session instead of always reading the same fixed list of docs. Fifteen records,
mirroring the ADRs and the three Critical-severity risks. Add the pattern to `.gitignore` next
to `AGENTS.md`/`CLAUDE.md`, which already lived there for the same reason — internal tooling,
not product. Validate it, run a real task against it, done.

The validation step returned an error: no `knowledge/` directory. It had existed fifteen
minutes earlier.

Nothing had gone wrong in any dramatic sense. Another piece of work was active on this same
checkout at the time — a different branch, its own commits landing normally — and somewhere in
that work, an ordinary `git clean -fd` ran. That command's whole job is to remove untracked
files a repo doesn't want lying around, and it does that job correctly. The catch is what
"doesn't want" means at that exact moment: the `.gitignore` pattern that was supposed to
protect `knowledge/` had only been merged into `main`. The branch actually checked out hadn't
merged it yet. So from git's point of view, on that branch, `knowledge/` wasn't ignored — it
was just an untracked directory sitting in the way, and `git clean` did exactly what it's
supposed to do to those.

`CLAUDE.md` and `AGENTS.md` survived the same sweep, sitting right next to the directory that
didn't. That's the detail that actually explains what happened: those two files had been
gitignored for months, long before today, so every branch's own `.gitignore` already knew
about them. The new pattern was newborn — correct on `main`, invisible everywhere else until
each branch caught up on its own schedule.

The fix wasn't to stop using `.gitignore`. It was to stop trusting it as the *only* guard for
something meant to survive on every branch, not just the one it happened to be added on.
`.git/info/exclude` does the same job as `.gitignore` for `git clean` and `git status`, but it
lives outside the tracked tree entirely — no merge required, no branch to catch up, just a line
in a file that's local to this one checkout and always in effect. The permanent fix landed in
the tracked `.gitignore` too, because every branch does eventually merge it and that's still
the right long-term answer. The local exclude is the belt under the suspenders — the thing
that's true immediately, on whichever branch happens to be checked out when someone runs a
command that removes untracked files for a living.

Rebuilding the fifteen records took a few minutes; nothing was actually lost, since the source
material it was drawn from was still sitting in `docs/decisions.md` and `docs/risks.md` right
where it always was. The interesting part was never the rebuild. It's that a tool meant to help
future sessions had, for about a quarter of an hour, no way to prove to itself that it still
existed — and the fix for that turned out to be smaller and more durable than the thing that
broke it.

Full technical detail: `docs/session-log.md`, 2026-09-16 entry.
