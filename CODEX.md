# CODEX.md — Veil Proxy (VeilGremlin family)

## Project Classification

- **Type:** factory-output
- **Name:** veil-proxy
- **Product family:** VeilGremlin — this repo is the masking data plane
- **Local repo:** <repo>
- **Vault control plane:** <vault>/20-projects/factory-output/veil-proxy
- **Lifecycle stage:** active
- **Promotion target:** none
- **Privacy boundary:** public
- **Owner:** dermdunc

## Codex Rules

Follow all rules in `~/hekton/CODEX.md` — including the **Hekton Repository Taxonomy**, **Hekton Documentation Contract**, and **Ongoing Hekton Project Operating Rules** sections.

Before coding:
1. Read `.hekton/project.yaml` to confirm classification and paths
2. Read `docs/project-walkthrough.md` for plain-English project context
3. Read `docs/session-log.md` for recent session history
4. Read `docs/decisions.md` for prior decisions that constrain this work
5. Read `docs/next-actions.md` for the current work queue
6. Do not add a `hekton-` prefix to files unless this is a platform repo
7. Do not commit vault paths or local filesystem paths to git
8. Add a `docs/build-log/YYYY-MM-DD-<slug>.md` entry for a session with a real event worth
   telling (a decision, a failure, a fix, a surprising result) — see `docs/build-log/README.md`.
   Distinct from `docs/session-log.md`: a readable narrative for a reader without context, not
   a summary of the technical log. Not every session needs one.

At end of session, output: changed files, decisions, assumptions, risks, next actions, validation status, vault updated (yes/no).
