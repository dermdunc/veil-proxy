# The fix that only moved the window

The task sounded self-contained: turn a real actor identity into an opaque pseudonym before it
ever leaves the machine as telemetry. Keyed HMAC, a key from the OS keychain, done. The kind of
thing that looks like a single well-understood primitive from a distance.

The distance closed fast. The obvious plan — teach the existing `TryFrom<&AuditEvent> for
TelemetryEvent` conversion to accept a key — turned out to be structurally impossible. That
conversion's signature was frozen weeks earlier specifically so it could never silently drop a
future `AuditEvent` variant, and "frozen" means frozen: no key parameter, ever, no matter what
gets built elsewhere. So the actual deliverable wasn't "make the existing thing work," it was "build
a second, parallel front door" — `EdgeEvent::try_from_audit_event`, key in hand, living next to a
first door that will reject forever by design. Realizing that before writing any code, rather than
half a day into it, was the first real save of the session.

The second one showed up in review, and it's the more interesting story.

A first pass — same model, fresh context, told to find problems rather than confirm them — came
back with a real list: an env-var test seam that bypassed the OS keychain with no warning when
used, a key that crossed a crate boundary as a bare byte array instead of a guarded type, an actor
identity that got hashed exactly as typed with no normalization at all. All fixed. The env
override now warns loudly. The keychain loader wraps the key the moment it's produced instead of
handing back raw bytes. The hashing function trims and lowercases before it does anything else,
because the CLI argument that actually feeds this — `vg demask --actor <name>` — is free-typed by
a human with no validation upstream, and the same person typing `jane.doe` one day and `Jane.Doe`
the next has no business getting two different pseudonyms for it.

Then a second reviewer — a different model this time, given nothing but the fixed code and the
rules it had to satisfy — read all of that and pushed back on almost every one of it.

Not "you missed something." Closer to: "you fixed the symptom you could see and stopped." The key
now arrives wrapped, yes — but it gets *to* the wrapping point through the same hex-encode,
hex-decode helper functions as before, and neither of those had ever zeroized anything. The raw
bytes still sat in an ordinary, non-zeroizing `String` and `Vec<u8>` on the way there. Nothing
about "wrap it at the end" touched that. The actor-name fix trimmed and lowercased — and then
missed that `"jane doe"` and `"jane  doe"`, two spaces instead of one, still hashed to different
people, because nobody had collapsed internal whitespace, only the edges. And the env-var
warning — the fix that felt the most obviously complete of the three — turned out to only address
*silence*. It never touched the actual failure mode underneath: if that same environment value
ever ended up set on two different machines, by a shared config file or a copied `.env`, both
machines would mint the identical "per-device, no-correlation" key. The whole point of building a
per-device secret is that it doesn't do that. A louder warning doesn't change what happens when
someone doesn't read it.

None of these were made up to sound thorough. Zeroizing was cheap and got fixed in the same pass —
the workspace already depends on the `zeroize` crate elsewhere, so wrapping the hex intermediates
in `Zeroizing` was a few lines. Internal whitespace was the same fix already halfway written,
just applied to the whole string instead of the ends. The cross-device env-var risk was not fixed,
because there wasn't a real fix available — the seam has to live where it lives for downstream
crates' tests to reach it at all, the same structural constraint an earlier, already-accepted seam
in this codebase lives with. What changed there was honesty: the code now says, in the one place
someone would look, exactly what breaks and why, instead of implying "warned about" means "safe."

One more thing the second reviewer caught, almost in passing: a doc comment claiming a known race
condition was "tracked as a follow-up in `docs/next-actions.md`." It wasn't. Nobody had actually
added it. Writing that a thing is tracked is not the same action as tracking it, and it took an
adversarial second reader with no attachment to the first draft's good intentions to notice the
gap between the two.

Two High-severity findings stand in `docs/decisions.md` right now, named, not buried: the
cross-device env-var risk, and a key type whose "only the keychain loader should construct this"
guarantee is a convention, not something the compiler enforces. Both real. Neither fixed. The
alternative to writing them down plainly was writing something reassuring instead, and this
project has been burned by that trade before.
