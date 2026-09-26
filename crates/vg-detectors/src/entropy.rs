//! Shannon-entropy detector for high-entropy tokens (API keys, tokens, random secrets)
//! that have no stable format a regex could describe — unlike email/phone/IP/IBAN,
//! secrets vary per provider with no shared shape, so this detector flags *any*
//! sufficiently long, sufficiently random-looking token instead of matching a pattern.
//!
//! **Judgment call (recorded in `docs/decisions.md`):** entropy alone can't distinguish
//! an API key from a password from a generic secret — all it sees is "a long random
//! string" — so every finding is tagged the generic `EntityType::Secret` rather than
//! guessing `ApiKey` from a token shape this detector has no basis to assert.

use vg_core::{Detector, DetectorId, EntityType, Finding, Span};

const ENTITY_TYPES: [EntityType; 1] = [EntityType::Secret];

/// Default minimum token length (bytes) before entropy is even considered. Short
/// strings hit their alphabet's max entropy trivially (e.g. a 4-character token can't
/// exceed 2 bits/char), so a length floor is what actually keeps this detector from
/// flagging short identifiers.
const DEFAULT_MIN_LENGTH: usize = 20;

/// Default Shannon-entropy threshold, in bits per character. Sits between hex-encoded
/// secrets (~4 bits/char) and base64-encoded ones (~6 bits/char, capped by their
/// 64-symbol alphabet), in the same ballpark as common secret-scanner heuristics (e.g.
/// detect-secrets' generic high-entropy-string plugin).
const DEFAULT_THRESHOLD: f64 = 3.5;

/// Bytes treated as part of a token rather than a delimiter: ASCII alphanumerics plus
/// the punctuation that commonly appears *inside* API keys/tokens (base64url and
/// common key-encoding alphabets use these); everything else (whitespace, quotes,
/// commas, etc.) splits tokens apart.
///
/// **Codex cross-model doubt-pass finding (2026-07-15):** `!@#$%^&*` added after the
/// review found that a generated password like `aB3!xY7@qR2#nM8$pL5%zK` (well above the
/// entropy threshold as a whole) was being split at every one of those bytes into
/// sub-20-byte fragments, each individually rejected by `min_length` -- a systematic
/// miss of an entire realistic secret shape, not a hypothetical one, for the one
/// detector whose whole job is catching secrets with no fixed format. Deliberately NOT
/// adding `:`/`;`/`(`/`)` even though they also appear in some compound secrets
/// (`user:token`): those are far more common as genuine field/prose delimiters in logs,
/// timestamps, and URLs, and including them risks merging unrelated adjacent tokens into
/// spurious high-entropy strings (e.g. an ISO timestamp's own digit runs). That
/// narrower gap is accepted as a documented residual, not fixed here — see
/// docs/decisions.md.
///
/// **Round-2 verification pass found two more residuals from including `@`, both
/// accepted, neither fixed:** (1) `@` makes an ordinary email (`jane.doe@example.com`,
/// 20 bytes, ~3.5 bits/byte) sit right at the entropy threshold, so plain emails can
/// ALSO get tagged `Secret` alongside `EmailDetector`'s own, more specific `Email`
/// finding for the same span -- a precision cost (over-flagging), not a leak; downstream
/// can prefer the more specific classification. (2) `@` can merge a real secret with a
/// long low-entropy suffix (e.g. Basic-Auth-in-URL style `<secret>@internal.example.com`)
/// and dilute the merged token's entropy below threshold, a genuine false-negative shape
/// that removing `@` would not fix either (it would just reopen the original password
/// gap this fix closed). Also pre-existing, not introduced by this fix: `=` is a token
/// byte, so a long low-entropy key name merged with `=<secret>` can similarly dilute
/// below threshold. All three are accepted: this is a coarse byte-classification
/// heuristic by design, not a context-aware tokenizer, and each further tweak trades one
/// realistic shape for another rather than strictly improving coverage.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'+' | b'/'
                | b'='
                | b'-'
                | b'_'
                | b'.'
                | b'!'
                | b'@'
                | b'#'
                | b'$'
                | b'%'
                | b'^'
                | b'&'
                | b'*'
        )
}

/// Excludes tokens that decompose entirely into word-like or short-numeric segments
/// when split on structural delimiters (`/`, `.`, `_`, `-`) -- covers file paths
/// (`scripts/gateway-run.sh`), snake_case/kebab-case identifiers
/// (`requires_confirmation`, `local-coding-harness`), and structured operational IDs
/// (`run-20260608-EG-012`) uniformly, rather than an unstructured secret.
///
/// **2026-07-16 census finding, corrected after measurement:** an initial version of
/// this exclusion assumed structured internal run IDs were the dominant
/// false-positive shape. Measuring the *actual* matched tokens (via a temporary local
/// debug print against real internal-tooling content, never committed) showed that
/// assumption was wrong: on that specific fixed content, the fix only removed 1 of 1849
/// entropy findings. The real dominant classes were file paths and
/// snake_case/kebab-case code identifiers -- `is_token_byte` treats `/`, `.`, and `_` as
/// part of a token (not a delimiter), so a whole path or identifier is scored for
/// entropy as one blob, and the resulting mix of letters/case/punctuation clears the
/// threshold even though every piece is an ordinary word. This version fixes that:
/// splitting on the token's own internal delimiters and requiring every resulting piece
/// to be purely alphabetic (any length -- these are word-like labels, not random blobs)
/// or purely numeric (<=8 digits -- dates/ordinals) catches paths and identifiers
/// generically, not via a Hekton-specific dictionary.
///
/// **Accepted residual, not fixed:** a real secret that happens to be a
/// dictionary-word passphrase joined by delimiters (e.g. `correct-horse-battery-staple`)
/// would also be excluded by this rule -- indistinguishable from a real identifier
/// without a dictionary/semantic check this detector doesn't have. A secret whose
/// segments mix letters and digits (the vast majority of real base64/hex/API-key
/// shapes) is unaffected, since a mixed segment is neither purely alphabetic nor purely
/// numeric and fails this exclusion.
/// **`=` handling redesigned (2026-07-22 doubt-pass fix, closing a Critical finding from
/// both a single-model and a Codex cross-model review).** The 2026-07-21 version simply
/// added `=` to the split set alongside `/`, `.`, `_`, `-` -- but that let a `KEY=value`
/// token pass whenever its VALUE was a single run of letters with no further delimiter,
/// even a genuinely high-entropy one: `TOKEN=zQvLmXpRwTuYbNdKfJhCsEoAiPlMnQr` (bare,
/// alphabetic, no internal structure) was being silently excluded -- a real
/// false-negative regression, not the intended fix. **Fix:** `=` is handled as its own,
/// narrower case: the whole token must independently fail the ordinary structured check
/// first; only then is a `KEY=VALUE` split considered, and even then the VALUE half must
/// ITSELF re-decompose into >=2 further segments via `is_structured_segments` (the same
/// rule applied to everything else) -- so `LICENSE_KEY=ACME-2026-DEMO-KEY` still excludes
/// (value `ACME-2026-DEMO-KEY` has 4 further segments), but a bare single-run value like
/// `xKrTqYbWmZjLpNsFhDvGc` does not (no further segments, `segments.len() < 2` in
/// `is_structured_segments`, same guard that already protects the general case).
///
/// **Round-2 doubt-pass finding: the key side needed a bound too.** The key was
/// originally left unchecked on the theory that it's "almost always a benign identifier
/// in practice" -- but that's an assumption, not a guarantee, and the shape is
/// symmetric: `zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi=run-2026-01-01` has the real secret on
/// the KEY side and a benign-looking VALUE side, and a value-only check would have
/// waved it through.
///
/// **Round-3 doubt-pass finding, closed: the round-2 length-cap fix was itself
/// insufficient.** A flat `key.len() <= 24` bound still let a realistic 20-24 byte
/// high-entropy secret through as a "key" -- `aB3dE5fG7hI9jK1lM2nP=run-2026-01-01` (a
/// 20-byte key, right at `DEFAULT_MIN_LENGTH`) passed the cap while looking nothing like
/// a real identifier. Length alone cannot distinguish a secret from a name. **Fix:**
/// require the KEY to independently satisfy `is_structured_segments` too -- the exact
/// same rule already applied to the value and to everything else in this file, not a new
/// one. `LICENSE_KEY`/`API_KEY`/`AWS_SECRET_ACCESS_KEY` all decompose into >=2
/// word-like segments and pass; a bare high-entropy run like
/// `aB3dE5fG7hI9jK1lM2nP` or `zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi` has no internal
/// delimiter, is exactly 1 segment, and fails. **Accepted precision cost, not a leak
/// risk:** a single-word key with no delimiter (`TOKEN=<benign-structured-value>`,
/// `KEY=<benign-structured-value>`) no longer qualifies for this exclusion either, since
/// the key alone doesn't decompose -- over-masking in that narrow case, not under-masking.
///
/// **Round-4 doubt-pass finding: "by construction" above overclaimed.** This closes the
/// *zero-delimiter* shape, not every shape. A secret with exactly ONE incidental
/// delimiter landing precisely on a letter/digit type boundary still passes both this
/// check and `is_structured_segments` directly (the same function guards the whole-token
/// path too) -- `AbCdEfGhIjKlMnOp-12345678` (16 mixed-case letters + `-` + 8 digits,
/// entropy 4.64 bits/byte) decomposes into one purely-alphabetic and one purely-numeric
/// segment and is excluded, on either side of `=` or as a bare token. This is not a new
/// gap this round introduced -- it is the SAME already-documented residual above
/// ("Accepted residual, not fixed" on `is_structured_segments`, the dictionary-word-
/// passphrase case) restated with a sharper example: `is_structured_segments` checks
/// character CLASS per segment, never whether a segment plausibly reads as a real word,
/// so any letters-only-then-digits-only (or vice versa) split defeats it regardless of
/// how the letters are cased. Fixing this would mean adding real word-likelihood
/// detection (e.g. rejecting per-letter-random case-switching, which no real identifier
/// exhibits) -- a meaningfully bigger, riskier change than anything else in this file's
/// history of narrow, targeted fixes, and out of scope for a detector that is
/// deliberately not a dictionary/semantic checker. Accepted and named, not fixed.
fn is_structured_identifier(token: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(token) else {
        return false;
    };
    if is_structured_segments(s) {
        return true;
    }
    if let Some((key, value)) = s.split_once('=') {
        if !key.is_empty()
            && !value.is_empty()
            && is_structured_segments(key)
            && is_structured_segments(value)
        {
            return true;
        }
    }
    false
}

/// Excludes a string that decomposes entirely into word-like or short-numeric segments
/// when split on structural delimiters (`/`, `.`, `_`, `-`) -- covers file paths
/// (`scripts/gateway-run.sh`), snake_case/kebab-case identifiers
/// (`requires_confirmation`, `local-coding-harness`), and structured operational IDs
/// (`run-20260608-EG-012`) uniformly, rather than an unstructured secret.
///
/// **2026-07-16 census finding, corrected after measurement:** an initial version of
/// this exclusion assumed structured internal run IDs were the dominant
/// false-positive shape. Measuring the *actual* matched tokens (via a temporary local
/// debug print against real internal-tooling content, never committed) showed that
/// assumption was wrong: on that specific fixed content, the fix only removed 1 of 1849
/// entropy findings. The real dominant classes were file paths and
/// snake_case/kebab-case code identifiers -- `is_token_byte` treats `/`, `.`, and `_` as
/// part of a token (not a delimiter), so a whole path or identifier is scored for
/// entropy as one blob, and the resulting mix of letters/case/punctuation clears the
/// threshold even though every piece is an ordinary word. This version fixes that:
/// splitting on the token's own internal delimiters and requiring every resulting piece
/// to be purely alphabetic (any length -- these are word-like labels, not random blobs)
/// or purely numeric (<=8 digits -- dates/ordinals) catches paths and identifiers
/// generically, not via a Hekton-specific dictionary.
///
/// **Accepted residual, not fixed:** a real secret that happens to be a
/// dictionary-word passphrase joined by delimiters (e.g. `correct-horse-battery-staple`)
/// would also be excluded by this rule -- indistinguishable from a real identifier
/// without a dictionary/semantic check this detector doesn't have. A secret whose
/// segments mix letters and digits (the vast majority of real base64/hex/API-key
/// shapes) is unaffected, since a mixed segment is neither purely alphabetic nor purely
/// numeric and fails this exclusion.
///
/// **Path mode (veil-proxy#86 finding 3, 2026-09-26).** A real Claude Code session sends its
/// working directory and file paths in every request, and the rule above flagged any path with
/// one mixed letter/digit segment (`phase-1a`, `run3`, `v2`, `abc123`, `@types`). Every `Secret`
/// hit is an irreversible redaction, so the agent saw `[REDACTED:SECRET]/billing/invoice.py`,
/// built tool calls from it, and failed. Measured before this fix: paths made only of letters
/// (`/Users/alice/Development/acme-billing`) were already excluded; the mixed segment was the
/// real trigger. So a token containing `/` gets two relaxations: an npm-scope `@` at the start of
/// a `/` component is stripped (`@types`), and a short lowercase letter/digit segment of at
/// most [`MAX_SHORT_MIXED_SEGMENT`] bytes is allowed ([`is_short_mixed`]). Guards, each added
/// for a concrete counterexample: at most one such segment per `/` component (grouped keys put
/// several in one); no uppercase in it (short random credentials mix case); at least one real
/// word segment (letters only, >=3 bytes); at most two such segments totalling at most 8
/// bytes in the whole token, with no digit-only segment longer than 4 bytes beside them (a
/// round-2 review showed a per-component limit alone let `/`-separated key groups through);
/// every letters-only segment word-cased
/// ([`is_word_cased`], which keeps AWS-style `wJalrXUtnFEMI/K7MDENG/...` flagged). `@` anywhere
/// else is not a split character, so URL userinfo (`postgres://app:Xk9mQ2vL@db.internal/prod`)
/// stays one failing segment and is still flagged. The first version of this fix split on every
/// `@` and allowed any number of mixed-case segments; a fresh-context adversarial review showed
/// it stopped flagging database URLs, share/reset links and grouped keys, all flagged on `main`.
/// Tokens without `/` are unchanged.
///
/// **Accepted residuals of path mode:** a single lowercase letter/digit token of <=8 bytes as its
/// own path component next to word components is excluded (`https://app.example.com/reset/hq7vk2mx`,
/// or a webhook path like `hooks/catch/1234/abc1xyz`);
/// a long random path segment (macOS `$TMPDIR`'s `/var/folders/xx/<random>/T/`) is still
/// flagged, the right call for a component indistinguishable from a token. Measured separately
/// and pre-existing, not introduced here: about 2.6% of random 20-byte base64 strings containing
/// `/` are excluded by the letters-only rule above.
fn is_structured_segments(s: &str) -> bool {
    let path_mode = s.contains('/');
    // Empty segments (a leading/trailing delimiter, e.g. the dotfile in
    // `.hekton/risk-register.yaml`, or a doubled delimiter) are common and not
    // themselves suspicious -- filtered out rather than treated as disqualifying.
    let mut segment_count = 0;
    let mut has_word = false;
    let mut all_words_cased = true;
    let mut short_mixed_count = 0;
    let mut short_mixed_bytes = 0;
    let mut longest_digit_run = 0;
    for component in s.split('/').filter(|c| !c.is_empty()) {
        // An npm scope (`@types`) is the one place `@` is structural. Anywhere else it is left
        // in the segment, which then fails, so `pass@host` userinfo is never split apart.
        let component = if path_mode {
            component.strip_prefix('@').unwrap_or(component)
        } else {
            component
        };
        let mut short_mixed_here = 0;
        for seg in component
            .split(['.', '_', '-'])
            .filter(|seg| !seg.is_empty())
        {
            segment_count += 1;
            let bytes = seg.as_bytes();
            if bytes.iter().all(|b| b.is_ascii_alphabetic()) {
                has_word |= bytes.len() >= 3;
                all_words_cased &= is_word_cased(bytes);
            } else if bytes.iter().all(|b| b.is_ascii_digit()) {
                if bytes.len() > 8 {
                    return false;
                }
                longest_digit_run = longest_digit_run.max(bytes.len());
            } else if path_mode && is_short_mixed(bytes) {
                short_mixed_here += 1;
                short_mixed_count += 1;
                short_mixed_bytes += bytes.len();
            } else {
                return false;
            }
        }
        // Grouped keys (`a8f3k2m9-x7q4w1z6-...`, `VK7JG-NPHTM-...`) put several mixed groups in
        // one component; real path components (`phase-1a`, `abc123`, `v2`) carry at most one.
        if short_mixed_here > 1 {
            return false;
        }
    }
    if segment_count < 2 {
        return false;
    }
    if short_mixed_count == 0 {
        return true;
    }
    // Whole-token budget (round-2 review finding): a per-component limit alone let `/`-separated
    // groups through (`/share/k3j9x2q8/p5r8t3v2/n6b9c4d7`, `/v1/keys/9f86d081/884c7d65/...`).
    // Real paths need at most two short mixed pieces totalling a few bytes (`phase-1a/run3`),
    // and don't pair them with long digit runs (`reset/a8f3k2m9-12345678-87654321`).
    has_word
        && all_words_cased
        && short_mixed_count <= MAX_SHORT_MIXED_PER_TOKEN
        && short_mixed_bytes <= MAX_SHORT_MIXED_BYTES_PER_TOKEN
        && longest_digit_run <= MAX_DIGIT_RUN_BESIDE_SHORT_MIXED
}

/// Path-mode whole-token budget (see [`is_structured_segments`]).
const MAX_SHORT_MIXED_PER_TOKEN: usize = 2;
const MAX_SHORT_MIXED_BYTES_PER_TOKEN: usize = 8;
const MAX_DIGIT_RUN_BESIDE_SHORT_MIXED: usize = 4;

/// A path-mode "short mixed" segment: letters and digits, at most [`MAX_SHORT_MIXED_SEGMENT`]
/// bytes, and **no uppercase**. Real path pieces with digits are lowercase (`1a`, `run3`, `v2`,
/// `abc123`, `py3`); random short credentials mix case (`Xk9mQ2vL`, `aB3dE5fG`).
fn is_short_mixed(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_SHORT_MIXED_SEGMENT
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Whether a letters-only segment is cased the way a real path word is: `lower`, `UPPER`, or
/// `Capitalized`. Random base64 letter runs almost never are (`wJalrXUtnFEMI`), which is what
/// keeps AWS-style keys with a `/` in them (`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) flagged
/// under path mode. Only consulted when a short mixed segment needs the path-mode allowance;
/// camelCase words still pass the plain rule on their own.
fn is_word_cased(bytes: &[u8]) -> bool {
    let rest_lower = bytes[1..].iter().all(u8::is_ascii_lowercase);
    rest_lower || bytes.iter().all(u8::is_ascii_uppercase)
}

/// Longest mixed letter/digit segment path mode allows (see [`is_structured_segments`]).
const MAX_SHORT_MIXED_SEGMENT: usize = 8;

/// Case-insensitive markers that, immediately before a hex-shaped token (skipping a
/// single separator like `:`/whitespace), corroborate "this is a git object hash", not a
/// secret. **`hash` removed (2026-07-22 doubt-pass fix):** too generic -- it matches as
/// the tail of extremely common compound identifiers that hold real sensitive values
/// (`password_hash:`, `file_hash:`, `content_hash:`), since the backward word-scan stops
/// at the underscore and captures only `hash`. `commit`/`sha`/`sha1`/`sha256`/`rev` are
/// much more specifically git-related and were not shown to have the same problem.
const GIT_SHA_CONTEXT_WORDS: [&[u8]; 5] = [b"commit", b"sha1", b"sha256", b"sha", b"rev"];

/// Whether the word immediately preceding `start` in `buf` (after skipping ordinary
/// separator bytes: space, tab, `:`) case-insensitively matches a git-SHA context marker.
///
/// **`=` removed from the skipped separators (2026-07-22 doubt-pass fix, Codex finding).**
/// `=` is a token byte (`is_token_byte`), so the entropy detector's own tokenizer never
/// splits `commit=<hex>` into two tokens in the first place -- `start` never points at
/// just the hex portion, so a `=`-skip here was unreachable dead code, not a working
/// feature. **Accepted scope limit, named rather than silently broken:** `commit=<sha>`
/// is not excluded via this path (`:`/whitespace-separated forms like `commit: <sha>` and
/// `commit <sha>` work correctly, since those separators are not token bytes). A
/// `commit=<sha>` value falls through to ordinary entropy scoring instead, where the
/// low-entropy `commit=` prefix diluting the merged token below threshold is a
/// pre-existing, already-documented residual of `is_token_byte` treating `=` as part of a
/// token (see the module-level doc comment above), not a new risk introduced here.
fn preceded_by_git_sha_context(buf: &[u8], start: usize) -> bool {
    let mut i = start;
    while i > 0 && matches!(buf[i - 1], b' ' | b'\t' | b':') {
        i -= 1;
    }
    let word_end = i;
    while i > 0 && buf[i - 1].is_ascii_alphanumeric() {
        i -= 1;
    }
    let word = &buf[i..word_end];
    GIT_SHA_CONTEXT_WORDS
        .iter()
        .any(|w| word.eq_ignore_ascii_case(w))
}

/// Excludes a token from `Secret` classification when it is shaped like a git object
/// hash (7-64 lowercase hex characters -- covers abbreviated and full SHA-1/SHA-256
/// object IDs) **and** is immediately preceded by a git-hash context word (`commit`,
/// `sha`, `sha1`, `sha256`, `rev`). Deliberately narrow on both axes, not a blanket
/// hex-shape carve-out (2026-07-21, closing the T10 residual FP: `docs/decisions.md`,
/// benign-slice entropy finding = 1, a commit SHA):
///
/// - **Length + charset alone is not enough.** Many real secrets (session tokens, some
///   API keys) are themselves lowercase hex of a length that would collide with a SHA;
///   excluding every such token regardless of context would reopen a false-negative hole
///   this detector exists to avoid -- worse than the false positive being fixed.
/// - **Context alone is not enough either.** A token that merely follows the word
///   "commit" but isn't hex-shaped (e.g. a non-hex build identifier) is left to the
///   normal entropy/structured-identifier logic, unaffected by this exclusion.
/// - **Accepted residual:** a real secret that is coincidentally pure lowercase hex AND
///   immediately preceded by one of these context words (e.g. `commit token: <hex
///   secret>`) would be missed. Narrow and named, not fixed here -- the same posture
///   this file already takes with its other documented residuals.
fn looks_like_git_sha(buf: &[u8], start: usize, token: &[u8]) -> bool {
    let len = token.len();
    if !(7..=64).contains(&len) {
        return false;
    }
    if !token
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    preceded_by_git_sha_context(buf, start)
}

fn shannon_entropy_bits_per_byte(token: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in token {
        counts[b as usize] += 1;
    }
    let len = token.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum()
}

/// Maps how far `entropy` sits above `threshold` onto a `0.5..=0.95` confidence range:
/// right at the threshold is a coin flip (0.5), and 2+ bits/char above it is treated as
/// as confident as this detector gets (0.95) — entropy is a continuous heuristic, so a
/// step function at the threshold would discard information the detector actually has.
fn confidence_for(entropy: f64, threshold: f64) -> f32 {
    let scaled = 0.5 + (entropy - threshold) / 2.0 * 0.45;
    scaled.clamp(0.5, 0.95) as f32
}

/// Tunable Shannon-entropy detector: flags whitespace/punctuation-delimited tokens at
/// least `min_length` bytes long whose Shannon entropy meets or exceeds `threshold`
/// bits per byte.
#[derive(Debug, Clone, Copy)]
pub struct EntropyDetector {
    pub min_length: usize,
    pub threshold: f64,
}

impl EntropyDetector {
    pub fn new(min_length: usize, threshold: f64) -> Self {
        Self {
            min_length,
            threshold,
        }
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new(DEFAULT_MIN_LENGTH, DEFAULT_THRESHOLD)
    }
}

impl Detector for EntropyDetector {
    fn id(&self) -> DetectorId {
        DetectorId("entropy".to_string())
    }

    fn detect(&self, buf: &[u8], _spans: &[Span]) -> Vec<Finding> {
        let detector_id = self.id();
        let mut findings = Vec::new();
        let mut idx = 0;
        while idx < buf.len() {
            if !is_token_byte(buf[idx]) {
                idx += 1;
                continue;
            }
            let start = idx;
            while idx < buf.len() && is_token_byte(buf[idx]) {
                idx += 1;
            }
            let token = &buf[start..idx];
            if token.len() < self.min_length {
                continue;
            }
            if is_structured_identifier(token) {
                continue;
            }
            if looks_like_git_sha(buf, start, token) {
                continue;
            }
            let entropy = shannon_entropy_bits_per_byte(token);
            if entropy >= self.threshold {
                findings.push(Finding {
                    entity_type: EntityType::Secret,
                    span: Span {
                        start,
                        end: idx,
                        node_kind: None,
                    },
                    confidence: confidence_for(entropy, self.threshold),
                    detector: detector_id.clone(),
                });
            }
        }
        findings
    }

    fn entity_types(&self) -> &[EntityType] {
        &ENTITY_TYPES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vg_core::conformance::assert_detector_contract;

    #[test]
    fn flags_a_long_random_looking_token() {
        let buf = b"export API_KEY=zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi";
        let findings = EntropyDetector::default().detect(buf, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, EntityType::Secret);
    }

    #[test]
    fn flags_a_password_containing_common_special_characters() {
        // Codex cross-model doubt-pass finding (2026-07-15): before is_token_byte
        // included !@#$%^&*, this password was split at every special character into
        // sub-20-byte fragments, each missed individually -- a whole class of realistic
        // secrets invisible to the one detector meant to catch unshaped ones.
        let buf = b"PASSWORD=aB3!xY7@qR2#nM8$pL5%zK^wQ9&";
        let findings = EntropyDetector::default().detect(buf, &[]);
        assert_eq!(
            findings.len(),
            1,
            "expected one merged high-entropy token, got {findings:?}"
        );
        assert_eq!(findings[0].entity_type, EntityType::Secret);
    }

    #[test]
    fn ignores_structured_identifiers_even_at_a_lenient_threshold() {
        // Lenient params so this test proves the shape-exclusion fires, independent of
        // whether the default 3.5 threshold happens to catch these particular tokens.
        // These are the real dominant false-positive shapes found by the 2026-07-16
        // census against real internal-tooling content (file paths and
        // snake_case/kebab-case identifiers), not the structured-run-ID shape an earlier,
        // measurement-corrected version of this exclusion assumed was dominant.
        let lenient = EntropyDetector::new(10, 0.5);
        for id in [
            "run-20260608-EG-012",
            "RISK-0017-EG-001",
            "scripts/gateway-run.sh",
            "docs/api-contract.md",
            ".hekton/risk-register.yaml",
            "requires_confirmation",
            "confirm_cloud_egress_or_abort",
            "local-coding-harness",
        ] {
            assert!(
                lenient.detect(id.as_bytes(), &[]).is_empty(),
                "expected {id} to be excluded as a structured identifier"
            );
        }
    }

    #[test]
    fn still_flags_a_real_secret_shaped_with_delimiters_at_a_lenient_threshold() {
        // Same lenient params, but each segment mixes letters and digits (a UUID's hex
        // groups), so no segment is purely alphabetic or purely numeric -- the
        // exclusion must not swallow it.
        let lenient = EntropyDetector::new(10, 0.5);
        let uuid_like = "550e8400-e29b-41d4-a716-446655440000";
        assert!(!lenient.detect(uuid_like.as_bytes(), &[]).is_empty());
    }

    /// veil-proxy#86 finding 3: paths a real Claude Code session sends in every request. Each
    /// was redacted irreversibly before the path-mode fix (the mixed segment was the trigger),
    /// breaking every tool call built from it. The first three were already excluded; kept as
    /// the issue's own reported cases.
    #[test]
    fn ignores_ordinary_paths_with_short_mixed_segments() {
        let detector = EntropyDetector::default();
        for path in [
            "/Users/alice/Development/acme-billing",
            "/Users/alice/acme-billing/billing/invoice.py",
            "test_invoice.InvoiceTests.test_invoice_total_includes_vat",
            "/Users/alice/Development/acme/demo-site/spikes/phase-1a/fixture",
            "/private/tmp/phase-1a/run3/acme-billing",
            "/private/var/folders/xy/abc123/T/tmp.XXXX",
            "/Users/alice/src/acme-billing2",
            "/Users/alice/Development/acme-billing/v2/src",
            "node_modules/@types/node/index.d.ts",
            "crates/vg-proxy/src/codec/anthropic/stream_demask.rs",
        ] {
            let findings = detector.detect(path.as_bytes(), &[]);
            assert!(
                findings.is_empty(),
                "{path} must not be flagged: {findings:?}"
            );
            let in_prose = format!("Working directory: {path}\n");
            assert!(
                detector.detect(in_prose.as_bytes(), &[]).is_empty(),
                "{path} in prose must not be flagged"
            );
        }
    }

    /// The other side of finding 3's fix: secrets that must still flag, including ones that
    /// contain `/` or short mixed groups.
    #[test]
    fn path_mode_still_flags_real_secrets() {
        let detector = EntropyDetector::default();
        for secret in [
            "whsec_9fK2xQ7mZ4pL8vR1tY6nB3cH5jD0gWq",
            // 40-char standard base64 with `/` and `+`.
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aB3/dE5fG7hI9jK1lM2nP+qR4sT6uV8wX0yZ/abc",
            "sk-ant-api03-Zx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We",
            "aB3!xY7@qR2#nM8$pL5%zK",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            // Grouped key with no `/`: path mode doesn't apply.
            "VK7JG-NPHTM-C97JM-9MPGT-3V66T",
            // Found by the fresh-context adversarial review of the first path-mode version:
            // URL userinfo, share/reset links, and grouped keys once a `/` appears.
            "postgres://app:Xk9mQ2vL@db.internal/prod",
            "postgres://app:zQvLmXpRwTuYbNdKfJhC@db.example.com/prod",
            "redis://:hQ7vK2mX@cache.internal/0",
            "https://deploy:Tq8Zr3Wk@git.example.com/org/repo.git",
            "keys/VK7JG-NPHTM-C97JM-9MPGT-3V66T",
            "/share/3kF9x2Q-7mZ4pL8v-R1tY6nB3",
            "https://example.com/invite/aB3dE5fG-hI9jK1lM-2nP4qR6s",
            "https://app.example.com/reset/Zk3P9q-Xm7L2w-Rt6Y1v-Bn8F4s",
            "recovery/a8f3k2m9-x7q4w1z6-p5r8t3v2-n6b9c4d7",
            // Round-2 review: `/`-separated groups, digit runs beside a mixed piece, and the
            // same inside a `KEY=value`.
            "/v1/keys/9f86d081/884c7d65/9a2feaa0/8fb4ab5c",
            "tokens/a8f3k2m9/x7q4w1z6/p5r8t3v2/n6b9c4d7",
            "/share/k3j9x2q8/p5r8t3v2/n6b9c4d7",
            "https://example.com/s/k3j9x2q8/p5r8t3v2",
            "codes/2fa/a8f3k2m9/x7q4w1z6",
            "reset/a8f3k2m9-12345678-87654321",
            "backup/a8f3k2m9_12345678/x7q4w1z6_87654321",
            "api_key=reset/k3j9x2q8/x7q4w1z6",
            "AWS_SECRET=keys/a8f3k2m9/x7q4w1z6/p5r8",
            // A random `$TMPDIR` component stays flagged (named residual).
            "/var/folders/7k/q1x2y3z4000gn/T/tmp.aB3dE5fG",
        ] {
            assert!(
                !detector.detect(secret.as_bytes(), &[]).is_empty(),
                "{secret} must still be flagged"
            );
        }
    }

    #[test]
    fn ignores_a_low_entropy_repeated_token() {
        let buf = b"filler aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa end";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn ignores_short_high_entropy_tokens_below_min_length() {
        // High entropy but far below the default 20-byte floor.
        assert!(EntropyDetector::default()
            .detect(b"id aB3!9k", &[])
            .is_empty());
    }

    #[test]
    fn ignores_ordinary_english_prose() {
        let buf = b"the quick brown fox jumps over the lazy dog repeatedly";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn a_lower_threshold_flags_tokens_the_default_would_miss() {
        // 20 bytes alternating 'a'/'b': Shannon entropy is exactly 1.0 bit/byte (two
        // equally likely symbols) -- below the default 3.5 threshold, but above a
        // deliberately lenient one.
        let buf = b"token abababababababababababababababab end";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
        let lenient = EntropyDetector::new(10, 0.9);
        assert_eq!(lenient.detect(buf, &[]).len(), 1);
    }

    #[test]
    fn confidence_stays_within_bounds() {
        let buf = b"export API_KEY=zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi";
        for finding in EntropyDetector::default().detect(buf, &[]) {
            assert!((0.0..=1.0).contains(&finding.confidence));
        }
    }

    #[test]
    fn satisfies_the_detector_contract() {
        let buf = b"export API_KEY=zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi and plain text";
        assert_detector_contract(&EntropyDetector::default(), buf, &[]);
    }

    #[test]
    fn ignores_a_license_key_shaped_env_assignment() {
        // A second T10 residual (docs/decisions.md, 2026-07-21), surfaced only after the
        // commit-SHA fix: `=` wasn't a split delimiter, so this whole assignment scored as
        // one entropy blob even though both sides are word/numeric-shaped.
        let buf = b"LICENSE_KEY=ACME-2026-DEMO-KEY";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn still_flags_a_real_secret_after_an_equals_sign() {
        // Same `KEY=value` shape, but the value mixes letters and digits -- must not be
        // swallowed by the `=` split added for the LICENSE_KEY case above.
        let buf = b"API_KEY=zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi";
        assert_eq!(EntropyDetector::default().detect(buf, &[]).len(), 1);
    }

    #[test]
    fn still_flags_a_secret_on_the_key_side_of_an_equals_sign() {
        // Round-2 doubt-pass finding: the `=` fix only checked the VALUE side, so a real
        // secret sitting on the KEY side with a benign-looking value would have been
        // silently excluded.
        let buf = b"zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi=run-2026-01-01";
        assert_eq!(
            EntropyDetector::default().detect(buf, &[]).len(),
            1,
            "a real secret on the key side of `=` must still be flagged"
        );
    }

    #[test]
    fn still_flags_a_short_high_entropy_key_side_secret() {
        // Round-3 doubt-pass finding (Codex): the round-2 length-cap fix (key.len() <=
        // 24) still let a realistic 20-24 byte secret through as a "key" -- a flat
        // length bound can't distinguish a secret from a name. This 20-byte key would
        // have passed the old cap; the current fix (key must independently decompose
        // via is_structured_segments) rejects it because it has no internal delimiter.
        let buf = b"aB3dE5fG7hI9jK1lM2nP=run-2026-01-01";
        assert_eq!(
            EntropyDetector::default().detect(buf, &[]).len(),
            1,
            "a 20-byte high-entropy key with no internal delimiter must still be flagged"
        );
    }

    #[test]
    fn ignores_a_multi_segment_key_and_value_assignment() {
        // Confirms the symmetric fix still catches the real target case: both sides
        // decompose into >=2 word-like segments, same as a real AWS-style env var name.
        let buf = b"AWS_SECRET_ACCESS_KEY=demo-placeholder-value";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn still_flags_a_bare_alphabetic_secret_after_an_equals_sign() {
        // 2026-07-22 doubt-pass Critical finding (single-model + Codex, independently):
        // the 2026-07-21 fix split on `=` unconditionally, so a VALUE that is a single
        // run of letters with no further delimiter -- still genuinely high-entropy --
        // was being excluded just for being alphabetic. Must still be flagged: the value
        // has no further `is_structured_segments` decomposition of its own.
        let buf = b"TOKEN=zQvLmXpRwTuYbNdKfJhCsEoAiPlMnQr";
        assert_eq!(
            EntropyDetector::default().detect(buf, &[]).len(),
            1,
            "a bare alphabetic high-entropy value after `=` must still be flagged"
        );
    }

    #[test]
    fn ignores_a_commit_sha_with_git_context() {
        // The exact T10 benign-lookalike residual (docs/decisions.md, 2026-07-21):
        // a full 40-char lowercase-hex SHA-1 immediately preceded by "commit".
        let buf = b"commit 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b merged on 2026-07-18";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn still_flags_a_hex_looking_secret_with_no_git_context() {
        // Same shape (lowercase hex, SHA-length), no context word -- must NOT be
        // excluded by a blanket hex-shape carve-out.
        let buf = b"token=17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b";
        assert_eq!(EntropyDetector::default().detect(buf, &[]).len(), 1);
    }

    #[test]
    fn still_flags_a_non_hex_token_after_the_word_commit() {
        // Context word present, but the token itself isn't hex-shaped -- the context
        // exclusion must not swallow ordinary high-entropy secrets that merely follow
        // the word "commit" in prose.
        let buf = b"commit token zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi applied";
        assert_eq!(EntropyDetector::default().detect(buf, &[]).len(), 1);
    }

    #[test]
    fn git_sha_context_words_are_case_insensitive_and_tolerate_a_colon() {
        let buf = b"Commit: 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b";
        assert!(EntropyDetector::default().detect(buf, &[]).is_empty());
    }

    #[test]
    fn sha1_and_sha256_context_words_now_actually_fire() {
        // 2026-07-22 doubt-pass High finding (single-model + Codex, independently): the
        // backward word-scan was alphabetic-only, so it stopped at the first digit and
        // could never extract "sha1"/"sha256" as a whole word -- dead code, unreachable
        // by construction. A 64-char lowercase-hex token (SHA-256 length) after "sha256:"
        // and a 40-char one after "sha1:" must both now be excluded.
        let sha1_buf = b"sha1: 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b";
        assert!(EntropyDetector::default().detect(sha1_buf, &[]).is_empty());
        let sha256_buf =
            b"sha256: 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b17b27d5c8f9e2a1b3d4c5e6f";
        assert!(EntropyDetector::default()
            .detect(sha256_buf, &[])
            .is_empty());
    }

    #[test]
    fn still_flags_a_hex_secret_after_the_removed_hash_marker() {
        // 2026-07-22 doubt-pass High finding (single-model + Codex, independently):
        // "hash" was too generic -- it matched as the tail of extremely common compound
        // identifiers holding real sensitive values (`password_hash:`, `file_hash:`),
        // since the backward scan stops at `_` and captures only "hash". Removed from
        // GIT_SHA_CONTEXT_WORDS entirely; both forms must now be flagged.
        let buf = b"hash: 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b";
        assert_eq!(EntropyDetector::default().detect(buf, &[]).len(), 1);
        let compound_buf = b"password_hash: 17b27d5c8f9e2a1b3d4c5e6f7a8b9c0d1e2f3a4b";
        assert_eq!(
            EntropyDetector::default().detect(compound_buf, &[]).len(),
            1
        );
    }

    #[test]
    fn never_panics_on_empty_or_invalid_utf8_input() {
        assert!(EntropyDetector::default().detect(b"", &[]).is_empty());
        let _ = EntropyDetector::default().detect(&[0xFF, 0xFE, 0x00, 0x80], &[]);
    }
}
