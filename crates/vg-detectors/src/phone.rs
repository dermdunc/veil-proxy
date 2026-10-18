//! E.164-ish phone number detector.
//!
//! ITU-T E.164 itself is just `+` followed by 7-15 digits with no separators, but almost
//! no real-world text writes numbers that way — they're grouped with spaces, dots,
//! hyphens, and/or parentheses. The regex below matches the loosely-grouped form (a
//! leading digit group, optionally parenthesised, followed by more digit groups joined
//! by common separators), and `detect` then filters candidates down to:
//!
//! 1. a total digit count in E.164's 7-15 range, and
//! 2. at least one phone-typical marker (`+`, parens, or a separator) — a bare
//!    unseparated run of digits is far more likely to be a generic numeric ID than a
//!    phone number, so it's excluded unless it starts with `+`.
//!
//! This is a heuristic by construction — the task spec calls for "E.164-ish", not a
//! validator — and it will still false-positive on separator-shaped numeric strings
//! that happen to fall in the digit-count range. This detector's confidence is set
//! below the fixed-format detectors' (email/IP/IBAN) to reflect that extra ambiguity;
//! see `docs/decisions.md`.
//!
//! **2026-07-16 census finding:** a real 197-file scan of Hekton's own repos found the
//! `YYYY-MM-DD` case above wasn't hypothetical — it was the dominant false-positive
//! class (783 of the census's phone findings), since dates are common in prose and an
//! 8-digit, 4/2/2-grouped, calendar-valid date is common enough to swamp real numbers.
//! Fixed narrowly via `looks_like_iso_date`: excludes only the strict ISO date shape,
//! not arbitrary grouped numbers, per the Codex-reconciled decision in
//! `docs/decisions.md` to fix detector-local false positives now rather than wait for
//! Task T10's formal precision measurement.

use std::sync::OnceLock;

use regex::bytes::{Regex, RegexBuilder};
use vg_core::{Detector, DetectorId, EntityType, Finding, Span};

const ENTITY_TYPES: [EntityType; 1] = [EntityType::Phone];
const CONFIDENCE: f32 = 0.7;
const MIN_DIGITS: usize = 7;
const MAX_DIGITS: usize = 15;

fn pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(r"\+?\(?[0-9]{1,4}\)?(?:[-. ]?[0-9]{2,4}){1,5}")
            .unicode(false)
            .build()
            .expect("phone regex pattern is a valid, tested literal")
    })
}

fn has_phone_marker(matched: &[u8]) -> bool {
    matched
        .iter()
        .any(|b| matches!(b, b'+' | b'(' | b')' | b'-' | b'.' | b' '))
}

/// Excludes matches shaped like an ISO-ish calendar date (`YYYY-MM-DD` or
/// `YYYY.MM.DD`) rather than a phone number: 8 digits split 4/2/2 with a
/// plausible year/month/day is indistinguishable from a short local number by
/// digit-count and marker alone, but real phone numbers essentially never fall
/// into exactly this grouping with a calendar-valid month and day. Deliberately
/// narrow (2026-07-16 census finding, see `docs/decisions.md`): only the strict
/// 4/2/2 date shape is excluded, not arbitrary grouped numbers, so this doesn't
/// eat real short local numbers that happen to share a digit count.
fn looks_like_iso_date(matched: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(matched) else {
        return false;
    };
    let groups: Vec<&str> = s.split(['-', '.']).collect();
    let [year, month, day] = groups.as_slice() else {
        return false;
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return false;
    }
    if !year.bytes().all(|b| b.is_ascii_digit())
        || !month.bytes().all(|b| b.is_ascii_digit())
        || !day.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        year.parse::<u32>(),
        month.parse::<u32>(),
        day.parse::<u32>(),
    ) else {
        return false;
    };
    (1900..=2099).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d)
}

/// Maximum bytes `expand_to_digit_hyphen_run` walks in each direction. Generous enough
/// for any realistic ISBN (17 bytes worst case: 13 digits + 4 hyphens), while bounding
/// the cost of a single expansion on an adversarial digit/hyphen-heavy buffer --
/// unbounded expansion is O(n) per match with up to O(n) matches possible in one buffer,
/// an O(n^2) risk on a hot path with a 25ms p95 budget (2026-07-22 doubt-pass finding,
/// single-model + Codex, independently).
///
/// **Round-2 doubt-pass finding, named but not further fixed: this bounds, it does not
/// eliminate, cross-match merging.** Two genuinely separate values joined by nothing but
/// digits/hyphens (no space, comma, or other separator between them) within the 24-byte
/// window can still merge into one candidate that coincidentally satisfies the ISBN-13
/// checksum -- which requires no text marker, unlike the ISBN-10/ZIP+4 paths below. This
/// only fires when the two values are truly byte-adjacent (any other separator character
/// stops the walk immediately), which is narrower than "any content within 24 bytes";
/// closing it further would mean bounding expansion by the regex's own group-count
/// structure rather than raw byte distance, a larger change not made here. Accepted,
/// named residual -- the same posture this file takes elsewhere.
const MAX_EXPAND: usize = 24;

/// Expands a match's byte range to the contiguous run of digits/hyphens in `buf`
/// (bounded by `MAX_EXPAND` each direction), walking left and right from the match
/// bounds. The phone regex's per-group digit cap (`{2,4}`) can split a longer structured
/// number -- an ISBN-13's `978-3-16-148410-0` matches this detector's pattern only as
/// the inner fragment `3-16-148410`, starting and ending mid-number -- so checksum
/// validation needs the WHOLE number, not just the regex's own match span.
///
/// **Round-2 doubt-pass fix, reverted in round 3 (Codex finding): does NOT match `.`.**
/// A round-2 fix added `.` to match the phone regex's own `[-. ]` separator class and
/// catch dot-separated ISBNs, but Codex showed this meaningfully widens the ISBN-13
/// cross-match-merge residual documented above -- dotted content (version strings,
/// decimals, IP-like patterns) is far more common than hyphenated content, and ISBN-13
/// requires no text marker, so a real dotted phone-like value merging with adjacent
/// dotted digits into a valid ISBN-13 checksum is a realistic leak, not a contrived one
/// (`978.316.1484.100` collects the canonical valid ISBN-13 digit sequence). The
/// precision gain (recognizing dot-separated ISBNs, a real but much less common
/// formatting choice per ISO 2108, which is predominantly hyphenated) was not worth that
/// false-negative surface. Reverted to digit/hyphen-only; dot-separated ISBNs remain a
/// named, accepted residual.
fn expand_to_digit_hyphen_run(buf: &[u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    let floor = start.saturating_sub(MAX_EXPAND);
    while s > floor && matches!(buf[s - 1], b'0'..=b'9' | b'-') {
        s -= 1;
    }
    let mut e = end;
    let ceil = (end + MAX_EXPAND).min(buf.len());
    while e < ceil && matches!(buf[e], b'0'..=b'9' | b'-') {
        e += 1;
    }
    (s, e)
}

/// Case-insensitive, whole-word search for `marker` within the `window` bytes
/// immediately preceding `pos` in `buf`. Used to corroborate the two checksum/shape
/// exclusions below that, unlike ISBN-13's 978/979-prefixed checksum, are not narrow
/// enough alone: ISBN-10 has no prefix to cut its ~1-in-11 checksum-collision rate
/// against real phone numbers, and a bare `DDDDD-DDDD` shape cannot be told apart from
/// some non-NANP phone formatting (2026-07-22 doubt-pass findings, single-model + Codex,
/// independently -- Codex's concrete counterexample: `415-234-0002`, an ordinary
/// NANP-shaped number, passes the ISBN-10 checksum outright).
///
/// **Word-boundary checked (round-2 doubt-pass finding, closed; round-3 Codex finding
/// closed a gap in that fix).** A plain substring search matched `zip` inside
/// `gzip`/`unzip`. The round-2 fix added boundary checks, but checked them against the
/// *truncated search window slice*, not the real buffer -- a match sitting exactly at
/// the window's start or end edge was treated as automatically boundary-OK regardless of
/// what byte actually sat just outside the window in the real buffer, so
/// `zip12345-6789` (marker glued directly onto the digits, zero separator) could still
/// pass. **Fix:** boundary bytes are now read from the full `buf` at absolute indices,
/// not the windowed slice, so a marker's true neighbours are always checked, however the
/// window happened to truncate. Also **treats `_` as a word-forming character, not a
/// boundary** (round-3 Codex finding): `zip_code`/`not_zip`/`customer_isbn` no longer
/// count as containing the standalone word, matching how `_` is already treated as an
/// identifier-forming character throughout the rest of this codebase. **Accepted
/// residual, not fixed:** `zip` as its own standalone word can still be present for an
/// unrelated reason (e.g. "extract the zip" before an unrelated ticket number) -- the
/// marker proves the word is present, not that it is being used in the postal-code
/// sense; the same class of ambiguity a human skimming the same text would also have.
fn preceded_by_marker_within(buf: &[u8], pos: usize, window: usize, marker: &[u8]) -> bool {
    // Round-4 doubt-pass finding: `pos <= buf.len()` was an unstated, unenforced
    // invariant every current call site happens to satisfy (both derive `pos` from a
    // non-empty regex match), but a function whose entire job is defending boundary
    // conditions on adversarial input shouldn't rely on caller discipline for its own
    // bounds -- a future call site passing an out-of-range `pos` would panic on the
    // `buf[i..i + marker.len()]` slice below instead of returning a safe `false`.
    if pos > buf.len() || marker.is_empty() || marker.len() > pos {
        return false;
    }
    let win_start = pos.saturating_sub(window);
    let last_start = pos - marker.len();
    if last_start < win_start {
        return false;
    }
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (win_start..=last_start).any(|i| {
        if !buf[i..i + marker.len()].eq_ignore_ascii_case(marker) {
            return false;
        }
        let left_ok = i == 0 || !is_word_byte(buf[i - 1]);
        let right_idx = i + marker.len();
        let right_ok = right_idx >= buf.len() || !is_word_byte(buf[right_idx]);
        left_ok && right_ok
    })
}

/// Validates an ISBN-13 checksum: exactly 13 digits, a `978`/`979` (Bookland EAN)
/// prefix, alternating 1/3 weights summing to 0 mod 10. Both the prefix and the
/// checksum are required together -- a real phone number satisfying the mod-10 checksum
/// alone happens by chance roughly 1 in 10; requiring the prefix too narrows that
/// further, so this is a validated exclusion, not a shape guess.
fn looks_like_isbn13(digits: &[u32]) -> bool {
    if digits.len() != 13 {
        return false;
    }
    let bookland_prefix = digits[0] == 9 && digits[1] == 7 && (digits[2] == 8 || digits[2] == 9);
    if !bookland_prefix {
        return false;
    }
    let sum: u32 = digits[..12]
        .iter()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 0 { d } else { d * 3 })
        .sum();
    (10 - (sum % 10)) % 10 == digits[12]
}

/// Validates an ISBN-10 checksum: exactly 10 digits, weighted sum (`d1*10 + d2*9 + ... +
/// d10*1`) divisible by 11. **Checksum alone is deliberately NOT sufficient** to exclude
/// a match on this -- see `looks_like_isbn`'s marker requirement. **Scope note:** only
/// the all-digit form is handled here -- an ISBN-10 whose check digit is the literal
/// character `X` (representing 10) doesn't match this detector's digit-only pattern, so
/// its numeric prefix never reaches a valid 10-digit checksum via this function; that
/// case is instead covered by the same "isbn" marker requirement below (an `ISBN
/// ...-X`-labelled number is excluded because the marker is present, independent of the
/// checksum path), so it isn't a silent gap in practice.
fn looks_like_isbn10(digits: &[u32]) -> bool {
    if digits.len() != 10 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (10 - i as u32))
        .sum();
    sum.is_multiple_of(11)
}

/// Excludes a match whose *expanded* digit/hyphen run (§`expand_to_digit_hyphen_run`)
/// passes an ISBN-13 or ISBN-10 checksum. **ISBN-13 is checksum-only** (its 978/979
/// prefix already narrows real-phone-number collisions to roughly 1-in-5000). **ISBN-10
/// additionally requires an "isbn" text marker** within a short lookback window of the
/// expanded run's start (2026-07-22 doubt-pass fix, Critical finding closed): ISBN-10 has
/// no prefix, so its mod-11 checksum alone collides with ordinary NANP-shaped phone
/// numbers roughly 1-in-11 -- confirmed concretely against `415-234-0002`, which passes
/// the checksum with no marker present. Requiring the label is the same conservative,
/// context-gated posture already used for the git-SHA exclusion in `entropy.rs`.
fn looks_like_isbn(buf: &[u8], m_start: usize, m_end: usize) -> bool {
    let (s, e) = expand_to_digit_hyphen_run(buf, m_start, m_end);
    let digits: Vec<u32> = buf[s..e]
        .iter()
        .filter(|b| b.is_ascii_digit())
        .map(|&b| u32::from(b - b'0'))
        .collect();
    if looks_like_isbn13(&digits) {
        return true;
    }
    looks_like_isbn10(&digits) && preceded_by_marker_within(buf, s, 16, b"isbn")
}

/// Excludes matches shaped like a US ZIP+4 postal code (`DDDDD-DDDD`): exactly two
/// digit groups of length 5 and 4 joined by a single hyphen, and nothing else in the
/// match, **plus a "zip"/"postal" text marker** within a short lookback window (2026-07-22
/// doubt-pass fix, Critical finding closed): shape alone cannot rule out some non-NANP
/// phone formatting that happens to group 5-then-4 (Codex finding) -- the same
/// conservative, context-gated posture as the ISBN-10 marker above and the git-SHA
/// exclusion in `entropy.rs`. **Accepted residual:** a real 5-4-grouped phone number that
/// happens to sit within 16 bytes of the literal word "zip"/"postal" in unrelated prose
/// would still be excluded; narrower than the prior unconditional shape-only exclusion,
/// not fixed further here.
fn looks_like_zip_plus4(buf: &[u8], m_start: usize, matched: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(matched) else {
        return false;
    };
    let parts: Vec<&str> = s.split('-').collect();
    let [first, second] = parts.as_slice() else {
        return false;
    };
    let shape_matches = first.len() == 5
        && second.len() == 4
        && first.bytes().all(|b| b.is_ascii_digit())
        && second.bytes().all(|b| b.is_ascii_digit());
    shape_matches
        && (preceded_by_marker_within(buf, m_start, 16, b"zip")
            || preceded_by_marker_within(buf, m_start, 16, b"postal"))
}

/// Model-family words a `-YYYYMMDD`-suffixed model ID can carry directly before its
/// version groups (`claude-haiku-4-5-20251001`, `claude-sonnet-4-20250514`). A positive
/// allowlist rather than "any word": DDD cycle 3 showed that "a letter is reached" let
/// phone labels qualify (`Tel_8-20251001`, `phone-1-19990101`).
const MODEL_FAMILY_WORDS: [&[u8]; 4] = [b"claude", b"opus", b"sonnet", b"haiku"];

/// Most single-digit version groups a model ID carries between its family word and the
/// date (`haiku-4-5-`). More is a phone shape: `tel-9-1-9-8-20251231` is a hyphenated
/// `+91 9820251231` (Codex, DDD cycle 3).
const MAX_VERSION_GROUPS: usize = 2;

/// Excludes the `-YYYYMMDD` date suffix of a Claude model ID: the regex matches
/// `5-20251001` inside `claude-haiku-4-5-20251001` (9 digits, a hyphen marker), which a
/// real Claude Code system prompt sends on every request (veil-proxy#90, XREPO-021).
/// Deliberately tied to that exact shape -- each review round found real numbers a looser
/// rule let through (`(415) 555-1234-mobile`, `kontakt-030-20150612`,
/// `sthlm-46-8-20251001`, `alice-1-20250231`, `tel-1-20251001_ext99`, `Tel_8-20251001`,
/// `tel-9-1-9-8-20251231`), all now regression tests. All of these must hold:
///
/// 1. the match has no `+`, parens or space -- strong phone markers always win;
/// 2. it ends in an unbroken run of exactly 8 digits that is a real calendar date
///    `YYYYMMDD` (leap years included), followed in `buf` by end of input or one of the
///    bytes a model ID ends on in text -- whitespace, quotes, backtick, `.,;:)]}>`, or `-`
///    for Bedrock `...-v1:0` IDs (an allowlist: `/` let `haiku-1-20251001/99` through,
///    Codex cycle 4);
/// 3. a `-` sits directly before that run (`_` and `.` cannot: the regex's separator
///    class is `[-. ]`, and a `.` joiner is not the model-ID shape);
/// 4. left of that `-`, at most `MAX_VERSION_GROUPS` single-digit `<digit><-|_>` groups,
///    then one of `MODEL_FAMILY_WORDS` (case-insensitive) starting at a word boundary
///    (preceded by neither an alphanumeric nor `_`: `phone_haiku-...` does not count).
///
/// Beyond one reverse scan of the match itself, at most 12 bytes are inspected
/// (1 + 2 x 2 + 6 + 1), so per-match cost is constant.
///
/// **Accepted residual:** a real number whose last 8 digits are unseparated, form a valid
/// date, and follow at most two single-digit groups glued to one of those four words
/// (`haiku-1-20251001`) is not flagged.
///
/// **Scope:** Claude model IDs only. Other providers' dated IDs (`o1-2024-12-17`,
/// `gpt-4.1-2025-04-14`, `gpt-4.5-20251001`) and glued variants (`claude-v4-20251001`,
/// `sonnet4-5-20251001`) still over-mask -- fails toward masking; tracked in next-actions.
fn looks_like_date_suffixed_identifier(buf: &[u8], start: usize, end: usize) -> bool {
    let matched = &buf[start..end];
    if matched
        .iter()
        .any(|b| matches!(b, b'+' | b'(' | b')' | b' '))
    {
        return false;
    }
    // The date run must end the identifier (`tel-1-20251001_ext99`, Codex cycle 2;
    // `haiku-1-20251001/99`, Codex cycle 4).
    let ends_identifier = buf.get(end).is_none_or(|&b| {
        b.is_ascii_whitespace()
            || matches!(
                b,
                b'\'' | b'"' | b'`' | b'.' | b',' | b';' | b':' | b')' | b']' | b'}' | b'>' | b'-'
            )
    });
    if !ends_identifier {
        return false;
    }
    let run_len = matched
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let run_start = end - run_len;
    if run_len != 8 || run_start == 0 || buf[run_start - 1] != b'-' {
        return false;
    }
    let digits = &buf[run_start..end];
    let num = |r: std::ops::Range<usize>| {
        digits[r]
            .iter()
            .fold(0u32, |acc, &b| acc * 10 + u32::from(b - b'0'))
    };
    if !is_calendar_date(num(0..4), num(4..6), num(6..8)) {
        return false;
    }
    // `i` indexes the joiner just crossed; step over at most MAX_VERSION_GROUPS
    // `<digit><joiner>` units, then require a model-family word ending right there.
    let mut i = run_start - 1;
    for _ in 0..MAX_VERSION_GROUPS {
        if i >= 2 && buf[i - 1].is_ascii_digit() && matches!(buf[i - 2], b'-' | b'_') {
            i -= 2;
        } else {
            break;
        }
    }
    MODEL_FAMILY_WORDS.iter().any(|word| {
        i >= word.len()
            && buf[i - word.len()..i].eq_ignore_ascii_case(word)
            && (i == word.len() || {
                let before = buf[i - word.len() - 1];
                !(before.is_ascii_alphanumeric() || before == b'_')
            })
    })
}

/// A real Gregorian date in 1900-2099, leap years included (`20250231` is not one --
/// Codex review finding against a range-only check).
fn is_calendar_date(y: u32, m: u32, d: u32) -> bool {
    let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1900..=2099).contains(&y) && (1..=days).contains(&d)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn id(&self) -> DetectorId {
        DetectorId("phone".to_string())
    }

    fn detect(&self, buf: &[u8], _spans: &[Span]) -> Vec<Finding> {
        let detector_id = self.id();
        pattern()
            .find_iter(buf)
            .filter_map(|m| {
                let matched = m.as_bytes();
                let digit_count = matched.iter().filter(|b| b.is_ascii_digit()).count();
                if !(MIN_DIGITS..=MAX_DIGITS).contains(&digit_count)
                    || !has_phone_marker(matched)
                    || looks_like_iso_date(matched)
                    || looks_like_zip_plus4(buf, m.start(), matched)
                    || looks_like_isbn(buf, m.start(), m.end())
                    || looks_like_date_suffixed_identifier(buf, m.start(), m.end())
                {
                    return None;
                }
                Some(Finding {
                    entity_type: EntityType::Phone,
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                        node_kind: None,
                    },
                    confidence: CONFIDENCE,
                    detector: detector_id.clone(),
                })
            })
            .collect()
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
    fn detects_an_international_number_with_country_code() {
        let buf = b"call +1-415-555-2671 now";
        let findings = PhoneDetector.detect(buf, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, EntityType::Phone);
    }

    #[test]
    fn detects_a_parenthesised_local_number() {
        let buf = b"office: (020) 7946 0958";
        assert_eq!(PhoneDetector.detect(buf, &[]).len(), 1);
    }

    #[test]
    fn detects_a_short_hyphenated_local_number() {
        let buf = b"reach me at 555-1234";
        assert_eq!(PhoneDetector.detect(buf, &[]).len(), 1);
    }

    #[test]
    fn ignores_too_few_digits() {
        assert!(PhoneDetector.detect(b"dial 911", &[]).is_empty());
        assert!(PhoneDetector.detect(b"room 12-34", &[]).is_empty());
    }

    #[test]
    fn ignores_a_bare_unseparated_digit_run_without_a_plus() {
        // No separators and no leading '+' -- too ambiguous with a generic numeric ID.
        assert!(PhoneDetector
            .detect(b"order id 415555267188", &[])
            .is_empty());
    }

    #[test]
    fn accepts_a_bare_digit_run_with_a_leading_plus() {
        assert_eq!(PhoneDetector.detect(b"+14155552671", &[]).len(), 1);
    }

    #[test]
    fn ignores_too_many_digits() {
        assert!(PhoneDetector
            .detect(b"ref-123456789012345678", &[])
            .is_empty());
    }

    #[test]
    fn ignores_an_iso_date() {
        assert!(PhoneDetector
            .detect(b"session started on 2026-07-16 and ran late", &[])
            .is_empty());
        assert!(PhoneDetector.detect(b"logged 2026.07.16", &[]).is_empty());
    }

    #[test]
    fn ignores_iso_dates_across_the_full_calendar_year() {
        for (y, m, d) in [(2026, 1, 31), (2026, 12, 1), (1999, 6, 15), (2099, 2, 28)] {
            let s = format!("{y:04}-{m:02}-{d:02}");
            assert!(
                PhoneDetector.detect(s.as_bytes(), &[]).is_empty(),
                "expected {s} to be excluded as a date"
            );
        }
    }

    #[test]
    fn still_detects_a_real_number_with_the_same_digit_count_as_a_date() {
        // 8 digits, 3 groups, but month/day out of calendar range -- not a date shape.
        assert_eq!(PhoneDetector.detect(b"call 9999-99-99 now", &[]).len(), 1);
    }

    #[test]
    fn satisfies_the_detector_contract() {
        assert_detector_contract(&PhoneDetector, b"+1-415-555-2671 and 555-1234", &[]);
    }

    #[test]
    fn ignores_an_isbn13() {
        // The exact T10 benign-lookalike residual (docs/decisions.md, 2026-07-21): the
        // regex's own match span is the inner fragment "3-16-148410", starting mid-number.
        let buf = b"ISBN 978-3-16-148410-0 and zip 12345-6789 in the shipping record";
        assert!(
            PhoneDetector.detect(buf, &[]).is_empty(),
            "expected both the ISBN-13 and the ZIP+4 to be excluded, got {:?}",
            PhoneDetector.detect(buf, &[])
        );
    }

    #[test]
    fn still_flags_a_13_digit_hyphenated_number_with_a_bad_isbn_checksum() {
        // Same digit-group shape and a 978 prefix, but the check digit is wrong -- must
        // not be excluded by a blanket ISBN-shape guess, only a validated checksum.
        let buf = b"call 978-3-16-148410-9 now";
        assert!(!PhoneDetector.detect(buf, &[]).is_empty());
    }

    #[test]
    fn ignores_an_isbn10_when_labelled() {
        // The Wikipedia-canonical ISBN-10 checksum example, now requiring the "isbn"
        // marker (2026-07-22 doubt-pass fix, see the Critical finding below).
        let buf = b"ISBN 0-306-40615-2 recorded";
        assert!(PhoneDetector.detect(buf, &[]).is_empty());
    }

    #[test]
    fn still_flags_an_isbn10_checksum_collision_with_no_label() {
        // 2026-07-22 doubt-pass Critical finding (single-model + Codex, independently,
        // Codex's concrete counterexample): an ordinary NANP-shaped phone number can
        // coincidentally satisfy the ISBN-10 mod-11 checksum. Without an "isbn" marker
        // nearby, checksum alone must NOT exclude it -- this is the exact regression the
        // marker requirement exists to close.
        let buf = b"call 415-234-0002 now";
        assert_eq!(
            PhoneDetector.detect(buf, &[]).len(),
            1,
            "an unlabelled ISBN-10-checksum-colliding phone number must still be flagged"
        );
    }

    #[test]
    fn still_flags_a_5_4_grouped_number_near_gzip_not_the_standalone_word_zip() {
        // Round-2 doubt-pass finding: a plain substring search for "zip" matched inside
        // "gzip"/"unzip", which would wrongly exclude a real 5-4 grouped number sitting
        // near either word. Must still be flagged with the word-boundary fix.
        let buf = b"please gzip 12345-6789 before sending";
        assert_eq!(
            PhoneDetector.detect(buf, &[]).len(),
            1,
            "a number near \"gzip\" (not the standalone word \"zip\") must still be flagged"
        );
    }

    #[test]
    fn never_panics_or_hangs_on_a_long_digit_hyphen_run() {
        // MAX_EXPAND bounds the cost of expand_to_digit_hyphen_run on an adversarial
        // digit/hyphen-heavy buffer -- proves it completes (no panic, no pathological
        // slowdown) rather than asserting a specific finding count.
        let long_run: String = "1-".repeat(5000) + "2345678";
        let buf = format!("prefix {long_run} suffix");
        let _ = PhoneDetector.detect(buf.as_bytes(), &[]);
    }

    #[test]
    fn expand_to_digit_hyphen_run_is_bounded_by_max_expand() {
        // Round-3 doubt-pass finding (Codex): the prior long-run test only proved "does
        // not panic," not that MAX_EXPAND actually bounds the walk. Direct test: a
        // contiguous digit/hyphen run much longer than MAX_EXPAND on both sides of a
        // one-byte "match" in the middle -- expansion must stop at the bound in each
        // direction, not walk the whole run.
        let long_run = "9".repeat(100);
        let buf = format!("{long_run}-{long_run}");
        let mid = long_run.len() + 1;
        let (s, e) = expand_to_digit_hyphen_run(buf.as_bytes(), mid, mid + 1);
        assert_eq!(
            mid - s,
            MAX_EXPAND,
            "left expansion did not stop at MAX_EXPAND"
        );
        assert_eq!(
            e - (mid + 1),
            MAX_EXPAND,
            "right expansion did not stop at MAX_EXPAND"
        );
    }

    #[test]
    fn still_flags_a_number_with_a_marker_glued_directly_onto_it() {
        // Round-3 doubt-pass finding (Codex): the round-2 boundary check validated
        // boundaries against the TRUNCATED search-window slice, not the real buffer, so
        // a marker sitting exactly at the window edge was treated as boundary-OK
        // regardless of the actual adjacent byte. `zip12345-6789` glues "zip" directly
        // onto the digits with zero separator -- not a real word boundary -- and must
        // still be flagged.
        let buf = b"zip12345-6789 recorded";
        assert_eq!(
            PhoneDetector.detect(buf, &[]).len(),
            1,
            "a marker glued directly onto the digits with no separator must still be flagged"
        );
    }

    #[test]
    fn still_flags_numbers_near_compound_identifiers_containing_the_marker() {
        // Round-3 doubt-pass finding (Codex): `_` was not treated as a word-forming
        // character, so "zip_code"/"customer_isbn" wrongly counted as containing the
        // standalone marker word.
        assert_eq!(
            PhoneDetector.detect(b"zip_code 12345-6789", &[]).len(),
            1,
            "\"zip_code\" must not be treated as containing the standalone word \"zip\""
        );
        assert_eq!(
            PhoneDetector
                .detect(b"customer_isbn 415-234-0002", &[])
                .len(),
            1,
            "\"customer_isbn\" must not be treated as containing the standalone word \"isbn\""
        );
    }

    #[test]
    fn still_flags_a_10_digit_hyphenated_number_with_a_bad_isbn10_checksum() {
        // Checksum fails regardless of the "ISBN" label being present -- the marker
        // requirement only narrows a checksum PASS, it never substitutes for one.
        let buf = b"ISBN 0-306-40615-9, call now";
        assert!(!PhoneDetector.detect(buf, &[]).is_empty());
    }

    #[test]
    fn ignores_a_zip_plus_4_when_labelled() {
        assert!(PhoneDetector
            .detect(b"ship to zip 12345-6789 please", &[])
            .is_empty());
    }

    #[test]
    fn still_flags_a_5_4_grouped_number_with_no_zip_or_postal_label() {
        // 2026-07-22 doubt-pass Critical finding (Codex): a bare 5-4 digit grouping
        // cannot be told apart from some non-NANP phone formatting by shape alone.
        // Without a "zip"/"postal" marker nearby, must NOT be excluded.
        let buf = b"reference 12345-6789 confirmed";
        assert_eq!(
            PhoneDetector.detect(buf, &[]).len(),
            1,
            "an unlabelled 5-4 grouped number must still be flagged"
        );
    }

    #[test]
    fn ignores_date_suffixed_identifiers() {
        // veil-proxy#90: seen live in a real Claude Code system prompt. Every case here
        // reaches `looks_like_date_suffixed_identifier` (the regex match carries a `-`).
        // (`claude-3-5-sonnet-20241022` never did: its bare 8-digit match has no marker.)
        for buf in [
            &b"Haiku 4.5: 'claude-haiku-4-5-20251001'. When building"[..],
            b"model claude-opus-4-1-20250805 is pinned",
            b"claude-sonnet-4-20250514",
            b"CLAUDE-HAIKU-4-5-20240229",
            b"anthropic.claude-haiku-4-5-20251001-v1:0",
        ] {
            assert!(
                PhoneDetector.detect(buf, &[]).is_empty(),
                "expected no phone in {:?}, got {:?}",
                String::from_utf8_lossy(buf),
                PhoneDetector.detect(buf, &[])
            );
        }
    }

    #[test]
    fn still_flags_numbers_next_to_non_identifier_delimiters() {
        for buf in [
            &b"+44 20 7946 0958"[..],
            b"020 7946 0958",
            b"(020) 7946-0958",
            b"tel: 415-555-1234",
            b"PHONE=415-555-1234",
            b"call +1-415-555-2671, thanks",
            b"'415-555-1234'",
            // Review findings against a broader first draft of the exclusion:
            b"(415) 555-1234-mobile",
            b"Reach me at 415-555-1234--Jane",
            b"Call 415-555-1234-ext",
            b"x-+1 415 555 2671",
            b"cust-a-+44 20 7946 0958",
            b"invoice_415-555-1234.pdf",
            b"/contact/jane-doe-415-555-1234",
            // A date-valid 8-digit tail is still a phone when phone markers are present
            // or nothing letter-bearing is joined to it.
            b"+44-20251001",
            b"call 1-20251001 now",
            // Confirming-review finding: an area-code group before a date-valid tail.
            b"kontakt-030-20150612",
            b"Tel_030-20150612",
            // DDD cycle 1 (fresh-context + Codex) findings:
            b"contact sthlm-46-8-20251001 now",
            b"/contact/alice-1-20250231",
            b"model-4-5-20250229",
            // DDD cycle 2 (Codex): the date run must end the identifier.
            b"{\"phone\":\"tel-1-20251001_ext99\"}",
            b"tel-1-20251001x",
            // DDD cycle 3 (fresh-context + Codex): labels and multi-group phone shapes.
            b"{\"phone\":\"tel-9-1-9-8-20251231\"}",
            b"Tel_8-20251001",
            b"sthlm-8-20251001",
            b"tw-2-20251001",
            b"phone-1-19990101",
            b"model_4-5-20240229",
            b"claude-haiku-1-4-5-20251001",
            b"ultrahaiku-4-5-20251001",
            // DDD cycle 4 (Codex): a continuing identifier and an `_`-glued family word.
            b"Call haiku-1-20251001/99",
            b"phone_haiku-1-20251001",
        ] {
            assert_eq!(
                PhoneDetector.detect(buf, &[]).len(),
                1,
                "expected one phone in {:?}",
                String::from_utf8_lossy(buf)
            );
        }
    }

    #[test]
    fn still_detects_a_real_number_with_a_different_grouping_than_zip_plus4() {
        // 5 then 4 digits is excluded; 3-3-4 (a real US-shaped grouping) must not be.
        assert_eq!(PhoneDetector.detect(b"call 415-555-1234 now", &[]).len(), 1);
    }
}
