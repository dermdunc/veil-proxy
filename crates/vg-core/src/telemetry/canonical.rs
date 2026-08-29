//! Canonical JSON rendering for the `veil.edge_event.v1` wire contract.
//!
//! The downstream verifier (`veil-observatory`, a separate private repo, not in this
//! workspace) is Python and computes its HMAC over
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"))`. This module must produce a
//! byte-identical string for the equivalent Rust value, forever — any divergence breaks
//! verification permanently, not just for one record.
//!
//! **Deliberately does not rely on `serde_json::to_string`'s own key ordering.**
//! `serde_json::Value::Object` is backed by a plain `BTreeMap` (and so iterates in
//! sorted-key order) *only* as long as no crate anywhere in this workspace's dependency
//! graph enables serde_json's `preserve_order` feature — Cargo unifies features across
//! the whole build for a given crate id, so a future, unrelated crate turning that
//! feature on anywhere in this workspace would silently change `Value::Object`'s
//! iteration order for everyone, including this module, without touching a single line
//! here. Rather than depend on that global invariant holding forever, [`to_canonical_json`]
//! explicitly collects and sorts every object's keys itself before rendering — correct
//! regardless of `serde_json::Map`'s internal representation, today or in the future.
//!
//! **Also does not rely on `serde_json::to_string`'s escaping matching Python's.**
//! `serde_json` does not escape non-ASCII characters by default; Python's `json.dumps`
//! does (`ensure_ascii=True` is the default). Every string value this crate's `telemetry`
//! types can ever produce is guaranteed ASCII by construction (hex encodings, UUIDs,
//! fixed enum tag strings, and `telemetry::ids`'s bounded tokens, whose charset is
//! ASCII alphanumeric plus `._-+` — see that module's `validate_token`) — so this
//! divergence can never actually be exercised by real data. [`render_string`] still
//! implements the full Python-compatible escaping rule (rather than assuming the
//! ASCII-only invariant and skipping it), so the canonicalizer itself is correct for any
//! input, not merely for the inputs this crate happens to produce today.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// Why [`to_canonical_json`] failed. `serde_json::to_value` can only fail for a small,
/// fixed set of reasons (a map with a non-string key, a `Serialize` impl that itself
/// errors, `NaN`/`Infinity` floats) — none of which any `Serialize` impl in this crate's
/// `telemetry` module can produce (no maps, no floats, no fallible field access), so this
/// is a defensive typed error, not one this crate's own call sites are expected to hit in
/// practice.
#[derive(Debug, thiserror::Error)]
#[error("failed to canonicalize value to JSON: {0}")]
pub struct CanonicalizeError(String);

/// Serializes `value` and renders it as canonical JSON: object keys sorted
/// lexicographically at every nesting level, no insignificant whitespace. Matches
/// Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))` byte-for-byte for
/// any value this crate's `telemetry` types can produce (see module doc for why).
pub(crate) fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, CanonicalizeError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalizeError(e.to_string()))?;
    let mut out = String::new();
    render(&v, &mut out);
    Ok(out)
}

fn render(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        // No float formatting to reconcile against Python: every number this crate's
        // `telemetry` types ever produce is an integer (`u16`/`u32`/`u64`), and
        // `serde_json::Number`'s `Display` for an integer is already the plain decimal
        // digit string Python's `int` repr would produce too.
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => render_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Re-sort explicitly rather than trusting the map's own iteration order —
            // see module doc.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render_string(k, out);
                out.push(':');
                render(v, out);
            }
            out.push('}');
        }
    }
}

/// Renders a JSON string literal matching Python's default `json.dumps` encoder
/// (`ensure_ascii=True`): escapes `"`, `\`, the standard short escapes for
/// `\b\f\n\r\t`, every other control character (`< 0x20`) as `\u00XX`, and every
/// character outside printable ASCII (`> 0x7E`) as `\uXXXX` (a UTF-16 surrogate pair for
/// codepoints beyond the BMP) — everything else passes through unescaped.
fn render_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) > 0x7E => {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
                } else {
                    out.push_str(&format!("\\u{:04x}", cp));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serializer;

    /// Hand-computed expected string, not "it looks sorted": a small nested struct with
    /// keys deliberately out of alphabetical order in the `Serialize` impl itself,
    /// checked against a literal expected string worked out by hand.
    struct Sample {
        zebra: u64,
        apple: bool,
        middle: Nested,
    }

    struct Nested {
        z: &'static str,
        a: &'static str,
    }

    impl Serialize for Nested {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeStruct;
            let mut s = serializer.serialize_struct("Nested", 2)?;
            s.serialize_field("z", self.z)?;
            s.serialize_field("a", self.a)?;
            s.end()
        }
    }

    impl Serialize for Sample {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeStruct;
            let mut s = serializer.serialize_struct("Sample", 3)?;
            s.serialize_field("zebra", &self.zebra)?;
            s.serialize_field("apple", &self.apple)?;
            s.serialize_field("middle", &self.middle)?;
            s.end()
        }
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level_with_no_whitespace() {
        let sample = Sample {
            zebra: 7,
            apple: true,
            middle: Nested { z: "last", a: "first" },
        };
        let got = to_canonical_json(&sample).unwrap();
        // Hand-computed: top-level keys sorted (apple, middle, zebra), nested keys
        // sorted (a, z), no spaces after `:` or `,`. Equivalent to Python's
        // `json.dumps({"zebra": 7, "apple": True, "middle": {"z": "last", "a": "first"}},
        // sort_keys=True, separators=(",", ":"))`.
        let expected = r#"{"apple":true,"middle":{"a":"first","z":"last"},"zebra":7}"#;
        assert_eq!(got, expected);
    }

    #[test]
    fn canonical_json_escapes_strings_matching_python_ensure_ascii_default() {
        struct S(&'static str);
        impl Serialize for S {
            fn serialize<Ser: Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
                serializer.serialize_str(self.0)
            }
        }
        // Python: json.dumps("a\"b\\c\ndé") == '"a\\"b\\\\c\\nd\\u00e9"'
        let got = to_canonical_json(&S("a\"b\\c\nd\u{00e9}")).unwrap();
        let expected = "\"a\\\"b\\\\c\\nd\\u00e9\"";
        assert_eq!(got, expected);
    }

    #[test]
    fn canonical_json_array_has_no_whitespace() {
        let got = to_canonical_json(&vec![3u32, 1, 2]).unwrap();
        assert_eq!(got, "[3,1,2]");
    }
}
