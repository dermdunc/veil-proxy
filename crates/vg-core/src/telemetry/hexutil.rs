//! Minimal, hand-rolled lowercase hex encode/decode for the wire-serialization contract
//! (`telemetry::envelope`, `telemetry::ids`, `telemetry::signing`) — not a new `hex` crate
//! dependency for two small, one-directional operations, matching this crate's existing
//! preference for hand-rolled bounded helpers over a new dependency for simple string
//! logic (see `telemetry::ids`'s `validate_token`, `crate::keying`'s `canonicalize`).
//!
//! `encode` is infallible and always produces lowercase output — the wire contract
//! (`docs/architecture` for `veil.edge_event.v1`) requires lowercase hex for
//! `integrity.signature` and every other byte-array field; this is the single choke
//! point that guarantees that everywhere it's used. `decode` is used only for parsing
//! `VEIL_RECEIPT_KEY` (`telemetry::signing`) — case-insensitive, matching common hex
//! conventions (a key typed/copied by a human may use either case).

/// Encodes `bytes` as a lowercase hex string, two characters per byte.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Why [`decode`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HexDecodeError {
    #[error("hex string has odd length")]
    OddLength,
    #[error("hex string contains a byte outside 0-9/a-f/A-F")]
    InvalidChar,
}

/// Decodes a hex string (either case) into bytes. Rejects odd length and any
/// non-hex-digit byte — never silently truncates or skips a bad character.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, HexDecodeError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or(HexDecodeError::InvalidChar)?;
        let lo = hex_val(bytes[i + 1]).ok_or(HexDecodeError::InvalidChar)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_lowercase_two_chars_per_byte() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn encode_of_empty_is_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decode_round_trips_through_encode() {
        let bytes = [1u8, 2, 3, 250, 251, 252];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes.to_vec());
    }

    #[test]
    fn decode_accepts_uppercase() {
        assert_eq!(decode("ABCD").unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert_eq!(decode("abc"), Err(HexDecodeError::OddLength));
    }

    #[test]
    fn decode_rejects_non_hex_char() {
        assert_eq!(decode("zz"), Err(HexDecodeError::InvalidChar));
        assert_eq!(decode("a b1"), Err(HexDecodeError::InvalidChar));
    }
}
