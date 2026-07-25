use anyhow::{Context as _, bail};
use cookie::Key;

/// Number of hex characters a session key must have (64 bytes / 512 bits).
const SESSION_KEY_HEX_LEN: usize = 128;

/// Decode a 128-hex-character (64-byte / 512-bit) session key into a signing
/// [`Key`].
///
/// The full 64 bytes are required because comics does not enable the `cookie`
/// crate's `key-expansion` feature, so `Key::derive_from` (which would stretch a
/// shorter secret) is unavailable; enabling it would pull in `hkdf`. Hex is
/// decoded by hand for the same reason — no dependency is worth a 16-line loop.
pub fn parse_session_key(raw: &str) -> anyhow::Result<Key> {
    let raw = raw.trim();
    if raw.len() != SESSION_KEY_HEX_LEN {
        bail!(
            "session key must be {SESSION_KEY_HEX_LEN} hex characters (64 bytes), got {}; \
             generate one with `openssl rand -hex 64`",
            raw.len()
        );
    }
    let mut bytes = [0u8; SESSION_KEY_HEX_LEN / 2];
    for (out, pair) in bytes.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
        let hex = std::str::from_utf8(pair).unwrap_or("");
        *out = u8::from_str_radix(hex, 16).context(
            "session key must be hex characters only; \
             generate one with `openssl rand -hex 64`",
        )?;
    }
    Key::try_from(&bytes[..]).context("failed to build a signing key from the session key")
}

/// Lower-case hex encoding, shared by the session nonce and any other place that
/// needs to render bytes without pulling in a hex crate.
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parse_session_key_accepts_128_hex_chars() {
        assert!(parse_session_key(VALID).is_ok());
        assert!(parse_session_key(&format!("  {VALID}\n")).is_ok());
        assert!(parse_session_key(&VALID.to_uppercase()).is_ok());
    }

    #[test]
    fn parse_session_key_rejects_short_wrong_length_and_non_hex() {
        let err = parse_session_key("abcd").unwrap_err().to_string();
        assert!(err.contains("128 hex characters"), "{err}");

        let err = parse_session_key(&VALID[..127]).unwrap_err().to_string();
        assert!(err.contains("got 127"), "{err}");

        let non_hex = format!("zz{}", &VALID[2..]);
        let err = parse_session_key(&non_hex).unwrap_err().to_string();
        assert!(err.contains("hex characters only"), "{err}");
    }

    /// The whole point of a configured key: the same string must always yield
    /// the same signing material, across restarts and across replicas.
    #[test]
    fn parse_session_key_is_deterministic() {
        let a = parse_session_key(VALID).unwrap();
        let b = parse_session_key(VALID).unwrap();
        assert_eq!(a.signing(), b.signing());
    }

    #[test]
    fn parse_session_key_distinguishes_different_secrets() {
        let other = format!("ff{}", &VALID[2..]);
        let a = parse_session_key(VALID).unwrap();
        let b = parse_session_key(&other).unwrap();
        assert_ne!(a.signing(), b.signing());
    }

    #[test]
    fn hex_lower_pads_each_byte() {
        assert_eq!("000fff", hex_lower(&[0x00, 0x0f, 0xff]));
        assert_eq!("", hex_lower(&[]));
    }
}
