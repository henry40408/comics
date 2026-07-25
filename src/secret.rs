use std::{fmt, str::FromStr};

use anyhow::{Context as _, bail};
use cookie::Key;
use sha2::{Digest as _, Sha256, Sha512};

/// Length of the configured secret in bytes (512 bits).
const SECRET_BYTES: usize = 64;

/// Number of hex characters the secret must have.
const SECRET_HEX_LEN: usize = SECRET_BYTES * 2;

/// Domain separators. Every value comics derives from the secret is the hash of
/// a distinct label concatenated with the secret, so the derived values cannot
/// be turned into one another. That matters here because the ID seed is not a
/// secret in practice: book IDs are `xxh3(seed, title)`, they appear in URLs,
/// and xxh3 is not a cryptographic hash — anyone who can invert enough IDs
/// learns the seed. Passing the secret's bytes straight through would make that
/// leak eight bytes of cookie-signing material; behind a hash it leaks nothing.
const SESSION_KEY_DOMAIN: &[u8] = b"comics/session-key/v1";
const ID_SEED_DOMAIN: &[u8] = b"comics/id-seed/v1";

/// The one secret comics is configured with (`COMICS_SECRET`).
///
/// Both the cookie signing key and the salt for hashed book/page IDs are derived
/// from it, so a deployment has a single value to generate, store and rotate.
/// Rotating it is a global logout *and* changes every book and page URL.
#[derive(Clone)]
pub struct Secret([u8; SECRET_BYTES]);

impl Secret {
    /// A fresh random secret, used when none is configured.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// The key that signs session cookies.
    ///
    /// SHA-512 is what makes this a one-liner: its output is exactly the 64
    /// bytes `Key` wants. comics does not enable the `cookie` crate's
    /// `key-expansion` feature (which would pull in `hkdf` for
    /// `Key::derive_from`), and a hash with a domain separator is all the
    /// stretching a 512-bit secret needs.
    pub fn session_key(&self) -> Key {
        let mut hasher = Sha512::new();
        hasher.update(SESSION_KEY_DOMAIN);
        hasher.update(self.0);
        Key::try_from(&hasher.finalize()[..]).expect("SHA-512 produces exactly 64 bytes")
    }

    /// The seed salting hashed book and page IDs.
    pub fn id_seed(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(ID_SEED_DOMAIN);
        hasher.update(self.0);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(bytes)
    }
}

impl FromStr for Secret {
    type Err = anyhow::Error;

    /// Decode 128 hex characters (64 bytes). Hex is decoded by hand: no
    /// dependency is worth a five-line loop.
    fn from_str(raw: &str) -> anyhow::Result<Self> {
        let raw = raw.trim();
        if raw.len() != SECRET_HEX_LEN {
            bail!(
                "secret must be {SECRET_HEX_LEN} hex characters ({SECRET_BYTES} bytes), got {}; \
                 generate one with `openssl rand -hex {SECRET_BYTES}`",
                raw.len()
            );
        }
        let mut bytes = [0u8; SECRET_BYTES];
        for (out, pair) in bytes.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
            let hex = std::str::from_utf8(pair).unwrap_or("");
            *out = u8::from_str_radix(hex, 16).context(
                "secret must be hex characters only; \
                 generate one with `openssl rand -hex 64`",
            )?;
        }
        Ok(Self(bytes))
    }
}

/// Redacted: `Opts` derives `Debug` and is handed to `debug!` in `main`, and
/// the secret must not ride along if that output ever reaches a log.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
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

    fn parse(raw: &str) -> anyhow::Result<Secret> {
        raw.parse()
    }

    #[test]
    fn accepts_128_hex_chars() {
        assert!(parse(VALID).is_ok());
        assert!(parse(&format!("  {VALID}\n")).is_ok());
        assert!(parse(&VALID.to_uppercase()).is_ok());
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        let err = parse("abcd").unwrap_err().to_string();
        assert!(err.contains("128 hex characters"), "{err}");

        let err = parse(&VALID[..127]).unwrap_err().to_string();
        assert!(err.contains("got 127"), "{err}");

        let non_hex = format!("zz{}", &VALID[2..]);
        let err = parse(&non_hex).unwrap_err().to_string();
        assert!(err.contains("hex characters only"), "{err}");
    }

    /// The whole point of a configured secret: the same string must always
    /// yield the same signing material and the same IDs, across restarts and
    /// across replicas.
    #[test]
    fn derivation_is_deterministic() {
        let a = parse(VALID).unwrap();
        let b = parse(VALID).unwrap();
        assert_eq!(a.session_key().signing(), b.session_key().signing());
        assert_eq!(a.id_seed(), b.id_seed());
    }

    #[test]
    fn different_secrets_derive_different_values() {
        let a = parse(VALID).unwrap();
        let b = parse(&format!("ff{}", &VALID[2..])).unwrap();
        assert_ne!(a.session_key().signing(), b.session_key().signing());
        assert_ne!(a.id_seed(), b.id_seed());
    }

    /// Domain separation: the seed must not be a window onto the signing key.
    #[test]
    fn the_id_seed_is_not_a_prefix_of_the_signing_key() {
        let secret = parse(VALID).unwrap();
        let seed = secret.id_seed().to_be_bytes();
        let key = secret.session_key();
        assert!(
            !key.signing().windows(seed.len()).any(|w| w == seed),
            "the id seed appears verbatim in the signing key"
        );
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let rendered = format!("{:?}", parse(VALID).unwrap());
        assert_eq!("Secret([redacted])", rendered);
        assert!(!rendered.contains("0123"));
    }

    #[test]
    fn generate_produces_distinct_secrets() {
        let a = Secret::generate();
        let b = Secret::generate();
        assert_ne!(a.session_key().signing(), b.session_key().signing());
    }

    #[test]
    fn hex_lower_pads_each_byte() {
        assert_eq!("000fff", hex_lower(&[0x00, 0x0f, 0xff]));
        assert_eq!("", hex_lower(&[]));
    }
}
