use std::{fmt, str::FromStr};

use anyhow::{Context as _, bail};
use cookie::Key;
use sha2::{Digest as _, Sha256, Sha512};

/// Sized to what it protects: `cookie`'s signed jar is HMAC-SHA256 keyed with
/// 32 bytes, so 256 bits of input entropy saturates it. (`cookie::Key` holds 64,
/// but the second half is the *encryption* key for private jars, which comics
/// never builds.) Longer secrets are hashed just the same, and buy nothing.
const SECRET_MIN_BYTES: usize = 32;

const SECRET_MIN_HEX_LEN: usize = SECRET_MIN_BYTES * 2;

/// Domain separators, so the values derived from the secret cannot be turned
/// into one another. That matters because the ID seed is not secret in practice:
/// book IDs are `xxh3(seed, title)`, they appear in URLs, and xxh3 is not
/// cryptographic — invert enough IDs and you have the seed. Passing the secret's
/// bytes straight through would leak eight bytes of cookie-signing material.
const SESSION_KEY_DOMAIN: &[u8] = b"comics/session-key/v1";
const ID_SEED_DOMAIN: &[u8] = b"comics/id-seed/v1";

/// The one secret comics is configured with (`COMICS_SECRET`).
///
/// Both the cookie signing key and the salt for hashed book/page IDs are derived
/// from it, so a deployment has a single value to generate, store and rotate.
/// Rotating it is a global logout *and* changes every book and page URL.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Used when none is configured.
    pub fn generate() -> Self {
        Self(rand::random::<[u8; SECRET_MIN_BYTES]>().to_vec())
    }

    /// SHA-512 outputs exactly the 64 bytes `Key` wants, so comics leaves the
    /// `cookie` crate's `key-expansion` feature off (it would pull in `hkdf` for
    /// `Key::derive_from`): a domain-separated hash is all a 512-bit secret
    /// needs.
    pub fn session_key(&self) -> Key {
        let mut hasher = Sha512::new();
        hasher.update(SESSION_KEY_DOMAIN);
        hasher.update(&self.0);
        Key::try_from(&hasher.finalize()[..]).expect("SHA-512 produces exactly 64 bytes")
    }

    /// The seed salting hashed book and page IDs.
    pub fn id_seed(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(ID_SEED_DOMAIN);
        hasher.update(&self.0);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(bytes)
    }
}

impl FromStr for Secret {
    type Err = anyhow::Error;

    /// Decode at least 64 hex characters (32 bytes). A *minimum*, not a fixed
    /// length: the value is hashed, so the floor only keeps someone from
    /// configuring a guessable string, and hex is required as evidence the value
    /// came out of a CSPRNG rather than off a keyboard.
    fn from_str(raw: &str) -> anyhow::Result<Self> {
        let raw = raw.trim();
        if raw.len() < SECRET_MIN_HEX_LEN {
            bail!(
                "secret must be at least {SECRET_MIN_HEX_LEN} hex characters \
                 ({SECRET_MIN_BYTES} bytes), got {}; \
                 generate one with `openssl rand -hex {SECRET_MIN_BYTES}`",
                raw.len()
            );
        }
        if !raw.len().is_multiple_of(2) {
            bail!(
                "secret must have an even number of hex characters, got {}; \
                 generate one with `openssl rand -hex {SECRET_MIN_BYTES}`",
                raw.len()
            );
        }
        let mut bytes = Vec::with_capacity(raw.len() / 2);
        for pair in raw.as_bytes().chunks_exact(2) {
            let hex = std::str::from_utf8(pair).unwrap_or("");
            bytes.push(u8::from_str_radix(hex, 16).context(
                "secret must be hex characters only; \
                 generate one with `openssl rand -hex 32`",
            )?);
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

/// Here rather than from a crate: not worth a dependency.
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

    /// 64 hex characters — what `openssl rand -hex 32` emits, and the
    /// documented size.
    const VALID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The 128-character form the secret used to require. Still accepted: the
    /// length is a floor, not a fixed size.
    const LONGER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                          fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn parse(raw: &str) -> anyhow::Result<Secret> {
        raw.parse()
    }

    #[test]
    fn accepts_64_hex_chars_and_longer() {
        assert!(parse(VALID).is_ok());
        assert!(parse(LONGER).is_ok());
        assert!(parse(&format!("  {VALID}\n")).is_ok());
        assert!(parse(&VALID.to_uppercase()).is_ok());
    }

    #[test]
    fn rejects_short_odd_and_non_hex() {
        let err = parse("abcd").unwrap_err().to_string();
        assert!(err.contains("at least 64 hex characters"), "{err}");

        let err = parse(&VALID[..63]).unwrap_err().to_string();
        assert!(err.contains("got 63"), "{err}");

        let odd = format!("{VALID}a");
        let err = parse(&odd).unwrap_err().to_string();
        assert!(err.contains("even number"), "{err}");

        let non_hex = format!("zz{}", &VALID[2..]);
        let err = parse(&non_hex).unwrap_err().to_string();
        assert!(err.contains("hex characters only"), "{err}");
    }

    /// A longer secret is a different secret, not the same one padded.
    #[test]
    fn length_is_part_of_the_secret() {
        let short = parse(VALID).unwrap();
        let long = parse(LONGER).unwrap();
        assert_ne!(
            short.session_key().signing(),
            long.session_key().signing(),
            "a prefix must not derive the same key as the whole"
        );
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
