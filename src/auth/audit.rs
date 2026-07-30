use sha2::{Digest as _, Sha256};

use crate::secret::hex_lower;

const SALT_BYTES: usize = 16;
/// Eight bytes are ample to correlate the handful of session events one process
/// emits, and truncation removes any temptation to treat the value as
/// reversible.
const FINGERPRINT_BYTES: usize = 8;

/// Per-process salt for session-identifier hashing.
///
/// Random per start and never logged: it only needs to correlate events within
/// one process lifetime. OWASP's *Logging Sessions Life Cycle* is explicit that
/// the session ID must not be logged in cleartext and that a salted hash should
/// be logged instead.
pub struct SessionAuditSalt([u8; SALT_BYTES]);

impl SessionAuditSalt {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// First [`FINGERPRINT_BYTES`] of `SHA-256(salt || nonce)`, hex-encoded.
    ///
    /// SHA-256 rather than the `xxh3` used for content IDs: xxh3 is not a
    /// cryptographic hash, so a salted xxh3 would not resist the recovery the
    /// OWASP guidance is guarding against.
    pub fn fingerprint(&self, nonce: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(nonce.as_bytes());
        hex_lower(&hasher.finalize()[..FINGERPRINT_BYTES])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn fingerprint_is_stable_for_the_same_nonce() {
        let salt = SessionAuditSalt::generate();
        assert_eq!(salt.fingerprint(NONCE), salt.fingerprint(NONCE));
        assert_eq!(FINGERPRINT_BYTES * 2, salt.fingerprint(NONCE).len());
    }

    #[test]
    fn fingerprint_differs_for_different_nonces() {
        let salt = SessionAuditSalt::generate();
        let other = format!("f{}", &NONCE[1..]);
        assert_ne!(salt.fingerprint(NONCE), salt.fingerprint(&other));
    }

    #[test]
    fn fingerprint_differs_across_salts() {
        let a = SessionAuditSalt::generate();
        let b = SessionAuditSalt::generate();
        assert_ne!(a.fingerprint(NONCE), b.fingerprint(NONCE));
    }

    /// The whole point of the hash: the logged value must not carry the
    /// identifier it stands for.
    #[test]
    fn fingerprint_does_not_contain_the_nonce() {
        let salt = SessionAuditSalt::generate();
        let fingerprint = salt.fingerprint(NONCE);
        for window in NONCE.as_bytes().windows(8) {
            let chunk = std::str::from_utf8(window).unwrap();
            assert!(
                !fingerprint.contains(chunk),
                "{fingerprint} contains {chunk}"
            );
        }
    }
}
