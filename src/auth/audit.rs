use sha2::{Digest as _, Sha256};

use crate::secret::hex_lower;

const SALT_BYTES: usize = 16;
/// Ample to correlate one process's session events.
const FINGERPRINT_BYTES: usize = 8;

/// Per-process random salt, never logged, for hashing session identifiers
/// into the audit log — OWASP forbids logging them in cleartext.
pub struct SessionAuditSalt([u8; SALT_BYTES]);

impl SessionAuditSalt {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// First `FINGERPRINT_BYTES` of `SHA-256(salt || nonce)`, hex-encoded.
    /// Not `xxh3` like content IDs: that is not a cryptographic hash.
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
