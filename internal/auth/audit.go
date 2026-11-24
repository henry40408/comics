package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const (
	auditSaltBytes = 16
	// fingerprintBytes is ample to correlate one process's session events.
	fingerprintBytes = 8
)

// AuditSalt is a per-process random salt, never logged, for hashing session
// identifiers into the audit log: OWASP forbids logging them in cleartext.
type AuditSalt struct {
	salt [auditSaltBytes]byte
}

// NewAuditSalt draws a fresh salt.
func NewAuditSalt() *AuditSalt {
	salt := &AuditSalt{}
	_, _ = rand.Read(salt.salt[:])
	return salt
}

// Fingerprint is the first fingerprintBytes of SHA-256(salt || nonce),
// hex-encoded. The salt is secret, so the logged value cannot be matched to a
// session identifier without it.
func (a *AuditSalt) Fingerprint(nonce string) string {
	hasher := sha256.New()
	hasher.Write(a.salt[:])
	hasher.Write([]byte(nonce))
	return hex.EncodeToString(hasher.Sum(nil)[:fingerprintBytes])
}
