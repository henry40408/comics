package auth

import (
	"strings"
	"testing"
)

const auditNonce = "0123456789abcdef0123456789abcdef"

func TestFingerprintIsStableForTheSameNonce(t *testing.T) {
	salt := NewAuditSalt()
	if salt.Fingerprint(auditNonce) != salt.Fingerprint(auditNonce) {
		t.Fatal("fingerprint changed between calls")
	}
	if got := len(salt.Fingerprint(auditNonce)); got != fingerprintBytes*2 {
		t.Fatalf("len = %d, want %d", got, fingerprintBytes*2)
	}
}

func TestFingerprintDiffersForDifferentNonces(t *testing.T) {
	salt := NewAuditSalt()
	other := "f" + auditNonce[1:]
	if salt.Fingerprint(auditNonce) == salt.Fingerprint(other) {
		t.Fatal("different nonces share a fingerprint")
	}
}

func TestFingerprintDiffersAcrossSalts(t *testing.T) {
	a, b := NewAuditSalt(), NewAuditSalt()
	if a.Fingerprint(auditNonce) == b.Fingerprint(auditNonce) {
		t.Fatal("different salts share a fingerprint")
	}
}

func TestFingerprintDoesNotContainTheNonce(t *testing.T) {
	fingerprint := NewAuditSalt().Fingerprint(auditNonce)
	for i := 0; i+8 <= len(auditNonce); i++ {
		chunk := auditNonce[i : i+8]
		if strings.Contains(fingerprint, chunk) {
			t.Errorf("%s contains %s", fingerprint, chunk)
		}
	}
}
