// Package secret holds the one secret comics is configured with
// (COMICS_SECRET) and derives the cookie signing key and the ID seed from it.
//
// Rotating the secret logs everyone out and changes every book and page URL.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The signed cookie is HMAC-SHA256 with a 32-byte key, so 256 bits saturates
// it. Longer secrets buy nothing.
const (
	minBytes  = 32
	minHexLen = minBytes * 2
)

// Domain separators. The ID seed is effectively public (IDs are xxh3(seed, ...)
// in URLs and xxh3 is invertible with enough samples), so it must not share
// bytes with the signing key.
const (
	sessionKeyDomain = "comics/session-key/v1"
	idSeedDomain     = "comics/id-seed/v1"
)

// Secret is the configured secret. Its printed forms are redacted.
type Secret struct {
	raw []byte
}

// Generate returns a random secret, for when none is configured.
func Generate() Secret {
	raw := make([]byte, minBytes)
	if _, err := rand.Read(raw); err != nil {
		panic("secret: system randomness unavailable: " + err.Error())
	}
	return Secret{raw: raw}
}

// Parse decodes at least 64 hex characters (32 bytes). Hex is required as a
// hint that the value came from a CSPRNG rather than a keyboard.
func Parse(text string) (Secret, error) {
	text = strings.TrimSpace(text)
	if len(text) < minHexLen {
		return Secret{}, fmt.Errorf("secret must be at least %d hex characters (%d bytes), got %d; "+
			"generate one with `openssl rand -hex %d`", minHexLen, minBytes, len(text), minBytes)
	}
	if len(text)%2 != 0 {
		return Secret{}, fmt.Errorf("secret must have an even number of hex characters, got %d; "+
			"generate one with `openssl rand -hex %d`", len(text), minBytes)
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return Secret{}, errors.New("secret must be hex characters only; " +
			"generate one with `openssl rand -hex 32`")
	}
	return Secret{raw: raw}, nil
}

// SessionKey is SHA-512 over the domain and the secret: exactly the 64 bytes
// of a cookie key. The signing half is the first 32 bytes.
func (s Secret) SessionKey() [64]byte {
	s.mustBeSet()
	return sha512.Sum512(append([]byte(sessionKeyDomain), s.raw...))
}

// IDSeed is the seed salting hashed book and page IDs.
func (s Secret) IDSeed() uint64 {
	s.mustBeSet()
	digest := sha256.Sum256(append([]byte(idSeedDomain), s.raw...))
	return binary.BigEndian.Uint64(digest[:8])
}

// mustBeSet stops a zero Secret from deriving a key anyone can compute.
func (s Secret) mustBeSet() {
	if len(s.raw) == 0 {
		panic("secret: zero-value Secret used; build one with Parse or Generate")
	}
}

// String redacts the secret, so logging a config cannot leak it.
func (Secret) String() string { return "Secret([redacted])" }

// GoString redacts the secret for %#v.
func (Secret) GoString() string { return "Secret([redacted])" }

func HexLower(data []byte) string { return hex.EncodeToString(data) }
