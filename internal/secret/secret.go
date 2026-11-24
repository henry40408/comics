// Package secret holds the one secret comics is configured with
// (COMICS_SECRET) and derives the ID seed from it.
//
// Rotating the secret changes every book and page URL, and nothing else.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The secret feeds one 64-bit seed (IDSeed), so 256 bits saturates it. Longer
// secrets buy nothing.
const (
	minBytes  = 32
	minHexLen = minBytes * 2
)

// idSeedDomain prefixes the secret before hashing. The ID seed is effectively
// public (IDs are xxh3(seed, ...) in URLs and xxh3 is invertible with enough
// samples), so the secret is hashed rather than used as the seed itself.
const idSeedDomain = "comics/id-seed/v1"

// Secret is the configured secret. Its printed forms are redacted.
type Secret struct {
	raw []byte
}

// Generate returns a random secret, for when none is configured.
func Generate() Secret {
	raw := make([]byte, minBytes)
	_, _ = rand.Read(raw) // crypto/rand.Read never returns an error
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

// IDSeed is the seed salting hashed book and page IDs.
func (s Secret) IDSeed() uint64 {
	s.mustBeSet()
	digest := sha256.Sum256(append([]byte(idSeedDomain), s.raw...))
	return binary.BigEndian.Uint64(digest[:8])
}

// mustBeSet stops a zero Secret from deriving a seed anyone can compute.
func (s Secret) mustBeSet() {
	if len(s.raw) == 0 {
		panic("secret: zero-value Secret used; build one with Parse or Generate")
	}
}

// String redacts the secret, so logging a config cannot leak it.
func (Secret) String() string { return "Secret([redacted])" }

// GoString redacts the secret for %#v.
func (Secret) GoString() string { return "Secret([redacted])" }
