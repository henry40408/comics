// Package models scans the data directory into books and pages.
package models

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// idBytes is how much of the SHA-256 digest an ID keeps: 8 bytes, so an ID is
// always 16 lowercase hex characters.
const idBytes = 8

// HashString is the first 8 bytes of SHA-256(seed as 8 big-endian bytes || s),
// as 16 lowercase hex characters. Book and page IDs in URLs come from it, so
// changing the algorithm or the length breaks every link. SHA-256 because the
// module already uses it, so IDs need no extra vendored dependency.
func HashString(seed uint64, s string) string {
	var seedBytes [8]byte
	binary.BigEndian.PutUint64(seedBytes[:], seed)
	hasher := sha256.New()
	_, _ = hasher.Write(seedBytes[:]) // hash.Hash.Write never returns an error
	_, _ = hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil)[:idBytes])
}
