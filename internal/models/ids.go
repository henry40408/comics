// Package models scans the data directory into books and pages.
package models

import (
	"strconv"

	"github.com/zeebo/xxh3"
)

// HashString is the seeded XXH3-64 of s as lowercase hex, not zero-padded.
// Book and page IDs in URLs come from it, so changing it breaks every link.
func HashString(seed uint64, s string) string {
	return strconv.FormatUint(xxh3.HashStringSeed(s, seed), 16)
}
