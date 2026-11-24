package models

import (
	"strings"
	"testing"
)

// Pinned vectors, cross-checked with shasum. The third starts with a zero
// digit, which proves the hex is not trimmed below 16 characters. Every answer
// is 16 lowercase hex characters.
func TestHashStringKnownAnswers(t *testing.T) {
	cases := []struct {
		seed uint64
		in   string
		want string
	}{
		{0, "", "af5570f5a1810b7a"},
		{^uint64(0), "abcd", "cc791ccbcc2f72b7"},
		{0, "z", "0fa89985dd70c09d"},
		{1, "a", "3b196fd4907bedf5"},
	}
	for _, c := range cases {
		got := HashString(c.seed, c.in)
		if got != c.want {
			t.Errorf("HashString(%d, %q) = %q, want %q", c.seed, c.in, got, c.want)
		}
		if len(got) != 16 || strings.Trim(got, "0123456789abcdef") != "" {
			t.Errorf("HashString(%d, %q) = %q, want 16 lowercase hex characters", c.seed, c.in, got)
		}
	}
}
