package models

import "testing"

// Pinned vectors. The second has 15 digits, which proves the hex is not
// zero-padded to 16.
func TestHashStringKnownAnswers(t *testing.T) {
	cases := []struct {
		seed uint64
		in   string
		want string
	}{
		{0, "", "af5570f5a1810b7a"},
		{^uint64(0), "abcd", "cc791ccbcc2f72b7"},
		{1, "a", "3b196fd4907bedf5"},
	}
	for _, c := range cases {
		if got := HashString(c.seed, c.in); got != c.want {
			t.Errorf("HashString(%d, %q) = %q, want %q", c.seed, c.in, got, c.want)
		}
	}
}
