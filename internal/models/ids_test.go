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
		{0, "", "2d06800538d394c2"},
		{^uint64(0), "abcd", "1e169947214dfef"},
		{1, "a", "d2f6d0996f37a720"},
	}
	for _, c := range cases {
		if got := HashString(c.seed, c.in); got != c.want {
			t.Errorf("HashString(%d, %q) = %q, want %q", c.seed, c.in, got, c.want)
		}
	}
}
