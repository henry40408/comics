package models

import (
	"strings"
	"testing"
)

func TestHashStringDeterministic(t *testing.T) {
	first, second := HashString(42, "test"), HashString(42, "test")
	if first != second {
		t.Fatal("same input hashed differently")
	}
}

func TestHashStringDifferentSeeds(t *testing.T) {
	if HashString(1, "test") == HashString(2, "test") {
		t.Fatal("seed has no effect")
	}
}

func TestHashStringDifferentInputs(t *testing.T) {
	if HashString(42, "hello") == HashString(42, "world") {
		t.Fatal("input has no effect")
	}
}

// Known answers from the Rust implementation. The second has 15 digits, which
// proves the hex is not zero-padded to 16.
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

func TestHashStringIsLowercaseHexWithoutPadding(t *testing.T) {
	for seed := uint64(0); seed < 2000; seed++ {
		got := HashString(seed, "x")
		if got == "" || got != strings.ToLower(got) || strings.Trim(got, "0123456789abcdef") != "" {
			t.Fatalf("seed %d: %q is not lowercase hex", seed, got)
		}
		if len(got) > 16 {
			t.Fatalf("seed %d: %q is longer than 16 digits", seed, got)
		}
	}
}
