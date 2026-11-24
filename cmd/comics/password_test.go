package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/auth"
)

func TestAShortPasswordIsWarnedAboutButStillHashed(t *testing.T) {
	short := strings.Repeat("x", auth.MinPasswordChars-1)
	warning, ok := passwordStrengthWarning(short)
	if !ok {
		t.Fatal("no warning")
	}
	for _, want := range []string{"14 characters", "15", "not a refusal"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning %q lacks %q", warning, want)
		}
	}
}

// `$(comics hash-password)` captures stdout, so it must hold the hash alone.
func TestTheWarningNeverReachesStdout(t *testing.T) {
	var out, errw bytes.Buffer
	if err := emitPasswordHash(strings.Repeat("x", auth.MinPasswordChars-1), &out, &errw); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 1 {
		t.Fatalf("stdout has %d lines: %q", lines, out.String())
	}
	if !strings.HasPrefix(out.String(), "$argon2id$") || strings.Contains(out.String(), "warning") {
		t.Fatalf("stdout = %q", out.String())
	}
	if !strings.Contains(errw.String(), "warning:") {
		t.Fatalf("stderr = %q", errw.String())
	}
}

func TestARefusedPasswordWritesNothing(t *testing.T) {
	var out, errw bytes.Buffer
	if err := emitPasswordHash("", &out, &errw); err == nil {
		t.Fatal("an empty password was emitted")
	}
	if out.Len() != 0 || errw.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", out.String(), errw.String())
	}
}

func TestTheStrengthFloorCountsCharactersNotBytes(t *testing.T) {
	fifteen := strings.Repeat("密", auth.MinPasswordChars)
	if len(fifteen) != 45 {
		t.Fatalf("len = %d", len(fifteen))
	}
	if _, ok := passwordStrengthWarning(fifteen); ok {
		t.Error("fifteen characters drew a warning")
	}
	five := strings.Repeat("密", 5)
	if _, ok := passwordStrengthWarning(five); !ok {
		t.Error("five characters (fifteen bytes) drew no warning")
	}
}

func TestPasswordLinesToleratesCRLFAndAMissingFinalNewline(t *testing.T) {
	password, confirmation, err := readPasswordLines(strings.NewReader("one\r\ntwo"))
	if err != nil || password != "one" || confirmation != "two" {
		t.Fatalf("got %q, %q, %v", password, confirmation, err)
	}
	if _, _, err := readPasswordLines(strings.NewReader("only-one\n")); err == nil {
		t.Fatal("a missing confirmation was accepted")
	}
}
