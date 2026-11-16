package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/auth"
)

func TestHashPasswordAcceptsAPasswordAtTheLimit(t *testing.T) {
	if err := auth.EnsurePasswordFits(strings.Repeat("x", auth.MaxPasswordBytes)); err != nil {
		t.Fatal(err)
	}
	cjk := strings.Repeat("密", 100)
	if len(cjk) != 300 {
		t.Fatalf("len = %d", len(cjk))
	}
	hash, err := auth.HashPassword(cjk)
	if err != nil || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash = %q, err = %v", hash, err)
	}
}

func TestHashPasswordRecordsTheOWASPParameters(t *testing.T) {
	hash, err := auth.HashPassword("a-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %q", hash)
	}
}

func TestHashPasswordRefusesAnOverLongPassword(t *testing.T) {
	long := strings.Repeat("x", auth.MaxPasswordBytes+1)
	err := auth.EnsurePasswordFits(long)
	if err == nil || !strings.Contains(err.Error(), "1025 bytes") {
		t.Fatalf("err = %v", err)
	}
	if _, err := auth.HashPassword(long); err == nil {
		t.Fatal("an over-long password was hashed")
	}
}

func TestHashPasswordRefusesAnEmptyPassword(t *testing.T) {
	if auth.EnsurePasswordFits("") == nil {
		t.Fatal("empty password fits")
	}
	if _, err := auth.HashPassword(""); err == nil {
		t.Fatal("empty password was hashed")
	}
}

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
	hash, err := auth.HashPassword(short)
	if err != nil || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash = %q, err = %v", hash, err)
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

func TestALongEnoughPasswordEmitsOnlyTheHash(t *testing.T) {
	var out, errw bytes.Buffer
	if err := emitPasswordHash(strings.Repeat("x", auth.MinPasswordChars), &out, &errw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "$argon2id$") {
		t.Fatalf("stdout = %q", out.String())
	}
	if errw.Len() != 0 {
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

func TestALongEnoughPasswordDrawsNoWarning(t *testing.T) {
	for _, n := range []int{auth.MinPasswordChars, auth.MinPasswordChars + 40} {
		if warning, ok := passwordStrengthWarning(strings.Repeat("x", n)); ok {
			t.Errorf("%d characters drew %q", n, warning)
		}
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
