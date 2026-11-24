package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/auth"
)

// stdinFile is a regular file, so term.IsTerminal is false for it.
func stdinFile(t *testing.T, content string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestHashPasswordCommandHashesAMatchingPair(t *testing.T) {
	var out, errw bytes.Buffer
	stdin := stdinFile(t, "a-long-enough-password\na-long-enough-password\n")
	if err := hashPasswordCommand(stdin, &out, &errw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "$argon2id$") || errw.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", out.String(), errw.String())
	}
}

func TestHashPasswordCommandRefusesAMismatch(t *testing.T) {
	var out, errw bytes.Buffer
	err := hashPasswordCommand(stdinFile(t, "one\ntwo\n"), &out, &errw)
	if err == nil || err.Error() != "Password mismatch" {
		t.Fatalf("err = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestHashPasswordCommandRefusesAnEmptyPassword(t *testing.T) {
	var out, errw bytes.Buffer
	if err := hashPasswordCommand(stdinFile(t, "\n\n"), &out, &errw); err == nil {
		t.Fatal("an empty password was hashed")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestHashPasswordCommandReportsMissingInput(t *testing.T) {
	var out, errw bytes.Buffer
	if err := hashPasswordCommand(stdinFile(t, ""), &out, &errw); err == nil {
		t.Fatal("missing input was accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestEmitPasswordHashReportsAFailedWrite(t *testing.T) {
	long := strings.Repeat("x", auth.MinPasswordChars)
	if err := emitPasswordHash(long, failingWriter{}, io.Discard); err == nil {
		t.Error("a failed stdout write was ignored")
	}
	if err := emitPasswordHash("short", io.Discard, failingWriter{}); err == nil {
		t.Error("a failed warning write was ignored")
	}
}
