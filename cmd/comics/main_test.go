package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// logWait bounds a wedged binary rather than pacing the tests, which finish in
// milliseconds; generous so a loaded machine never reaches it.
const logWait = 30 * time.Second

// fixturesDir is relative to this package's directory, where go test runs.
const fixturesDir = "../../fixtures/data"

var comicsBinary string

// coverDir is where a `-cover` binary writes its profile; empty means the
// binary is built plain. `go test -coverprofile` does not see the exec'd binary.
var coverDir = os.Getenv("COMICS_COVERDIR")

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

// buildAndRun builds the binary once, so every test drives the real thing.
func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "comics-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	comicsBinary = filepath.Join(dir, "comics")
	buildArgs := []string{"build", "-mod=vendor"}
	if coverDir != "" {
		if err := os.MkdirAll(coverDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		buildArgs = append(buildArgs, "-cover", "-coverpkg=github.com/henry40408/comics/...")
	}
	build := exec.Command("go", append(buildArgs, "-o", comicsBinary, ".")...)
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// cleanEnv is the environment of a server under test.
func cleanEnv() []string {
	return []string{"COMICS_SECRET=" + testSecret}
}

func command(ctx context.Context, env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, comicsBinary, args...)
	cmd.Env = env
	if coverDir != "" {
		cmd.Env = append(append([]string(nil), env...), "GOCOVERDIR="+coverDir)
	}
	return cmd
}

func runToCompletion(t *testing.T, env []string, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), logWait)
	defer cancel()
	cmd := command(ctx, env, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errw bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errw
	err := cmd.Run()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("failed to run comics: %v", err)
	}
	return out.String(), errw.String(), cmd.ProcessState.ExitCode()
}

func TestList(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, nil, "", "--data-dir", fixturesDir, "list")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := regexp.MustCompile(`^Pepper and Carrot 01 - Potion of Flight \(3P\)\n` +
		`Pepper and Carrot 02 - Rainbow Potions \(5P\)\n` +
		`2 book\(s\), 8 page\(s\), scanned in \S+\n$`)
	if !want.MatchString(stdout) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestVersionFlag(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, nil, "", "--version")
	if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "comics ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// runningServer is a comics process whose stdout is read line by line.
type runningServer struct {
	cmd    *exec.Cmd
	lines  chan string
	stderr *bytes.Buffer
	logs   []string
}

func startServer(t *testing.T, env []string, args ...string) *runningServer {
	t.Helper()
	args = append([]string{"--bind", "127.0.0.1:0"}, args...)
	cmd := command(context.Background(), env, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server := &runningServer{cmd: cmd, lines: make(chan string, 64), stderr: &bytes.Buffer{}}
	cmd.Stderr = server.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start comics: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			server.lines <- scanner.Text()
		}
		close(server.lines)
	}()
	return server
}

// waitFor reads log lines until one contains marker, recording every line.
func (s *runningServer) waitFor(t *testing.T, marker string) {
	t.Helper()
	timeout := time.After(logWait)
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				t.Fatalf("stdout closed before %q; logs:\n%s", marker, s.joined())
			}
			s.logs = append(s.logs, line)
			if strings.Contains(line, marker) {
				return
			}
		case <-timeout:
			t.Fatalf("%q was never logged; logs:\n%s", marker, s.joined())
		}
	}
}

// drain collects the remaining log lines until stdout closes.
func (s *runningServer) drain(t *testing.T) {
	t.Helper()
	timeout := time.After(logWait)
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				return
			}
			s.logs = append(s.logs, line)
		case <-timeout:
			t.Fatalf("the server never closed stdout; logs:\n%s", s.joined())
		}
	}
}

func (s *runningServer) joined() string { return strings.Join(s.logs, "\n") }

func (s *runningServer) wait(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		// A non-zero exit is expected here (ExitCode is read below); anything else
		// means Wait itself failed.
		var exited *exec.ExitError
		if err != nil && !errors.As(err, &exited) {
			t.Fatalf("waiting for the server: %v", err)
		}
	case <-time.After(logWait):
		t.Fatalf("the server never exited; logs:\n%s", s.joined())
	}
	return s.cmd.ProcessState.ExitCode()
}

func (s *runningServer) terminate(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
}

// assertLogLines checks each line against `msg=<message>` plus the given
// key=value fragments, in order, ignoring the handler's time and level layout.
func assertLogLines(t *testing.T, logs []string, want [][]string) {
	t.Helper()
	if len(logs) != len(want) {
		t.Fatalf("got %d log lines, want %d:\n%s", len(logs), len(want), strings.Join(logs, "\n"))
	}
	for i, fragments := range want {
		for _, fragment := range fragments {
			if !strings.Contains(logs[i], fragment) {
				t.Errorf("line %d %q lacks %q", i, logs[i], fragment)
			}
		}
	}
}

func TestInitialScanFinished(t *testing.T) {
	server := startServer(t, cleanEnv(), "--data-dir", fixturesDir)
	server.waitFor(t, "initial scan finished")
	assertLogLines(t, server.logs, [][]string{
		{"level=WARN", `msg="no authorization enabled, server is publicly accessible"`},
		{"level=INFO", `msg="server started"`, "addr=127.0.0.1:", "version="},
		{"level=INFO", `msg="initial scan finished"`, "books=2", "pages=8", "duration_ms="},
	})
	_ = server.cmd.Process.Kill()
	server.drain(t)
	// Reading stderr is only safe once the process has been reaped.
	server.wait(t)
	if server.stderr.Len() != 0 {
		t.Fatalf("stderr = %q", server.stderr.String())
	}
}

// runUntilSIGTERM sends SIGTERM once a log line contains marker and returns the
// server after asserting a clean exit.
func runUntilSIGTERM(t *testing.T, marker string) *runningServer {
	t.Helper()
	server := startServer(t, cleanEnv(), "--data-dir", fixturesDir)
	server.waitFor(t, marker)
	server.terminate(t)
	server.drain(t)
	if code := server.wait(t); code != 0 {
		t.Fatalf("exited with %d; logs:\n%s", code, server.joined())
	}
	if server.stderr.Len() != 0 {
		t.Fatalf("stderr = %q", server.stderr.String())
	}
	return server
}

// SIGTERM is what a container runtime sends; the server must drain and exit 0
// rather than die from the signal.
func TestSIGTERMShutsDownGracefully(t *testing.T) {
	server := runUntilSIGTERM(t, "initial scan finished")
	assertLogLines(t, server.logs, [][]string{
		{"no authorization enabled"},
		{`msg="server started"`, "addr=127.0.0.1:"},
		{`msg="initial scan finished"`, "books=2", "pages=8"},
		{"level=INFO", `msg="received shutdown signal"`},
	})
}

// A signal that lands right after startup, before the scan reports, must
// still shut down gracefully.
func TestSIGTERMRightAfterStartupShutsDownGracefully(t *testing.T) {
	server := runUntilSIGTERM(t, "server started")
	if !strings.Contains(server.joined(), "received shutdown signal") {
		t.Fatalf("unexpected logs:\n%s", server.joined())
	}
}

func TestLegacyEnvVarAbortsStartup(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, []string{"BIND=127.0.0.1:0"}, "", "--data-dir", fixturesDir)
	want := "Error: these environment variables no longer exist; rename (or unset) them to continue:\n" +
		"  BIND -> COMICS_BIND\n"
	if code != 1 || stdout != "" || stderr != want {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestFoldedEnvVarsAbortStartup(t *testing.T) {
	env := []string{"COMICS_SEED=1", "COMICS_SESSION_KEY=0123456789abcdef"}
	stdout, stderr, code := runToCompletion(t, env, "", "--data-dir", fixturesDir)
	want := "Error: these environment variables no longer exist; rename (or unset) them to continue:\n" +
		"  COMICS_SEED -> COMICS_SECRET\n" +
		"  COMICS_SESSION_KEY -> COMICS_SECRET\n"
	if code != 1 || stdout != "" || stderr != want {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestRustLogIsARetiredVariable(t *testing.T) {
	_, stderr, code := runToCompletion(t, []string{"RUST_LOG=debug"}, "", "--data-dir", fixturesDir)
	if code != 1 || !strings.Contains(stderr, "  RUST_LOG -> COMICS_LOG_LEVEL\n") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestInvalidOptionExitsWithUsageCode(t *testing.T) {
	env := []string{"COMICS_SECRET=abcd"}
	stdout, stderr, code := runToCompletion(t, env, "", "--data-dir", fixturesDir)
	if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "Error: ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestAMalformedPasswordHashStopsTheServer(t *testing.T) {
	env := append(cleanEnv(), "COMICS_AUTH_USERNAME=user", "COMICS_AUTH_PASSWORD_HASH=not-a-hash")
	stdout, stderr, code := runToCompletion(t, env, "", "--bind", "127.0.0.1:0", "--data-dir", fixturesDir)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "hash-password") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestInitialScanFailed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "non_exist")
	server := startServer(t, cleanEnv(), "--data-dir", missing)
	server.drain(t)
	if code := server.wait(t); code != 0 {
		t.Fatalf("exited with %d; logs:\n%s", code, server.joined())
	}
	assertLogLines(t, server.logs, [][]string{
		{"no authorization enabled"},
		{`msg="server started"`, "addr="},
		{"level=ERROR", `msg="initial scan failed"`, "err="},
		{"level=WARN", `msg="fatal error occurred, shutdown the server"`},
	})
	if server.stderr.Len() != 0 {
		t.Fatalf("stderr = %q", server.stderr.String())
	}
}

func TestHashPasswordReadsStdinWithoutATerminal(t *testing.T) {
	stdout, stderr, code := runToCompletion(t, nil, "short\nshort\n", "hash-password")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !regexp.MustCompile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[^$\s]+\$[^$\s]+\n$`).MatchString(stdout) {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.HasPrefix(stderr, "warning: password is 5 characters;") || !strings.Contains(stderr, "not a refusal") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestHashPasswordRefusals(t *testing.T) {
	cases := map[string]struct{ stdin, wantErr string }{
		"mismatch": {"one\ntwo\n", "Error: Password mismatch\n"},
		"empty":    {"\n\n", "Error: Password is empty.\n"},
		"too long": {strings.Repeat("x", 1025) + "\n" + strings.Repeat("x", 1025) + "\n", "Error: Password is 1025 bytes"},
	}
	for name, tc := range cases {
		stdout, stderr, code := runToCompletion(t, nil, tc.stdin, "hash-password")
		if code != 1 || stdout != "" || !strings.HasPrefix(stderr, tc.wantErr) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
}

// The legacy check comes first, even for hash-password.
func TestHashPasswordStillChecksLegacyEnvFirst(t *testing.T) {
	_, stderr, code := runToCompletion(t, []string{"BIND=x"}, "a\na\n", "hash-password")
	if code != 1 || !strings.Contains(stderr, "BIND -> COMICS_BIND") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
