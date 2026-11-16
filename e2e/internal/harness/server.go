// Package harness drives the comics server and a browser for the e2e suite.
package harness

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Port is fixed, so a developer can leave a server running between runs.
const Port = 3030

// BaseURL is what every page object navigates against.
const BaseURL = "http://127.0.0.1:3030"

// Username and Password are what the login steps sign in with.
const (
	Username = "user"
	Password = "password"
)

// testPasswordHash is the Argon2id hash of "password", a throwaway
// credential for the fixtures.
const testPasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$C2qIDpzPcTL0a5wYL1152Q$2MWeEDjhoNnp8oRwz9DkFoLgYH3NTe+qArT3vPHN14g"

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const startupTimeout = time.Minute

// Server is a running comics server. Stop kills it, unless it was already
// listening before the suite started: then it is left alone.
type Server struct {
	cmd *exec.Cmd
	// exited receives the result of cmd.Wait once the child is gone.
	exited chan error
}

// Start starts the server, or adopts one already listening on Port.
//
// An adopted server may be an orphan from a killed run, running an old
// binary, so adoption is logged.
func Start() (*Server, error) {
	if portIsOpen() {
		fmt.Fprintf(os.Stderr, "e2e: adopting the server already listening on 127.0.0.1:%d\n", Port)
		return &Server{}, nil
	}

	binary, err := ensureBinary()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary,
		"--bind", "127.0.0.1:"+strconv.Itoa(Port),
		"--data-dir", "fixtures/data",
	)
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(),
		"COMICS_AUTH_USERNAME="+Username,
		"COMICS_AUTH_PASSWORD_HASH="+testPasswordHash,
		"COMICS_SECRET="+testSecret,
	)
	// Passed through, so a refusal to start shows in the test output.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawning the comics server at %s: %w", binary, err)
	}

	server := &Server{cmd: cmd, exited: make(chan error, 1)}
	go func() { server.exited <- cmd.Wait() }()

	if err := server.waitUntilListening(); err != nil {
		return nil, err
	}
	return server, nil
}

// Stop kills the server if this process started it.
func (s *Server) Stop() {
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Kill()
	<-s.exited
	s.cmd = nil
}

// ensureBinary returns the path to the server binary, building it first when
// it is not there.
//
// An existing binary is never rebuilt, so rebuild by hand after changing
// server code. CI builds it beforehand.
func ensureBinary() (string, error) {
	binary := filepath.Join(repoRoot(), "bin", "comics")
	if isFile(binary) {
		return binary, nil
	}

	fmt.Fprintf(os.Stderr, "e2e: %s is missing, building it\n", binary)
	build := exec.Command("go", "build", "-mod=vendor", "-o", "bin/comics", "./cmd/comics")
	build.Dir = repoRoot()
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("running go build: %w", err)
	}
	if !isFile(binary) {
		return "", fmt.Errorf("go build did not produce %s", binary)
	}
	return binary, nil
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// waitUntilListening polls the port until the child answers. It gives up as
// soon as the child exits, so a startup failure shows its exit status at once
// rather than after the timeout.
func (s *Server) waitUntilListening() error {
	deadline := time.After(startupTimeout)
	for {
		select {
		case err := <-s.exited:
			return fmt.Errorf("comics server exited before listening on 127.0.0.1:%d: %v", Port, err)
		case <-deadline:
			s.Stop()
			return fmt.Errorf("comics server did not start listening on 127.0.0.1:%d within %v", Port, startupTimeout)
		case <-time.After(100 * time.Millisecond):
			if portIsOpen() {
				return nil
			}
		}
	}
}

func portIsOpen() bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(Port)), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// repoRoot is the repository root, three levels above e2e/internal/harness.
// It comes from this file's compile-time path, so the suite works from any
// working directory.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}
