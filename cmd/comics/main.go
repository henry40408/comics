// Command comics serves a directory of comic books over HTTP.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/henry40408/comics/internal/version"
)

const (
	exitFailure = 1
	exitUsage   = 2
)

// process is everything run needs from the outside world.
type process struct {
	args      []string
	lookupEnv func(string) (string, bool)
	stdin     *os.File
	stdout    io.Writer
	stderr    io.Writer
}

func main() {
	os.Exit(run(process{
		args:      os.Args[1:],
		lookupEnv: os.LookupEnv,
		stdin:     os.Stdin,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
	}))
}

// run returns the exit code. Logs go to stdout, so stderr stays empty in
// server mode.
func run(p process) int {
	// First, before flags: a retired variable must stop startup however the
	// rest of the command line looks.
	if err := ensureNoLegacyEnvVars(p.lookupEnv); err != nil {
		return reportFatal(p.stderr, err)
	}
	opts, err := parseOptions(p.args, p.lookupEnv, p.stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return reportFatal(p.stderr, err)
	}
	if opts.showVersion {
		_, _ = fmt.Fprintf(p.stdout, "comics %s\n", version.Version())
		return 0
	}
	if err := runCommand(p, opts); err != nil {
		return reportFatal(p.stderr, err)
	}
	return 0
}

func runCommand(p process, opts options) error {
	// hash-password writes no log lines: its stdout holds the hash alone.
	if opts.command == "hash-password" {
		return hashPasswordCommand(p.stdin, p.stdout, p.stderr)
	}
	logger := newLogger(p.stdout, opts.logFormat, opts.logLevel)
	if opts.command == "list" {
		return listCommand(opts.dataDir, p.stdout, logger)
	}
	return runServer(opts, logger)
}

func reportFatal(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
	var usage usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitFailure
}
