package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/henry40408/comics/internal/auth"
	"github.com/henry40408/comics/internal/secret"
)

const (
	defaultBind      = "127.0.0.1:8080"
	defaultDataDir   = "./data"
	defaultLogFormat = "full"
	logLevelEnv      = "COMICS_LOG_LEVEL"
)

// usageError marks a bad command line or environment value; main exits 2.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// options holds the parsed configuration. A nil pointer means "not given",
// which matters where the absence itself has a meaning (no secret → random).
type options struct {
	bind             string
	dataDir          string
	cacheDir         string
	logFormat        string
	logLevel         slog.Level
	secret           *secret.Secret
	authUsername     string
	authPasswordHash string
	cookieSecure     bool
	hstsMaxAge       *uint64
	trustedProxies   auth.TrustedProxies
	disableCSRFGuard bool
	showVersion      bool
	// command is "", "list" or "hash-password".
	command string
}

// flagSpec describes one setting. Precedence is flag, then env, then default:
// the environment is applied first and a flag parsed afterwards overrides it.
type flagSpec struct {
	names   []string
	env     string
	usage   string
	boolean bool
	set     func(value string) error
}

func newOptions() options {
	return options{
		bind:      defaultBind,
		dataDir:   defaultDataDir,
		cacheDir:  filepath.Join(os.TempDir(), "comics-thumbs"),
		logFormat: defaultLogFormat,
		logLevel:  slog.LevelInfo,
	}
}

func (o *options) specs() []flagSpec {
	return []flagSpec{
		{names: []string{"bind", "b"}, env: "COMICS_BIND", set: setString(&o.bind),
			usage: "bind host and port, loopback by default (default " + defaultBind + ")"},
		{names: []string{"data-dir"}, env: "COMICS_DATA_DIR", set: setString(&o.dataDir),
			usage: "data directory (default " + defaultDataDir + ")"},
		{names: []string{"cache-dir"}, env: "COMICS_CACHE_DIR", set: setString(&o.cacheDir),
			usage: "directory for cached thumbnails (default comics-thumbs under the system temp dir)"},
		{names: []string{"log-format"}, env: "COMICS_LOG_FORMAT", set: setParsed(&o.logFormat, parseLogFormat),
			usage: "log format: full or json (default " + defaultLogFormat + ")"},
		{env: logLevelEnv, set: setParsed(&o.logLevel, parseLogLevel)},
		{names: []string{"secret"}, env: "COMICS_SECRET", set: o.setSecret,
			usage: "at least 64 hex characters (`openssl rand -hex 32`); unset means a random secret per start"},
		{names: []string{"auth-username"}, env: "COMICS_AUTH_USERNAME", set: setNonEmpty(&o.authUsername),
			usage: "username for the login form"},
		{names: []string{"auth-password-hash"}, env: "COMICS_AUTH_PASSWORD_HASH", set: setNonEmpty(&o.authPasswordHash),
			usage: "Argon2id hash of the password for the login form (see hash-password)"},
		{names: []string{"cookie-secure"}, env: "COMICS_COOKIE_SECURE", boolean: true, set: setParsed(&o.cookieSecure, parseStrictBool),
			usage: "send the session cookie with the Secure attribute (HTTPS only)"},
		{names: []string{"hsts-max-age"}, env: "COMICS_HSTS_MAX_AGE", set: o.setHSTSMaxAge,
			usage: "send Strict-Transport-Security with this max-age in seconds"},
		{names: []string{"trusted-proxies"}, env: "COMICS_TRUSTED_PROXIES", set: setParsed(&o.trustedProxies, auth.ParseTrustedProxies),
			usage: "comma-separated IPs and CIDR prefixes whose X-Forwarded-For is trusted"},
		{names: []string{"disable-csrf-guard"}, env: "COMICS_DISABLE_CSRF_GUARD", boolean: true, set: setParsed(&o.disableCSRFGuard, parseStrictBool),
			usage: "turn off the CSRF origin guard (plain-HTTP LAN hosts only)"},
		{names: []string{"version"}, boolean: true, set: setParsed(&o.showVersion, parseStrictBool),
			usage: "print the version and exit"},
	}
}

// parseOptions reads the environment, then args. The caller prints the returned
// error; errw receives only the usage text.
func parseOptions(args []string, lookupEnv func(string) (string, bool), errw io.Writer) (options, error) {
	opts, err := parseOptionValues(args, lookupEnv, errw)
	if err != nil {
		return options{}, usageError{err}
	}
	return opts, nil
}

func parseOptionValues(args []string, lookupEnv func(string) (string, bool), errw io.Writer) (options, error) {
	opts := newOptions()
	specs := opts.specs()
	if err := applyEnv(specs, lookupEnv); err != nil {
		return options{}, err
	}
	flags := newFlagSet(specs)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// Only a request for help prints usage; a bad flag is reported once,
			// by the caller.
			flags.SetOutput(errw)
			flags.Usage()
		}
		return options{}, err
	}
	if err := opts.setCommand(flags.Args()); err != nil {
		return options{}, err
	}
	if err := opts.validateBindForServer(); err != nil {
		return options{}, err
	}
	return opts, nil
}

// validateBindForServer checks --bind only when the server will listen, so
// COMICS_BIND=localhost:8080 comics list still works.
func (o *options) validateBindForServer() error {
	if o.command != "" || o.showVersion {
		return nil
	}
	// Hostnames are refused: the listen address must be a literal IP.
	if _, err := netip.ParseAddrPort(o.bind); err != nil {
		return fmt.Errorf("invalid bind %q: must be an IP address and port such as 127.0.0.1:8080: %w", o.bind, err)
	}
	return nil
}

func newFlagSet(specs []flagSpec) *flag.FlagSet {
	flags := flag.NewFlagSet("comics", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for _, spec := range specs {
		for _, name := range spec.names {
			if spec.boolean {
				flags.BoolFunc(name, spec.usage, spec.set)
				continue
			}
			flags.Func(name, spec.usage, spec.set)
		}
	}
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "Usage: comics [flags] [list|ls|hash-password]")
		flags.PrintDefaults()
	}
	return flags
}

// applyEnv treats an empty variable as unset: a container image may export one
// empty to mean "no value".
func applyEnv(specs []flagSpec, lookupEnv func(string) (string, bool)) error {
	for _, spec := range specs {
		value, ok := lookupEnv(spec.env)
		if spec.env == "" || !ok || value == "" {
			continue
		}
		if err := spec.set(value); err != nil {
			return fmt.Errorf("invalid value %q for %s: %w", value, spec.env, err)
		}
	}
	return nil
}

func (o *options) setCommand(rest []string) error {
	if len(rest) == 0 {
		return nil
	}
	if len(rest) > 1 {
		return fmt.Errorf("unexpected argument %q after the subcommand", rest[1])
	}
	switch rest[0] {
	case "list", "ls":
		o.command = "list"
	case "hash-password":
		o.command = "hash-password"
	default:
		return fmt.Errorf("unknown subcommand %q (want list, ls or hash-password)", rest[0])
	}
	return nil
}

func setString(target *string) func(string) error {
	return func(value string) error {
		*target = value
		return nil
	}
}

// setParsed stores what parse returns, so a setting needs no method of its own.
func setParsed[T any](target *T, parse func(string) (T, error)) func(string) error {
	return func(value string) error {
		parsed, err := parse(value)
		if err != nil {
			return err
		}
		*target = parsed
		return nil
	}
}

// setNonEmpty refuses an explicit empty value: an empty credential would
// silently turn authorization off, so it is an error, never "unset". An empty
// environment variable never reaches here; applyEnv treats it as unset.
func setNonEmpty(target *string) func(string) error {
	return func(value string) error {
		if value == "" {
			return errors.New("must not be empty")
		}
		*target = value
		return nil
	}
}

// parseStrictBool accepts only true and false, like clap.
func parseStrictBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("must be true or false")
}

func (o *options) setSecret(value string) error {
	parsed, err := secret.Parse(value)
	if err != nil {
		return err
	}
	o.secret = &parsed
	return nil
}

func (o *options) setHSTSMaxAge(value string) error {
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return err
	}
	o.hstsMaxAge = &seconds
	return nil
}
