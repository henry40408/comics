package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/auth"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func envOf(pairs map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := pairs[name]
		return value, ok
	}
}

func mustParse(t *testing.T, args []string, env map[string]string) options {
	t.Helper()
	opts, err := parseOptions(args, envOf(env), io.Discard)
	if err != nil {
		t.Fatalf("parseOptions(%v): %v", args, err)
	}
	return opts
}

func TestDefaults(t *testing.T) {
	opts := mustParse(t, nil, nil)
	if opts.bind != "127.0.0.1:8080" || opts.dataDir != "./data" || opts.logFormat != "full" ||
		opts.logLevel != slog.LevelInfo || opts.command != "" || opts.secret != nil ||
		opts.authUsername != "" || opts.hstsMaxAge != nil || opts.disableCSRFGuard {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
	if !strings.HasSuffix(opts.cacheDir, "comics-thumbs") {
		t.Fatalf("cacheDir = %q", opts.cacheDir)
	}
}

func TestFlagBeatsEnvBeatsDefault(t *testing.T) {
	env := map[string]string{"COMICS_DATA_DIR": "from-env", "COMICS_BIND": "127.0.0.1:1"}
	opts := mustParse(t, []string{"--data-dir", "from-flag"}, env)
	if opts.dataDir != "from-flag" {
		t.Errorf("dataDir = %q", opts.dataDir)
	}
	if opts.bind != "127.0.0.1:1" {
		t.Errorf("bind = %q", opts.bind)
	}
	if got := mustParse(t, []string{"-b", "127.0.0.1:2"}, env).bind; got != "127.0.0.1:2" {
		t.Errorf("short flag: bind = %q", got)
	}
}

func TestAnEmptyEnvVarIsUnset(t *testing.T) {
	opts := mustParse(t, nil, map[string]string{"COMICS_TRUSTED_PROXIES": "", "COMICS_COOKIE_SECURE": ""})
	if !opts.trustedProxies.IsEmpty() || opts.cookieSecure {
		t.Fatalf("empty variables took effect: %+v", opts)
	}
}

func TestBooleansAcceptOnlyTrueAndFalse(t *testing.T) {
	if opts := mustParse(t, []string{"--cookie-secure"}, nil); !opts.cookieSecure {
		t.Error("a bare flag did not mean true")
	}
	if opts := mustParse(t, []string{"--cookie-secure=false"}, nil); opts.cookieSecure {
		t.Error("=false was ignored")
	}
	if opts := mustParse(t, nil, map[string]string{"COMICS_DISABLE_CSRF_GUARD": "true"}); !opts.disableCSRFGuard {
		t.Error("env true was ignored")
	}
	for _, bad := range []string{"1", "yes", "TRUE"} {
		_, err := parseOptions(nil, envOf(map[string]string{"COMICS_COOKIE_SECURE": bad}), io.Discard)
		assertUsageError(t, err)
		_, err = parseOptions([]string{"--cookie-secure=" + bad}, envOf(nil), io.Discard)
		assertUsageError(t, err)
	}
}

func assertUsageError(t *testing.T, err error) {
	t.Helper()
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("err = %v, want a usage error", err)
	}
}

func TestInvalidValuesAreUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"secret too short": {"--secret", "abcd"},
		"bad proxies":      {"--trusted-proxies", "not-an-ip"},
		"hostname bind":    {"--bind", "localhost:8080"},
		"bad log format":   {"--log-format", "yaml"},
		"compact format":   {"--log-format", "compact"},
		"pretty format":    {"--log-format", "pretty"},
		"bad hsts":         {"--hsts-max-age", "-1"},
		"unknown flag":     {"--nope"},
		"unknown command":  {"frobnicate"},
		"extra argument":   {"list", "extra"},
	}
	for name, args := range cases {
		_, err := parseOptions(args, envOf(nil), io.Discard)
		if err == nil {
			t.Errorf("%s: accepted %v", name, args)
			continue
		}
		assertUsageError(t, err)
	}
	_, err := parseOptions(nil, envOf(map[string]string{logLevelEnv: "trace"}), io.Discard)
	assertUsageError(t, err)
}

func TestBindIsValidatedOnlyInServerMode(t *testing.T) {
	env := envOf(map[string]string{"COMICS_BIND": "localhost:8080"})
	for _, args := range [][]string{{"list"}, {"ls"}, {"hash-password"}, {"--version"}} {
		if _, err := parseOptions(args, env, io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	_, err := parseOptions(nil, env, io.Discard)
	assertUsageError(t, err)
}

func TestEnvErrorsNameTheVariable(t *testing.T) {
	_, err := parseOptions(nil, envOf(map[string]string{"COMICS_SECRET": "abcd"}), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "COMICS_SECRET") ||
		!strings.Contains(err.Error(), "at least 64 hex characters") {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionsAreParsedIntoTheirTypes(t *testing.T) {
	opts := mustParse(t, []string{
		"--secret", testSecret,
		"--hsts-max-age", "0",
		"--trusted-proxies", "10.0.0.0/8,192.168.0.1",
		"--auth-username", "user",
		"--auth-password-hash", "x",
		"--log-format", "json",
		"ls",
	}, map[string]string{logLevelEnv: "warn"})
	if opts.secret == nil || opts.hstsMaxAge == nil || *opts.hstsMaxAge != 0 {
		t.Fatalf("secret/hsts: %+v", opts)
	}
	if opts.trustedProxies.IsEmpty() {
		t.Error("trusted proxies were dropped")
	}
	if opts.authUsername != "user" {
		t.Errorf("auth username = %q", opts.authUsername)
	}
	if opts.logFormat != "json" || opts.logLevel != slog.LevelWarn || opts.command != "list" {
		t.Errorf("unexpected: %+v", opts)
	}
	if got := mustParse(t, []string{"hash-password"}, nil).command; got != "hash-password" {
		t.Errorf("command = %q", got)
	}
}

func TestHelpPrintsUsageAndABadFlagDoesNot(t *testing.T) {
	var help bytes.Buffer
	_, err := parseOptions([]string{"-h"}, envOf(nil), &help)
	if !errors.Is(err, flag.ErrHelp) || !strings.Contains(help.String(), "Usage: comics") {
		t.Fatalf("err = %v, usage = %q", err, help.String())
	}
	var bad bytes.Buffer
	_, _ = parseOptions([]string{"--nope"}, envOf(nil), &bad)
	if bad.Len() != 0 {
		t.Fatalf("a bad flag printed %q", bad.String())
	}
}

func TestLegacyEnvVarsAreReportedInOrder(t *testing.T) {
	err := ensureNoLegacyEnvVars(envOf(map[string]string{
		"COMICS_SESSION_KEY": "x", "BIND": "", "RUST_LOG": "debug",
	}))
	want := "these environment variables no longer exist; rename (or unset) them to continue:\n" +
		"  BIND -> COMICS_BIND\n  COMICS_SESSION_KEY -> COMICS_SECRET\n  RUST_LOG -> COMICS_LOG_LEVEL"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
	if ensureNoLegacyEnvVars(envOf(nil)) != nil {
		t.Fatal("an empty environment was refused")
	}
}

func TestEveryLegacyVariableNamesALiveReplacement(t *testing.T) {
	live := map[string]bool{}
	opts := newOptions()
	for _, spec := range opts.specs() {
		live[spec.env] = true
	}
	for _, legacy := range legacyEnvVars {
		if !live[legacy.replacement] {
			t.Errorf("%s points at %s, which no flag reads", legacy.old, legacy.replacement)
		}
		if live[legacy.old] {
			t.Errorf("%s is both legacy and live", legacy.old)
		}
	}
}

func TestAUsablePasswordHashStartsTheServer(t *testing.T) {
	hash, err := auth.HashPassword("password")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensurePasswordHashIsUsable(options{authPasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	if err := ensurePasswordHashIsUsable(options{}); err != nil {
		t.Fatal(err)
	}
}

func TestAMalformedPasswordHashStopsStartup(t *testing.T) {
	cases := []string{
		"not-a-hash",
		"password",
		"$argon2id$v=19$m=19456$nope",
		"$pbkdf2-sha256$i=1000$c2FsdHNhbHQ$xEbJPmXjr2fBIf1RhJ1Kd0uGrjhOTOAgWnMYGVBLj4Y",
	}
	for _, hash := range cases {
		err := ensurePasswordHashIsUsable(options{authPasswordHash: hash})
		if err == nil || !strings.Contains(err.Error(), "hash-password") {
			t.Errorf("%q: err = %v", hash, err)
		}
	}
}

func TestAnExplicitlyEmptyCredentialIsRefused(t *testing.T) {
	for _, flagName := range []string{"--auth-username", "--auth-password-hash"} {
		_, err := parseOptions([]string{flagName, ""}, envOf(nil), io.Discard)
		assertUsageError(t, err)
	}
}

func TestABcryptHashNamesTheMigration(t *testing.T) {
	for _, version := range []string{"2a", "2b", "2x", "2y"} {
		hash := "$" + version + "$11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu"
		err := ensurePasswordHashIsUsable(options{authPasswordHash: hash})
		if err == nil {
			t.Fatalf("%s accepted", version)
		}
		for _, want := range []string{"bcrypt", "Argon2id", "hash-password", "password itself is unchanged"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q lacks %q", version, err, want)
			}
		}
	}
}
