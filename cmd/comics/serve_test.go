package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/secret"
)

func warningsFor(opts options) string {
	var buffer bytes.Buffer
	logConfigurationWarnings(opts, slog.New(slog.NewTextHandler(&buffer, nil)))
	return buffer.String()
}

func TestConfigurationWarnings(t *testing.T) {
	hsts := uint64(3600)
	username, hash := "user", "hash"
	authed := options{authUsername: &username, authPasswordHash: &hash}

	secureAuthed := authed
	secureAuthed.cookieSecure = true

	insecureHSTS := authed
	insecureHSTS.hstsMaxAge = &hsts

	noCSRF := secureAuthed
	noCSRF.disableCSRFGuard = true

	halfAuth := options{authUsername: &username, cookieSecure: true}

	cases := []struct {
		name string
		opts options
		want []string
	}{
		{"everything secure is quiet", secureAuthed, nil},
		{"CSRF guard disabled", noCSRF, []string{"CSRF origin guard disabled"}},
		{"no authorization", options{cookieSecure: true}, []string{"no authorization enabled"}},
		{"only a username is not authorization", halfAuth, []string{"no authorization enabled"}},
		{"insecure cookie with auth", authed, []string{"without the Secure attribute"}},
		{"HSTS with an insecure cookie", insecureHSTS,
			[]string{"without the Secure attribute", "HSTS is enabled"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := warningsFor(tc.opts)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("warnings lack %q: %q", want, got)
				}
			}
			if lines := strings.Count(got, "\n"); lines != len(tc.want) {
				t.Errorf("got %d warnings, want %d: %q", lines, len(tc.want), got)
			}
		})
	}
}

func TestServerConfigWithoutASecretWarnsAndGeneratesOne(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, nil))

	config := serverConfig(options{dataDir: "books"}, logger)

	if !strings.Contains(buffer.String(), "no --secret provided") {
		t.Fatalf("log = %q", buffer.String())
	}
	// SessionKey panics on a zero-value Secret, so reaching here proves it was set.
	if config.Secret.SessionKey() == serverConfig(options{}, logger).Secret.SessionKey() {
		t.Fatal("two generated secrets are identical")
	}
	if config.DataDir != "books" || config.AuthUsername != "" || config.AuthPasswordHash != "" {
		t.Fatalf("config = %+v", config)
	}
}

func TestServerConfigCarriesTheGivenSecretAndCredentials(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, nil))
	given, err := secret.Parse(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	username, hash := "user", "hash"
	opts := options{secret: &given, authUsername: &username, authPasswordHash: &hash, cookieSecure: true}

	config := serverConfig(opts, logger)

	if buffer.Len() != 0 {
		t.Fatalf("log = %q", buffer.String())
	}
	if config.Secret.SessionKey() != given.SessionKey() {
		t.Fatal("the configured secret was replaced")
	}
	if config.AuthUsername != "user" || config.AuthPasswordHash != "hash" || !config.CookieSecure {
		t.Fatalf("config = %+v", config)
	}
}
