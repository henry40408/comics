package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/henry40408/comics/internal/auth"
	"github.com/henry40408/comics/internal/secret"
)

// testSecret is fixed so the derived IDs, and so dataIDs, are stable.
const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// otherSecret differs from testSecret; used where two apps must agree on one.
const otherSecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" +
	"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// dataIDs are the book IDs under testSecret. To recompute, run comics with
// --secret testSecret --data-dir fixtures/data and read the /book/ hrefs.
var dataIDs = [2]string{
	// Pepper and Carrot 01 - Potion of Flight
	"ef4c3cd1ffa17dc1",
	// Pepper and Carrot 02 - Rainbow Potions
	"ad99f34da8eb7ed6",
}

const (
	fixtureData = "./fixtures/data"
	jpegMagic   = "\xFF\xD8\xFF"
	// sessionCookie is the cookie name without the secure prefix.
	sessionCookie = auth.SessionCookie
)

// TestMain runs from the repository root because the tests name the fixtures
// by a path relative to it (fixtureData, and the fixture JPEG that
// fixturePage reads), while go test starts in this package's directory.
func TestMain(m *testing.M) {
	if err := os.Chdir("../.."); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// syncBuffer is a log sink safe for the server's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Far cheaper than the production parameters, and still real Argon2: login
// verification reads the parameters from the hash.
var passwordHash = sync.OnceValue(func() string {
	hash, err := auth.HashPasswordWith("password", auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1})
	if err != nil {
		panic(err)
	}
	return hash
})

// testApp is a running server plus a client that never follows redirects.
type testApp struct {
	t      *testing.T
	app    *App
	server *httptest.Server
	client *http.Client
	logs   *syncBuffer
}

type option func(*Config)

func withAuth() option {
	return func(c *Config) {
		c.AuthUsername = "user"
		c.AuthPasswordHash = passwordHash()
	}
}

func withDataDir(dir string) option {
	return func(c *Config) { c.DataDir = dir }
}

func withSecret(hex string) option {
	return func(c *Config) { c.Secret = mustSecret(hex) }
}

func withCookieSecure() option {
	return func(c *Config) { c.CookieSecure = true }
}

func withoutCSRFGuard() option {
	return func(c *Config) { c.DisableCSRFGuard = true }
}

func withHSTS(maxAge uint64) option {
	return func(c *Config) { c.HSTSMaxAge = &maxAge }
}

func withTrustedProxies(list string) option {
	return func(c *Config) {
		proxies, err := auth.ParseTrustedProxies(list)
		if err != nil {
			panic(err)
		}
		c.TrustedProxies = proxies
	}
}

func mustSecret(hex string) secret.Secret {
	parsed, err := secret.Parse(hex)
	if err != nil {
		panic(err)
	}
	return parsed
}

func newConfig(t *testing.T, logs *syncBuffer, opts []option) Config {
	cfg := Config{
		DataDir:  fixtureData,
		CacheDir: t.TempDir(),
		Secret:   mustSecret(testSecret),
		Logger:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// newUnscannedApp starts a server whose scan never lands.
func newUnscannedApp(t *testing.T, opts ...option) *testApp {
	t.Helper()
	logs := &syncBuffer{}
	app := New(newConfig(t, logs, opts))
	server := httptest.NewServer(app.Handler())
	t.Cleanup(server.Close)
	return &testApp{t: t, app: app, server: server, logs: logs, client: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// newTestApp starts a server after a synchronous scan.
func newTestApp(t *testing.T, opts ...option) *testApp {
	t.Helper()
	ta := newUnscannedApp(t, opts...)
	if err := ta.app.RunInitialScan(); err != nil {
		t.Fatal(err)
	}
	return ta
}

// browse makes the client keep cookies like a browser.
func (ta *testApp) browse() *testApp {
	jar, err := cookiejar.New(nil)
	if err != nil {
		ta.t.Fatal(err)
	}
	ta.client.Jar = jar
	return ta
}

// response is a fully read response.
type response struct {
	*http.Response
	body []byte
}

func (r *response) text() string { return string(r.body) }

func (r *response) location() string { return r.Header.Get("Location") }

// cookie is the Set-Cookie of the given name, or nil.
func (r *response) cookie(name string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// setCookieLines are the raw Set-Cookie header values.
func (r *response) setCookieLines() []string { return r.Header.Values("Set-Cookie") }

type requestMod func(*http.Request)

func withHeader(name, value string) requestMod {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

func withHost(value string) requestMod {
	return func(r *http.Request) { r.Host = value }
}

func withCookie(c *http.Cookie) requestMod {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) }
}

func form(values url.Values) requestMod {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(values.Encode()))
		r.ContentLength = int64(len(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

func nopCloser(body string) io.ReadCloser { return io.NopCloser(strings.NewReader(body)) }

func (ta *testApp) do(method, path string, mods ...requestMod) *response {
	ta.t.Helper()
	req, err := http.NewRequest(method, ta.server.URL+path, nil)
	if err != nil {
		ta.t.Fatal(err)
	}
	for _, mod := range mods {
		mod(req)
	}
	res, err := ta.client.Do(req)
	if err != nil {
		ta.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		ta.t.Fatal(err)
	}
	return &response{Response: res, body: body}
}

func (ta *testApp) get(path string, mods ...requestMod) *response {
	ta.t.Helper()
	return ta.do(http.MethodGet, path, mods...)
}

func (ta *testApp) post(path string, mods ...requestMod) *response {
	ta.t.Helper()
	return ta.do(http.MethodPost, path, mods...)
}

func credentials(username, password string) url.Values {
	return url.Values{"username": {username}, "password": {password}}
}

func (ta *testApp) login() *response {
	ta.t.Helper()
	return ta.post("/login", form(credentials("user", "password")))
}

func (ta *testApp) failedLogin(mods ...requestMod) *response {
	ta.t.Helper()
	return ta.post("/login", append([]requestMod{form(credentials("user", "nope"))}, mods...)...)
}

// firstAfter is the text between marker and the next double quote.
func firstAfter(t *testing.T, html, marker string) string {
	t.Helper()
	_, rest, found := strings.Cut(html, marker)
	if !found {
		t.Fatalf("no %q in %s", marker, html)
	}
	value, _, _ := strings.Cut(rest, `"`)
	return value
}

func (ta *testApp) coverID() string {
	ta.t.Helper()
	id := firstAfter(ta.t, ta.get("/").text(), "/thumb/md/")
	if id == "" {
		ta.t.Fatal("empty cover id")
	}
	return id
}

func assertStatus(t *testing.T, want int, res *response, what string) {
	t.Helper()
	if res.StatusCode != want {
		t.Errorf("%s: status %d, want %d", what, res.StatusCode, want)
	}
}
