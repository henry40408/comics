package server

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/assets"
)

// Pinned independently of the constants in middleware.go, so a change to either
// side fails.
var wantConstantHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; script-src 'self'; " +
		"style-src 'self' https://fonts.bunny.net; " +
		"font-src https://fonts.bunny.net https://cdn.jsdelivr.net/fontsource/fonts/; " +
		"img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Referrer-Policy":              "no-referrer",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Permissions-Policy": "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
		"encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), " +
		"microphone=(), midi=(), payment=(), usb=()",
}

func assertSecurityHeaders(t *testing.T, res *response, what string) {
	t.Helper()
	for name, want := range wantConstantHeaders {
		if got := res.Header.Get(name); got != want {
			t.Errorf("%s: %s = %q, want %q", what, name, got, want)
		}
	}
}

func TestCSRFCrossSitePostIsForbidden(t *testing.T) {
	ta := newTestApp(t)
	for _, path := range []string{"/rescan", "/shuffle", "/login", "/logout"} {
		assertStatus(t, 403, ta.post(path, withHeader("Sec-Fetch-Site", "cross-site")), "POST "+path+" cross-site")
	}
}

func TestCSRFSameOriginPostIsAllowed(t *testing.T) {
	ta := newTestApp(t)
	assertStatus(t, 303, ta.post("/shuffle", withHeader("Sec-Fetch-Site", "same-origin")), "sec-fetch-site")
	res := ta.post("/shuffle", withHeader("Origin", "http://localhost"), withHost("localhost"))
	assertStatus(t, 303, res, "origin fallback")
}

// The plain-HTTP LAN lockout DisableCSRFGuard exists for.
func TestCSRFNullOriginPostIsForbiddenByDefault(t *testing.T) {
	ta := newTestApp(t)
	res := ta.post("/shuffle", withHeader("Origin", "null"), withHost("nas.local"))
	assertStatus(t, 403, res, "null origin")
}

func TestCSRFGuardCanBeDisabled(t *testing.T) {
	ta := newTestApp(t, withoutCSRFGuard())
	assertStatus(t, 303, ta.post("/shuffle", withHeader("Origin", "null"), withHost("nas.local")), "null origin")
	assertStatus(t, 303, ta.post("/shuffle", withHeader("Sec-Fetch-Site", "cross-site")), "cross-site")
}

func TestCSRFSafeMethodIsNeverChecked(t *testing.T) {
	ta := newTestApp(t)
	assertStatus(t, 200, ta.get("/", withHeader("Sec-Fetch-Site", "cross-site")), "GET /")
}

// A TLS-terminating proxy forwards a portless Host against an https Origin.
func TestCSRFTLSTerminatingProxyOriginMatchesForwardedHost(t *testing.T) {
	ta := newTestApp(t)
	res := ta.post("/shuffle", withHeader("Origin", "https://app.example.com"), withHost("app.example.com"))
	assertStatus(t, 303, res, "proxied origin")
}

// comics is a single origin, so its own forms report same-origin.
func TestCSRFSameSitePostIsForbidden(t *testing.T) {
	ta := newTestApp(t)
	assertStatus(t, 403, ta.post("/shuffle", withHeader("Sec-Fetch-Site", "same-site")), "same-site")
}

func TestCSRFOriginFallbackComparesThePortToo(t *testing.T) {
	ta := newTestApp(t)
	res := ta.post("/shuffle", withHeader("Origin", "http://nas.local:8080"), withHost("nas.local:8080"))
	assertStatus(t, 303, res, "matching port")
	res = ta.post("/shuffle", withHeader("Origin", "http://nas.local:8080"), withHost("nas.local"))
	assertStatus(t, 403, res, "mismatched port")
}

// A non-browser client carries no ambient cookie, so it is no CSRF vector.
func TestCSRFClientSendingNeitherHeaderIsAllowed(t *testing.T) {
	assertStatus(t, 303, newTestApp(t).post("/shuffle"), "bare POST")
}

// TRACE is safe in RFC 7231, but only GET/HEAD/OPTIONS are exempt.
func TestCSRFCrossSiteTraceIsForbidden(t *testing.T) {
	res := newTestApp(t).do("TRACE", "/shuffle", withHeader("Sec-Fetch-Site", "cross-site"))
	assertStatus(t, 403, res, "TRACE")
}

func TestHSTSAbsentByDefault(t *testing.T) {
	res := newTestApp(t).get("/healthz")
	if got := res.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS = %q, want none", got)
	}
}

func TestHSTSPresentWhenConfigured(t *testing.T) {
	ta := newTestApp(t, withAuth(), withHSTS(63072000))
	for _, path := range []string{"/healthz", "/login", "/assets/app.css"} {
		if got := ta.get(path).Header.Get("Strict-Transport-Security"); got != "max-age=63072000" {
			t.Errorf("GET %s: HSTS = %q", path, got)
		}
	}
}

func TestSecurityHeadersPresentOnEveryResponse(t *testing.T) {
	ta := newTestApp(t)
	for _, path := range []string{"/", "/book/" + dataIDs[0], "/healthz", "/assets/app.css", "/assets/theme.js", "/favicon.svg"} {
		res := ta.get(path)
		assertStatus(t, 200, res, "GET "+path)
		assertSecurityHeaders(t, res, path)
	}

	protected := newTestApp(t, withAuth())
	res := protected.get("/login")
	assertStatus(t, 200, res, "GET /login")
	assertSecurityHeaders(t, res, "/login")
	res = protected.get("/")
	assertStatus(t, 303, res, "GET / anonymous")
	assertSecurityHeaders(t, res, "/ (anonymous redirect)")
}

// The 403/404/405 are produced by layers inside the header layer.
func TestSecurityHeadersPresentOnErrorResponses(t *testing.T) {
	ta := newTestApp(t)
	cases := []struct {
		what   string
		status int
		res    *response
	}{
		{"403 csrf", 403, ta.post("/shuffle", withHeader("Sec-Fetch-Site", "cross-site"))},
		{"404 unrouted", 404, ta.get("/no/such/route")},
		{"404 book", 404, ta.get("/book/nonexistent123")},
		{"405 wrong verb", 405, ta.post("/healthz")},
	}
	for _, c := range cases {
		assertStatus(t, c.status, c.res, c.what)
		assertSecurityHeaders(t, c.res, c.what)
	}
}

func TestEveryConstantHeaderIsWellFormed(t *testing.T) {
	for _, h := range constantHeaders {
		name, value := h[0], h[1]
		if name != http.CanonicalHeaderKey(name) {
			t.Errorf("%s is not canonical", name)
		}
		if strings.ContainsAny(value, "\r\n") || value == "" {
			t.Errorf("%s has a malformed value %q", name, value)
		}
		if want := wantConstantHeaders[name]; value != want {
			t.Errorf("%s = %q, want %q", name, value, want)
		}
	}
	if len(constantHeaders) != len(wantConstantHeaders) {
		t.Errorf("%d constant headers, want %d", len(constantHeaders), len(wantConstantHeaders))
	}
}

func TestStaticAssetsStayPubliclyCacheable(t *testing.T) {
	res := newTestApp(t, withAuth()).get("/assets/app.css")
	assertStatus(t, 200, res, "GET /assets/app.css")
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", got)
	}
}

// A rendered page that is not no-store lets the back button show it after
// logout. Every way the server answers with one is listed here.
func TestEveryRenderedPageIsNotCacheable(t *testing.T) {
	ta := newTestApp(t, withAuth()).browse()
	check := func(what string, wantStatus int, res *response) {
		t.Helper()
		assertStatus(t, wantStatus, res, what)
		if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("%s: Content-Type %q, so the no-store check proves nothing", what, got)
		}
		assertNoStore(t, res, what)
	}

	check("login form", 200, ta.get("/login"))
	check("login form after a failed login", 401, ta.failedLogin())
	ta.login()
	book := "/book/" + dataIDs[0]
	for _, path := range []string{"/", book, book + "?mode=paged", book + "?mode=scroll", book + "?mode=unknown"} {
		check("GET "+path, 200, ta.get(path))
	}
}

// Browser-cacheable, but never by a shared cache.
func TestPageAndThumbImagesArePrivatelyCacheable(t *testing.T) {
	ta := newTestApp(t, withAuth()).browse()
	ta.login()
	id := ta.coverID()
	for _, path := range []string{"/data/" + id, "/thumb/md/" + id} {
		res := ta.get(path)
		assertStatus(t, 200, res, "GET "+path)
		cc := res.Header.Get("Cache-Control")
		if !strings.HasPrefix(cc, "private") || !strings.Contains(cc, "max-age=") {
			t.Errorf("GET %s: Cache-Control = %q", path, cc)
		}
	}
}

func TestThemeScriptIsServedAndNotDeferred(t *testing.T) {
	ta := newTestApp(t)
	res := ta.get("/assets/theme.js")
	assertStatus(t, 200, res, "theme.js")
	if got := res.Header.Get("Content-Type"); got != "text/javascript" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", got)
	}
	if !strings.Contains(res.text(), "data-theme") {
		t.Error("theme.js does not set data-theme")
	}

	html := ta.get("/").text()
	at := strings.Index(html, "/assets/theme.js")
	if at < 0 {
		t.Fatal("no theme script in the index")
	}
	start := strings.LastIndex(html[:at], "<script")
	tag := html[start : at+strings.Index(html[at:], ">")]
	if strings.Contains(tag, "defer") || strings.Contains(tag, "async") {
		t.Errorf("theme script is deferred: %s", tag)
	}
}

// Without the js class before first paint, :target fights app.js.
func TestTheScriptedPathIsMarkedBeforeFirstPaint(t *testing.T) {
	js := newTestApp(t).get("/assets/theme.js").text()
	if !strings.Contains(js, `classList.add("js")`) {
		t.Errorf("theme.js does not add the js class: %s", js)
	}
	if !strings.Contains(assets.AppCSS, "html:not(.js)") {
		t.Error("app.css has no html:not(.js) rules")
	}
}

// Without theme.js there is no data-theme; the media-query copy of the dark
// palette must match the attribute one.
func TestDarkThemeHasANoJSFallback(t *testing.T) {
	explicit := cssTokens(cssBlock(t, assets.AppCSS, `html[data-theme="dark"] {`))
	system := cssTokens(cssBlock(t, assets.AppCSS, `html:not([data-theme]) {`))
	if len(explicit) == 0 {
		t.Fatal("the dark palette went missing")
	}
	if !slices.Equal(explicit, system) {
		t.Errorf("the dark palettes have drifted:\n%v\n%v", explicit, system)
	}
}

func cssBlock(t *testing.T, css, selector string) string {
	t.Helper()
	at := strings.Index(css, selector)
	if at < 0 {
		t.Fatalf("no %q block", selector)
	}
	rest := css[at:]
	open := strings.Index(rest, "{")
	closing := strings.Index(rest[open:], "}")
	if open < 0 || closing < 0 {
		t.Fatalf("unbalanced %q block", selector)
	}
	return rest[open+1 : open+closing]
}

// cssTokens are the "--name: value" declarations, sorted so order cannot matter.
func cssTokens(block string) []string {
	var tokens []string
	for line := range strings.SplitSeq(block, "\n") {
		decl, found := strings.CutSuffix(strings.TrimSpace(line), ";")
		name, value, hasColon := strings.Cut(decl, ":")
		if !found || !hasColon || !strings.HasPrefix(strings.TrimSpace(name), "--") {
			continue
		}
		tokens = append(tokens, strings.TrimSpace(name)+": "+strings.TrimSpace(value))
	}
	slices.Sort(tokens)
	return tokens
}
