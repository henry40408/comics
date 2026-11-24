package auth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	return &Authenticator{
		Enabled:  true,
		Sessions: newTestStore(),
		Salt:     NewAuditSalt(),
		Logger:   slog.New(slog.DiscardHandler),
	}
}

// cookiePair renders cookie as a browser Cookie header value.
func cookiePair(cookie *http.Cookie) string {
	return cookie.Name + "=" + cookie.Value
}

func requestWithCookie(cookieHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if cookieHeader != "" {
		r.Header.Set("Cookie", cookieHeader)
	}
	return r
}

// requestFor is a request whose cookie carries id, as a browser sends it.
func requestFor(id string) *http.Request {
	return requestWithCookie(cookiePair(BuildSessionCookie(false, id)))
}

// legacySignedValue is what a release that signed the session cookie sent for
// id: a 43-character digest in front of the identifier, 75 characters in all.
func legacySignedValue(id string) string {
	return strings.Repeat("A", 43) + id
}

func wantState(t *testing.T, got AuthState, kind AuthKind, why Rejection) {
	t.Helper()
	if got.Kind != kind || got.Rejection != why {
		t.Fatalf("state = %+v, want kind %d rejection %d", got, kind, why)
	}
}

func TestAuthenticatePublicWhenNoAuthConfig(t *testing.T) {
	a := newTestAuthenticator(t)
	a.Enabled = false
	wantState(t, a.Authenticate(requestWithCookie("")), AuthPublic, RejectionNone)
}

func TestAuthenticateAuthenticatedForALiveSession(t *testing.T) {
	a := newTestAuthenticator(t)
	id := a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(id)), AuthAuthenticated, RejectionNone)
}

func TestAuthenticateReportsWhyItRefused(t *testing.T) {
	a := newTestAuthenticator(t)

	wantState(t, a.Authenticate(requestWithCookie("")), AuthUnauthenticated, RejectionAbsent)

	// Not an identifier shape.
	wantState(t, a.Authenticate(requestFor("not-an-id")), AuthUnauthenticated, RejectionMalformed)

	// A cookie from a release that signed them: its tail names a live session,
	// but the whole value is not an identifier, so it must not log in.
	live := a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(legacySignedValue(live))), AuthUnauthenticated, RejectionMalformed)

	// Well-formed, but never issued.
	wantState(t, a.Authenticate(requestFor(strings.Repeat("0", 32))), AuthUnauthenticated, RejectionUnknown)
}

func TestAuthenticateSurfacesAChangedUserAgentWithoutRefusing(t *testing.T) {
	a := newTestAuthenticator(t)
	id := a.Sessions.Create("original-agent")

	request := requestFor(id)
	request.Header.Set("User-Agent", "a-different-agent")

	got := a.Authenticate(request)
	wantState(t, got, AuthAuthenticated, RejectionNone)
	if !got.UserAgentChanged {
		t.Fatal("a changed User-Agent was not reported")
	}
}

func TestAuthenticateReportsExpiredSessions(t *testing.T) {
	a := newTestAuthenticator(t)
	a.Sessions = NewSessionStore(0, DefaultAbsoluteTTL, nil)
	id := a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(id)), AuthUnauthenticated, RejectionExpiredIdle)

	a.Sessions = NewSessionStore(DefaultIdleTTL, 0, nil)
	id = a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(id)), AuthUnauthenticated, RejectionExpiredAbsolute)
}

func TestAuthenticateRejectsUnprefixedCookieWhenSecureIsOn(t *testing.T) {
	a := newTestAuthenticator(t)
	id := a.Sessions.Create("test-agent")
	a.CookieSecure = true

	wantState(t, a.Authenticate(requestFor(id)), AuthUnauthenticated, RejectionAbsent)
}

func TestAuthenticateAcceptsThePrefixedCookieWhenSecureIsOn(t *testing.T) {
	a := newTestAuthenticator(t)
	a.CookieSecure = true
	id := a.Sessions.Create("test-agent")

	header := cookiePair(BuildSessionCookie(true, id))
	wantState(t, a.Authenticate(requestWithCookie(header)), AuthAuthenticated, RejectionNone)
}

func TestSessionIDReturnsTheIdentifierItWasGiven(t *testing.T) {
	a := newTestAuthenticator(t)
	id := a.Sessions.Create("test-agent")

	if got, ok := a.SessionID(requestFor(id)); !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
	if got, ok := a.SessionID(requestWithCookie("")); ok {
		t.Fatalf("SessionID of a bare request = %q", got)
	}
}

func TestTheLastCookieOfTheNameWins(t *testing.T) {
	a := newTestAuthenticator(t)
	id := a.Sessions.Create("test-agent")
	good := cookiePair(BuildSessionCookie(false, id))

	request := requestWithCookie(SessionCookie + "=junk")
	request.Header.Add("Cookie", good)
	if got, ok := a.SessionID(request); !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
}

func TestLoginRedirectTargetCarriesPathAndQuery(t *testing.T) {
	for _, tc := range []struct{ requested, want string }{
		{"/book/abc?mode=scroll", "/login?next=%2Fbook%2Fabc%3Fmode%3Dscroll"},
		// The '&' and '=' inside next must not read as parameters of /login, a
		// '+' must not come back as a space, and the '%' of an escape is escaped
		// again, so one decoding gives the requested URI back.
		{"/book/a%20b/caf%C3%A9?title=x%20y&k=a=b&p=1+1&n=漫", "/login?next=%2Fbook%2Fa%2520b%2Fcaf%25C3%25A9%3Ftitle%3Dx%2520y%26k%3Da%3Db%26p%3D1%2B1%26n%3D%E6%BC%AB"},
	} {
		requested, err := url.Parse(tc.requested)
		if err != nil {
			t.Fatal(err)
		}
		target := LoginRedirectTarget(requested)
		if target != tc.want {
			t.Errorf("target for %q = %q, want %q", tc.requested, target, tc.want)
		}
		login, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		next := login.Query().Get("next")
		if next != tc.requested || SafeNext(next) != next {
			t.Errorf("next for %q came back as %q (SafeNext: %q)", tc.requested, next, SafeNext(next))
		}
	}
}

func TestSafeNextBlocksOpenRedirects(t *testing.T) {
	for _, target := range []string{"//evil.example", "https://evil.example", "javascript:alert(1)", "",
		"/\t/evil.example", "/\t\\evil.example", "/a\tb"} {
		if got := SafeNext(target); got != "/" {
			t.Errorf("SafeNext(%q) = %q", target, got)
		}
	}
}

func TestSafeNextBlocksBackslashAuthorities(t *testing.T) {
	for _, target := range []string{
		`/\evil.example`,
		`/\/evil.example`,
		`/\\evil.example`,
		`/\evil.example/path`,
		`\evil.example`,
	} {
		if got := SafeNext(target); got != "/" {
			t.Errorf("%s was accepted as %q", target, got)
		}
	}
}

func TestSafeNextRejectsValuesAHeaderCannotCarry(t *testing.T) {
	for _, target := range []string{"/foo\nbar", "/foo\rbar", "/foo\r\nSet-Cookie: x=y", "/\x00", "/\x7f"} {
		if got := SafeNext(target); got != "/" {
			t.Errorf("%q was accepted as %q", target, got)
		}
	}
}

// next from the auth middleware is percent-encoded, so always ASCII.
func TestSafeNextStillAcceptsOrdinaryPaths(t *testing.T) {
	for _, target := range []string{"/", "/book/1f1c111677715adf", "/book/abc?page=2", "/a%20b", "/%09/evil.example"} {
		if got := SafeNext(target); got != target {
			t.Errorf("%q was rewritten to %q", target, got)
		}
	}
}
