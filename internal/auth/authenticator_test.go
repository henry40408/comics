package auth

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func randomSessionKey(t *testing.T) [64]byte {
	t.Helper()
	var key [64]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

func newTestAuthenticator(t *testing.T, key [64]byte) *Authenticator {
	t.Helper()
	return &Authenticator{
		Enabled:  true,
		Signer:   NewCookieSigner(key),
		Sessions: newTestStore(),
		Salt:     NewAuditSalt(),
		Logger:   slog.New(slog.DiscardHandler),
	}
}

// signedHeader signs cookie with key and renders it as a browser Cookie header
// value.
func signedHeader(key [64]byte, cookie *http.Cookie) string {
	signed := NewCookieSigner(key).SignCookie(cookie)
	return signed.Name + "=" + signed.Value
}

func requestWithCookie(cookieHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if cookieHeader != "" {
		r.Header.Set("Cookie", cookieHeader)
	}
	return r
}

// requestFor is a request whose cookie is correctly signed and names id.
func requestFor(key [64]byte, id string) *http.Request {
	return requestWithCookie(signedHeader(key, BuildSessionCookie(false, id)))
}

func wantState(t *testing.T, got AuthState, kind AuthKind, why Rejection) {
	t.Helper()
	if got.Kind != kind || got.Rejection != why {
		t.Fatalf("state = %+v, want kind %d rejection %d", got, kind, why)
	}
}

func TestAuthenticatePublicWhenNoAuthConfig(t *testing.T) {
	a := newTestAuthenticator(t, randomSessionKey(t))
	a.Enabled = false
	wantState(t, a.Authenticate(requestWithCookie("")), AuthPublic, RejectionNone)
}

func TestAuthenticateAuthenticatedForALiveSession(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(key, id)), AuthAuthenticated, RejectionNone)
}

func TestAuthenticateReportsWhyItRefused(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)

	wantState(t, a.Authenticate(requestWithCookie("")), AuthUnauthenticated, RejectionAbsent)

	// Right name, never signed by this key.
	forged := SessionCookie + "=" + strings.Repeat("a", 32)
	wantState(t, a.Authenticate(requestWithCookie(forged)), AuthUnauthenticated, RejectionBadSignature)

	// Correctly signed, but not an identifier shape.
	malformed := signedHeader(key, &http.Cookie{Name: SessionCookie, Value: "not-an-id", Path: "/"})
	wantState(t, a.Authenticate(requestWithCookie(malformed)), AuthUnauthenticated, RejectionMalformed)

	// Well-formed and correctly signed, but never issued.
	wantState(t, a.Authenticate(requestFor(key, strings.Repeat("0", 32))), AuthUnauthenticated, RejectionUnknown)
}

func TestAuthenticateRejectsACookieSignedByAnotherKey(t *testing.T) {
	a := newTestAuthenticator(t, randomSessionKey(t))
	id := a.Sessions.Create("test-agent")
	request := requestFor(randomSessionKey(t), id)
	wantState(t, a.Authenticate(request), AuthUnauthenticated, RejectionBadSignature)
}

func TestAuthenticateSurfacesAChangedUserAgentWithoutRefusing(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("original-agent")

	request := requestFor(key, id)
	request.Header.Set("User-Agent", "a-different-agent")

	got := a.Authenticate(request)
	wantState(t, got, AuthAuthenticated, RejectionNone)
	if !got.UserAgentChanged {
		t.Fatal("a changed User-Agent was not reported")
	}
}

func TestAuthenticateReportsExpiredSessions(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	a.Sessions = NewSessionStore(0, DefaultAbsoluteTTL, nil)
	id := a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(key, id)), AuthUnauthenticated, RejectionExpiredIdle)

	a.Sessions = NewSessionStore(DefaultIdleTTL, 0, nil)
	id = a.Sessions.Create("test-agent")
	wantState(t, a.Authenticate(requestFor(key, id)), AuthUnauthenticated, RejectionExpiredAbsolute)
}

func TestAuthenticateRejectsUnprefixedCookieWhenSecureIsOn(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("test-agent")
	a.CookieSecure = true

	wantState(t, a.Authenticate(requestFor(key, id)), AuthUnauthenticated, RejectionAbsent)
}

func TestAuthenticateAcceptsThePrefixedCookieWhenSecureIsOn(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	a.CookieSecure = true
	id := a.Sessions.Create("test-agent")

	header := signedHeader(key, BuildSessionCookie(true, id))
	wantState(t, a.Authenticate(requestWithCookie(header)), AuthAuthenticated, RejectionNone)
}

func TestSessionIDReturnsTheIdentifierItWasGiven(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("test-agent")

	if got, ok := a.SessionID(requestFor(key, id)); !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
	if got, ok := a.SessionID(requestWithCookie("")); ok {
		t.Fatalf("SessionID of a bare request = %q", got)
	}
}

func TestTheLastCookieOfTheNameWins(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("test-agent")
	good := signedHeader(key, BuildSessionCookie(false, id))

	request := requestWithCookie(SessionCookie + "=junk")
	request.Header.Add("Cookie", good)
	if got, ok := a.SessionID(request); !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
}

func TestLoginRedirectTargetCarriesPathAndQuery(t *testing.T) {
	requested, err := url.Parse("/book/abc?mode=scroll")
	if err != nil {
		t.Fatal(err)
	}
	want := "/login?next=%2Fbook%2Fabc%3Fmode%3Dscroll"
	if got := LoginRedirectTarget(requested); got != want {
		t.Fatalf("target = %q, want %q", got, want)
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
