package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/auth"
)

func newAuthApp(t *testing.T, opts ...option) *testApp {
	t.Helper()
	return newTestApp(t, append([]option{withAuth()}, opts...)...)
}

// sessionCookieOf is the session cookie a successful login issued.
func sessionCookieOf(t *testing.T, res *response) *http.Cookie {
	t.Helper()
	cookie := res.cookie(sessionCookie)
	if cookie == nil {
		t.Fatalf("no session cookie in %v", res.setCookieLines())
	}
	return cookie
}

func TestAuthUnauthenticatedGetRedirectsToLogin(t *testing.T) {
	res := newAuthApp(t).get("/")
	assertStatus(t, 303, res, "GET /")
	if !strings.HasPrefix(res.location(), "/login") || !strings.Contains(res.location(), "next=") {
		t.Errorf("Location %q", res.location())
	}
	assertRedirectIsBare(t, res)
}

func TestAuthUnauthenticatedPostIsUnauthorized(t *testing.T) {
	assertStatus(t, 401, newAuthApp(t).post("/rescan"), "POST /rescan")
}

func TestAuthLoginPageIsPublic(t *testing.T) {
	res := newAuthApp(t).get("/login")
	assertStatus(t, 200, res, "GET /login")
	if !strings.Contains(res.text(), `action="/login"`) {
		t.Error("no login form")
	}
}

func TestAuthLoginSuccessSetsCookieAndGrantsAccess(t *testing.T) {
	ta := newAuthApp(t).browse()
	res := ta.post("/login", form(url.Values{"username": {"user"}, "password": {"password"}, "next": {"/"}}))
	assertStatus(t, 303, res, "POST /login")
	if res.location() != "/" {
		t.Errorf("Location %q", res.location())
	}
	sessionCookieOf(t, res)

	res = ta.get("/")
	assertStatus(t, 200, res, "GET /")
	if !strings.Contains(res.text(), "2 book(s)") {
		t.Error("index lacks the books")
	}
}

func TestAuthLoginCookieHasSecureWhenEnabled(t *testing.T) {
	res := newAuthApp(t, withCookieSecure()).login()
	lines := res.setCookieLines()
	if !slicesAny(lines, func(h string) bool { return strings.Contains(h, "Secure") }) {
		t.Errorf("expected a Secure attribute in %v", lines)
	}
}

// A browser drops a Secure cookie over plain HTTP.
func TestAuthLoginCookieHasNoSecureByDefault(t *testing.T) {
	lines := newAuthApp(t).login().setCookieLines()
	if len(lines) == 0 {
		t.Fatal("no Set-Cookie")
	}
	if slicesAny(lines, func(h string) bool { return strings.Contains(h, "Secure") }) {
		t.Errorf("unexpected Secure attribute in %v", lines)
	}
}

func slicesAny(lines []string, pred func(string) bool) bool {
	for _, line := range lines {
		if pred(line) {
			return true
		}
	}
	return false
}

func TestAuthLoginWrongPasswordIsUnauthorized(t *testing.T) {
	res := newAuthApp(t).failedLogin()
	assertStatus(t, 401, res, "wrong password")
	if res.cookie(sessionCookie) != nil {
		t.Error("a failed login set a session cookie")
	}
	if !strings.Contains(res.text(), "帳號或密碼錯誤") {
		t.Error("no error message")
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestAuthLoginSetsHostPrefixedCookieWhenSecure(t *testing.T) {
	lines := newAuthApp(t, withCookieSecure()).login().setCookieLines()
	var session string
	for _, line := range lines {
		if strings.HasPrefix(line, "__Host-comics_session=") {
			session = line
		}
	}
	if session == "" {
		t.Fatalf("no __Host- cookie in %v", lines)
	}
	if !strings.Contains(session, "Secure") || !strings.Contains(session, "Path=/") || strings.Contains(session, "Domain=") {
		t.Errorf("bad attributes: %s", session)
	}
}

// Deliberate: a server-side store is what makes logout enforceable.
func TestSessionsDoNotSurviveARouterRebuild(t *testing.T) {
	first := newAuthApp(t, withSecret(otherSecret))
	res := first.login()
	assertStatus(t, 303, res, "first login")
	cookie := sessionCookieOf(t, res)

	second := newAuthApp(t, withSecret(otherSecret))
	res = second.get("/", withCookie(cookie))
	assertStatus(t, 303, res, "a stale session was accepted")
	if !strings.HasPrefix(res.location(), "/login") {
		t.Errorf("Location %q", res.location())
	}
}

func TestSecretKeepsURLsStableAcrossRouterRebuild(t *testing.T) {
	bookIDs := func(ta *testApp) []string {
		ta.login()
		var ids []string
		for rest := ta.get("/").text(); ; {
			_, after, found := strings.Cut(rest, "/book/")
			if !found {
				return ids
			}
			id, remaining, _ := strings.Cut(after, `"`)
			ids = append(ids, id)
			rest = remaining
		}
	}
	// Not testSecret/dataIDs: the secret must be what makes them agree.
	before := bookIDs(newAuthApp(t, withSecret(otherSecret)).browse())
	after := bookIDs(newAuthApp(t, withSecret(otherSecret)).browse())
	if len(before) != 2 || strings.Join(before, ",") != strings.Join(after, ",") {
		t.Errorf("before %v, after %v", before, after)
	}
}

func TestSessionCookieValueIsABareIdentifier(t *testing.T) {
	cookie := sessionCookieOf(t, newAuthApp(t).login())
	// The signed value is <signature><id>.
	if strings.Contains(cookie.Value, ".") || len(cookie.Value) <= 32 {
		t.Fatalf("unexpected value %q", cookie.Value)
	}
	id := cookie.Value[len(cookie.Value)-32:]
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			t.Fatalf("id %q is not hex", id)
		}
	}
}

func TestAuthSuccessfulLoginsDoNotCountAgainstTheLimit(t *testing.T) {
	ta := newAuthApp(t)
	for attempt := 1; attempt <= auth.LoginMaxAttemptsPerIP+3; attempt++ {
		assertStatus(t, 303, ta.login(), "attempt "+strconv.Itoa(attempt))
	}
}

// The throttle runs before the credential check, so even the correct password
// gets a 429.
func TestAuthLoginIsRateLimitedAfterFiveAttempts(t *testing.T) {
	ta := newAuthApp(t)
	for attempt := 1; attempt <= auth.LoginMaxAttemptsPerIP; attempt++ {
		assertStatus(t, 401, ta.failedLogin(), "attempt "+strconv.Itoa(attempt))
	}
	assertStatus(t, 429, ta.failedLogin(), "sixth attempt")
	res := ta.login()
	assertStatus(t, 429, res, "correct password while throttled")
	if res.cookie(sessionCookie) != nil {
		t.Error("a throttled login set a cookie")
	}
}

func failedLoginFrom(ta *testApp, forwardedFor string) *response {
	return ta.failedLogin(withHeader("X-Forwarded-For", forwardedFor))
}

// Guards the Config to App to handler wiring no unit test sees.
func TestAuthTrustedProxyGivesEachForwardedClientItsOwnBudget(t *testing.T) {
	ta := newAuthApp(t, withTrustedProxies("127.0.0.1"))
	for attempt := 1; attempt <= auth.LoginMaxAttemptsPerIP; attempt++ {
		assertStatus(t, 401, failedLoginFrom(ta, "203.0.113.1"), "attempt "+strconv.Itoa(attempt))
	}
	assertStatus(t, 429, failedLoginFrom(ta, "203.0.113.1"), "exhausted client")
	assertStatus(t, 401, failedLoginFrom(ta, "203.0.113.2"), "another client")
}

func TestAuthUntrustedForwardedClientsShareOneBudget(t *testing.T) {
	ta := newAuthApp(t)
	for attempt := 1; attempt <= auth.LoginMaxAttemptsPerIP; attempt++ {
		assertStatus(t, 401, failedLoginFrom(ta, "203.0.113."+strconv.Itoa(attempt)), "attempt "+strconv.Itoa(attempt))
	}
	assertStatus(t, 429, failedLoginFrom(ta, "203.0.113.99"), "sixth, new address")
}

// Four addresses spend their budgets; a fifth, fresh one is still refused.
func TestAuthLoginIsThrottledAcrossAllClientAddresses(t *testing.T) {
	ta := newAuthApp(t, withTrustedProxies("127.0.0.1"))
	for client := 1; client <= auth.LoginMaxAttemptsGlobal/auth.LoginMaxAttemptsPerIP; client++ {
		for attempt := 1; attempt <= auth.LoginMaxAttemptsPerIP; attempt++ {
			res := failedLoginFrom(ta, "203.0.113."+strconv.Itoa(client))
			assertStatus(t, 401, res, "client "+strconv.Itoa(client)+", attempt "+strconv.Itoa(attempt))
		}
	}
	assertStatus(t, 429, failedLoginFrom(ta, "203.0.113.99"), "a fresh address got through")
}

func TestAuthLoginRedirectsSafely(t *testing.T) {
	ta := newAuthApp(t)
	res := ta.post("/login", form(url.Values{"username": {"user"}, "password": {"password"}, "next": {"https://evil.example"}}))
	assertStatus(t, 303, res, "POST /login")
	if res.location() != "/" {
		t.Errorf("Location %q", res.location())
	}
}

func TestSessionCookieIsSameSiteStrict(t *testing.T) {
	var issued string
	for _, line := range newAuthApp(t).login().setCookieLines() {
		if strings.HasPrefix(line, sessionCookie+"=") {
			issued = line
		}
	}
	if !strings.Contains(issued, "SameSite=Strict") || !strings.Contains(issued, "HttpOnly") {
		t.Errorf("issued %q", issued)
	}
}

// noStoreHTML does not reach these: they are public, and redirects.
func TestResponsesCarryingASessionCookieAreNotCacheable(t *testing.T) {
	ta := newAuthApp(t)
	res := ta.login()
	assertStatus(t, 303, res, "login")
	assertNoStore(t, res, "login success")

	res = ta.post("/logout", withCookie(sessionCookieOf(t, res)))
	assertStatus(t, 303, res, "logout")
	assertNoStore(t, res, "logout")

	assertNoStore(t, ta.failedLogin(), "login failure")
}

func assertNoStore(t *testing.T, res *response, what string) {
	t.Helper()
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
		t.Errorf("%s: Cache-Control %q, Pragma %q", what, res.Header.Get("Cache-Control"), res.Header.Get("Pragma"))
	}
}

// A browser resolves /\evil.example to //evil.example.
func TestAuthLoginRejectsBackslashRedirectTargets(t *testing.T) {
	res := newAuthApp(t).post("/login", form(url.Values{"username": {"user"}, "password": {"password"}, "next": {`/\evil.example`}}))
	assertStatus(t, 303, res, "POST /login")
	if res.location() != "/" {
		t.Errorf("Location %q", res.location())
	}
}

// next arrives percent-decoded; a header-hostile value must still be answered.
func TestLoginSurvivesAControlCharacterInNext(t *testing.T) {
	res := newTestApp(t).get("/login?next=%2F%0Ax")
	assertStatus(t, 303, res, "GET /login")
	if res.location() != "/" {
		t.Errorf("Location %q", res.location())
	}
}

func TestWithoutANextParameterLoginReturnsToTheFrontPage(t *testing.T) {
	res := newAuthApp(t).post("/login", form(credentials("user", "password")))
	assertStatus(t, 303, res, "POST /login")
	if res.location() != "/" {
		t.Errorf("Location %q", res.location())
	}
}

func TestLoginPageRedirectsASignedInVisitor(t *testing.T) {
	ta := newAuthApp(t).browse()
	ta.login()
	res := ta.get("/login?next=/book/abc")
	assertStatus(t, 303, res, "GET /login")
	if res.location() != "/book/abc" {
		t.Errorf("Location %q", res.location())
	}
}

// Replayed by hand, not via the jar: a copied cookie must die with the
// server-side session.
func TestAuthLogoutInvalidatesTheSessionServerSide(t *testing.T) {
	ta := newAuthApp(t)
	cookie := sessionCookieOf(t, ta.login())
	assertStatus(t, 200, ta.get("/", withCookie(cookie)), "fresh session")
	assertStatus(t, 303, ta.post("/logout", withCookie(cookie)), "logout")
	res := ta.get("/", withCookie(cookie))
	assertStatus(t, 303, res, "a destroyed session was still accepted")
	if !strings.HasPrefix(res.location(), "/login") {
		t.Errorf("Location %q", res.location())
	}
}

// Logout ends every session, so signing out anywhere kills a stolen cookie.
func TestAuthLogoutEndsSessionsOnOtherDevices(t *testing.T) {
	ta := newAuthApp(t)
	phone := sessionCookieOf(t, ta.login())
	desktop := sessionCookieOf(t, ta.login())
	if phone.Value == desktop.Value {
		t.Fatal("the two logins should be distinct sessions")
	}
	assertStatus(t, 303, ta.post("/logout", withCookie(phone)), "logout")
	assertStatus(t, 303, ta.get("/", withCookie(desktop)), "the other device's session outlived the logout")
}

// /logout is public and the CSRF guard passes header-less clients, so store
// membership must be what authorises the clear.
func TestAuthAnonymousLogoutEndsNothing(t *testing.T) {
	ta := newAuthApp(t)
	cookie := sessionCookieOf(t, ta.login())
	assertStatus(t, 303, ta.post("/logout"), "anonymous logout")
	assertStatus(t, 200, ta.get("/", withCookie(cookie)), "an anonymous logout ended a live session")
}

func TestAuthLogoutClearsSession(t *testing.T) {
	ta := newAuthApp(t).browse()
	ta.login()
	assertStatus(t, 200, ta.get("/"), "signed in")

	res := ta.post("/logout")
	assertStatus(t, 303, res, "logout")
	if res.location() != "/login" {
		t.Errorf("Location %q", res.location())
	}
	if got := res.Header.Get("Clear-Site-Data"); got != `"cache", "cookies", "storage"` {
		t.Errorf("Clear-Site-Data = %q", got)
	}
	var removal string
	for _, line := range res.setCookieLines() {
		if strings.HasPrefix(line, sessionCookie+"=") {
			removal = line
		}
	}
	// Must mirror the issued cookie, or the browser treats it as another.
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=0"} {
		if !strings.Contains(removal, want) {
			t.Errorf("removal cookie %q lacks %s", removal, want)
		}
	}
	assertStatus(t, 303, ta.get("/"), "after logout")
}

func TestAuthPublicRoutesNeedNoLogin(t *testing.T) {
	ta := newAuthApp(t)
	for _, path := range []string{"/healthz", "/assets/app.css", "/assets/app.js", "/assets/theme.js", "/favicon.svg", "/favicon-32.png", "/apple-touch-icon.png"} {
		assertStatus(t, 200, ta.get(path), "GET "+path)
	}
}

// Guards against a route slipping out from under the middleware.
func TestAuthEveryProtectedRouteRejectsAnonymous(t *testing.T) {
	ta := newAuthApp(t)
	book := dataIDs[0]
	// A bogus id still redirects: auth runs before the handler.
	for _, path := range []string{"/", "/book/" + book, "/data/" + book, "/thumb/md/" + book} {
		res := ta.get(path)
		assertStatus(t, 303, res, "GET "+path)
		if !strings.HasPrefix(res.location(), "/login") {
			t.Errorf("GET %s -> %s", path, res.location())
		}
	}
	for _, path := range []string{"/rescan", "/shuffle", "/shuffle/" + book} {
		assertStatus(t, 401, ta.post(path), "POST "+path)
	}
}

func TestAuthEveryProtectedRouteReachableWhenLoggedIn(t *testing.T) {
	ta := newAuthApp(t).browse()
	ta.login()
	book := dataIDs[0]
	assertStatus(t, 200, ta.get("/"), "GET /")
	assertStatus(t, 200, ta.get("/book/"+book), "GET /book")
	assertStatus(t, 303, ta.post("/rescan"), "POST /rescan")
	assertStatus(t, 303, ta.post("/shuffle"), "POST /shuffle")
	assertStatus(t, 303, ta.post("/shuffle/"+book), "POST /shuffle/{id}")
	// 404, not a redirect, proves auth passed.
	assertStatus(t, 404, ta.get("/data/deadbeef"), "GET /data")
	assertStatus(t, 404, ta.get("/thumb/md/deadbeef"), "GET /thumb")
}

func TestAnonymousHeadIsUnauthorizedNotRedirected(t *testing.T) {
	assertStatus(t, 401, newAuthApp(t).do(http.MethodHead, "/"), "HEAD /")
}

func TestAuthDisabledLoginPageGoesStraightToNext(t *testing.T) {
	res := newTestApp(t).get("/login?next=/book/abc")
	assertStatus(t, 303, res, "GET /login")
	if res.location() != "/book/abc" {
		t.Errorf("Location %q", res.location())
	}
}

func TestLoginRejectsWrongMediaTypeAndMalformedForms(t *testing.T) {
	ta := newAuthApp(t)
	raw := func(contentType, body string) *response {
		return ta.post("/login", func(r *http.Request) {
			r.Body = http.NoBody
			if body != "" {
				r.Body = nopCloser(body)
				r.ContentLength = int64(len(body))
			}
			if contentType != "" {
				r.Header.Set("Content-Type", contentType)
			}
		})
	}
	assertStatus(t, 415, raw("application/json", `{"username":"user"}`), "json")
	assertStatus(t, 415, raw("", "username=user&password=password"), "no content type")
	assertStatus(t, 422, raw("application/x-www-form-urlencoded", "username=user"), "missing password")
	assertStatus(t, 422, raw("application/x-www-form-urlencoded", "username=%zz&password=x"), "bad escape")
	// Malformed forms spend no throttle budget: the correct login still works.
	assertStatus(t, 303, ta.login(), "login after malformed forms")
}

func TestLoginBodyOverTwoMebibytesIsRefused(t *testing.T) {
	ta := newAuthApp(t)
	body := "username=user&password=" + strings.Repeat("x", maxLoginBodyBytes)
	res := ta.post("/login", form(url.Values{}), func(r *http.Request) {
		r.Body = nopCloser(body)
		r.ContentLength = int64(len(body))
	})
	assertStatus(t, 413, res, "oversized body")
}

// A server fault must not read as a wrong password, or the reader keeps
// retyping a correct one. Go has no closable semaphore: a full one and a
// request that gives up while waiting is the equivalent.
func TestAFullVerificationQueueIsNotReportedAsABadPassword(t *testing.T) {
	ta := newAuthApp(t)
	for range cap(ta.app.verifySem) {
		ta.app.verifySem <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(credentials("user", "password").Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	ta.app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", rec.Code)
	}
}

func TestVerifySemaphoresHaveTheDocumentedCapacity(t *testing.T) {
	app := newAuthApp(t).app
	if got := cap(app.verifySem); got != auth.MaxConcurrentVerifications {
		t.Errorf("verifySem cap %d, want %d", got, auth.MaxConcurrentVerifications)
	}
	if cap(app.thumbSem) < 1 {
		t.Error("thumbSem has no capacity")
	}
}

// --- log capture ----------------------------------------------------------

// postLoginFrom posts straight to the handler so the peer address is chosen.
func postLoginFrom(app *App, peer string, values url.Values, mods ...requestMod) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = peer
	for _, mod := range mods {
		mod(req)
	}
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	return rec
}

// Only a salted hash of the identifier may be logged.
func TestSessionEventsDoNotLeakTheCookieValue(t *testing.T) {
	ta := newAuthApp(t)
	res := ta.login()
	cookie := sessionCookieOf(t, res)
	id := cookie.Value[len(cookie.Value)-32:]

	logs := ta.logs.String()
	if !strings.Contains(logs, "session_created") {
		t.Errorf("no session_created in %s", logs)
	}
	if !strings.Contains(logs, ta.app.salt.Fingerprint(id)) {
		t.Errorf("expected the fingerprint in %s", logs)
	}
	if strings.Contains(logs, id) || strings.Contains(logs, cookie.Value) {
		t.Errorf("identifier leaked into %s", logs)
	}

	ta.post("/logout", withCookie(cookie))
	logs = ta.logs.String()
	if !strings.Contains(logs, "session_destroyed") || strings.Contains(logs, id) {
		t.Errorf("logout log wrong or leaking: %s", logs)
	}
}

func TestFailedLoginLogsNoCredentials(t *testing.T) {
	ta := newAuthApp(t)
	res := ta.post("/login", form(credentials("alice-the-user", "hunter2")))
	assertStatus(t, 401, res, "failed login")
	logs := ta.logs.String()
	if !strings.Contains(logs, "login_failed") {
		t.Errorf("no login_failed in %s", logs)
	}
	for _, secret := range []string{"hunter2", "alice-the-user"} {
		if strings.Contains(logs, secret) {
			t.Errorf("%q leaked into %s", secret, logs)
		}
	}
}

// Operators' filters match on the event name; scope names the window.
func TestAPerIPThrottleKeepsItsEventName(t *testing.T) {
	ta := newAuthApp(t)
	ta.app.limiter = auth.NewRateLimiter(1, 100, 60, nil)
	assertStatus(t, 401, ta.failedLogin(), "first")
	assertStatus(t, 429, ta.failedLogin(), "second")
	logs := ta.logs.String()
	if !strings.Contains(logs, "login_rate_limited") || !strings.Contains(logs, "per_ip") || strings.Contains(logs, "login_lockout") {
		t.Errorf("unexpected log: %s", logs)
	}
}

func TestAGlobalLockoutLogsItsOwnEvent(t *testing.T) {
	ta := newAuthApp(t)
	ta.app.limiter = auth.NewRateLimiter(100, 1, 60, nil)
	assertStatus(t, 401, ta.failedLogin(), "first")
	assertStatus(t, 429, ta.failedLogin(), "second")
	logs := ta.logs.String()
	if !strings.Contains(logs, "login_lockout") || strings.Contains(logs, "login_rate_limited") {
		t.Errorf("the lockout was logged wrongly: %s", logs)
	}
}

func TestTheClientKeyIsTheTCPPeerWhenNoProxyIsTrusted(t *testing.T) {
	ta := newAuthApp(t)
	postLoginFrom(ta.app, "203.0.113.7:4000", credentials("user", "nope"), withHeader("X-Forwarded-For", "198.51.100.1"))
	logs := ta.logs.String()
	if !strings.Contains(logs, "ip=203.0.113.7") || strings.Contains(logs, "198.51.100.1") {
		t.Errorf("unexpected client key: %s", logs)
	}
}

func TestAThrottledLoginSaysWhenToRetry(t *testing.T) {
	ta := newAuthApp(t)
	ta.app.limiter = auth.NewRateLimiter(1, 100, 60, nil)
	ta.failedLogin()
	res := ta.failedLogin()
	assertStatus(t, 429, res, "second")
	seconds, err := strconv.Atoi(res.Header.Get("Retry-After"))
	if err != nil || seconds < 1 || seconds > 60 {
		t.Errorf("Retry-After %q", res.Header.Get("Retry-After"))
	}
	if len(res.body) != 0 {
		t.Errorf("429 body %q, want empty", res.body)
	}
}
