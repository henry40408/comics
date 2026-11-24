package server

import (
	"cmp"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/henry40408/comics/internal/auth"
	"github.com/henry40408/comics/internal/views"
)

// maxLoginBodyBytes caps the login form body at 2 MiB.
const maxLoginBodyBytes = 2 << 20

// clearSiteData drops what the browser already holds (no-store only prevents
// new entries). The quotes are part of the header grammar. "executionContexts"
// is omitted: its forced reload would fight logout's own 303. Inert outside a
// secure context, e.g. plain-HTTP LAN.
const clearSiteData = `"cache", "cookies", "storage"`

type loginForm struct {
	username string
	password string
	next     string
}

// handleLoginPage renders the form, or redirects to next when auth is disabled
// or the visitor is already signed in.
func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := cmp.Or(r.URL.Query().Get("next"), "/")
	signedIn := a.authenticator.Authenticate(r).Kind == auth.AuthAuthenticated
	if a.creds == nil || signedIn {
		seeOther(w, auth.SafeNext(next))
		return
	}
	renderLogin(w, false, next)
}

// renderLogin sends the form. It is public, so noStoreHTML never sees it, yet
// it carries the error state and next.
func renderLogin(w http.ResponseWriter, failed bool, next string) {
	status := http.StatusOK
	if failed {
		status = http.StatusUnauthorized
	}
	setNoStore(w.Header())
	writeHTML(w, status, views.LoginPage(views.LoginView{Error: failed, Next: auth.SafeNext(next)}))
}

// handleLoginSubmit is POST /login. The form is read first, so a malformed
// request spends neither budget nor a verification slot. The throttle then runs
// before the credential check, so a throttled attempt learns nothing.
func (a *App) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	form, ok := readLoginForm(w, r)
	if !ok {
		return
	}
	ip := a.clientKeys.Key(r)
	userAgent := auth.UserAgent(r)
	if throttle := a.limiter.TryAcquire(ip); !throttle.Allowed {
		a.respondThrottled(w, throttle, ip.String(), userAgent)
		return
	}
	// Acquired after the throttle, so a refused attempt never queues.
	release, ok := a.acquireVerifySlot(r)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer release()
	if !auth.VerifyCredentials(a.creds, form.username, form.password) {
		// No credentials in the log: a password typed into the username field
		// would leak.
		a.logger.Warn("login failed", "event", "login_failed", "ip", ip.String(), "user_agent", userAgent)
		renderLogin(w, true, form.next)
		return
	}
	// Refund the attempt: only failures count against the windows.
	a.limiter.Release(ip)
	a.startSession(w, auth.SafeNext(form.next), ip.String(), userAgent)
}

// readLoginForm answers the error itself and reports false when the request is
// not an acceptable login form.
func readLoginForm(w http.ResponseWriter, r *http.Request) (loginForm, bool) {
	fail := func(status int) (loginForm, bool) {
		http.Error(w, http.StatusText(status), status)
		return loginForm{}, false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return fail(http.StatusUnsupportedMediaType)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLoginBodyBytes))
	if err != nil {
		return fail(bodyErrorStatus(err))
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || !values.Has("username") || !values.Has("password") {
		return fail(http.StatusUnprocessableEntity)
	}
	return loginForm{
		username: values.Get("username"),
		password: values.Get("password"),
		next:     cmp.Or(values.Get("next"), "/"),
	}, true
}

func bodyErrorStatus(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// acquireVerifySlot bounds concurrent Argon2id verifications (19 MiB each).
// It gives up when the client does, so an abandoned request frees its place.
func (a *App) acquireVerifySlot(r *http.Request) (release func(), ok bool) {
	select {
	case a.verifySem <- struct{}{}:
		return func() { <-a.verifySem }, true
	case <-r.Context().Done():
		return nil, false
	}
}

// respondThrottled is the 429 for a refused login, logged by which window
// refused it.
func (a *App) respondThrottled(w http.ResponseWriter, throttle auth.Throttle, ip, userAgent string) {
	// The global window is an account lockout (the reader is locked out too),
	// so it gets its own event name for alerting.
	if throttle.Scope == auth.ScopeGlobal {
		a.logger.Warn("login refused for every client address: the account-wide attempt "+
			"budget is spent, which also locks out legitimate sign-ins until the window passes",
			"event", "login_lockout", "retry_after_secs", throttle.RetryAfterSecs,
			"ip", ip, "user_agent", userAgent)
	} else {
		a.logger.Warn("login rate limited",
			"event", "login_rate_limited", "scope", string(throttle.Scope),
			"retry_after_secs", throttle.RetryAfterSecs, "ip", ip, "user_agent", userAgent)
	}
	w.Header().Set("Retry-After", strconv.Itoa(throttle.RetryAfterSecs))
	w.WriteHeader(http.StatusTooManyRequests)
}

// startSession opens a session, sends its signed cookie and redirects. The
// response carries a session ID, so OWASP wants no-store on it.
func (a *App) startSession(w http.ResponseWriter, location, ip, userAgent string) {
	id := a.sessions.Create(userAgent)
	cookie := a.signer.SignCookie(auth.BuildSessionCookie(a.cfg.CookieSecure, id))
	http.SetCookie(w, cookie)
	setNoStore(w.Header())
	seeOther(w, location)
	a.logger.Info("session created",
		"event", "session_created", "session", a.salt.Fingerprint(id),
		"ip", ip, "user_agent", userAgent)
}

// handleLogout is POST /logout: it ends every live session, clears the cookie
// and redirects to the login form.
//
// Server-side destruction is what counts; the removal cookie and
// Clear-Site-Data do nothing about a stolen copy. The route is public and the
// CSRF guard passes header-less clients, so store membership is what
// authorises the clear (see auth.SessionStore.DestroyAll).
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	ip := a.clientKeys.Key(r)
	id, hasSession := a.authenticator.SessionID(r)
	session, destroyed := "-", 0
	if hasSession {
		session = a.salt.Fingerprint(id)
		// Zero means nothing was ended: an expired cookie or a double submit.
		destroyed = a.sessions.DestroyAll(id)
	}
	a.logger.Info("session destroyed",
		"event", "session_destroyed", "session", session, "destroyed", destroyed,
		"ip", ip.String(), "user_agent", auth.UserAgent(r))

	http.SetCookie(w, auth.BuildSessionRemovalCookie(a.cfg.CookieSecure))
	w.Header().Set("Clear-Site-Data", clearSiteData)
	setNoStore(w.Header())
	seeOther(w, "/login")
}
