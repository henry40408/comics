package auth

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// AuthKind is the outcome class of Authenticator.Authenticate.
type AuthKind int

const (
	// AuthPublic: no credentials are configured; everything is public.
	AuthPublic AuthKind = iota
	// AuthAuthenticated: the cookie named a live session.
	AuthAuthenticated
	// AuthUnauthenticated: see AuthState.Rejection.
	AuthUnauthenticated
)

// Rejection is why a request was treated as unauthenticated. The reasons are
// logged at different levels: a bad signature cannot happen by accident, while
// every legitimate cookie becomes unknown after a restart.
type Rejection int

const (
	RejectionNone Rejection = iota
	// RejectionAbsent: no cookie of the accepted name.
	RejectionAbsent
	// RejectionBadSignature: not signed by this key; forged, or from a
	// different COMICS_SECRET.
	RejectionBadSignature
	// RejectionMalformed: correctly signed, but not a session identifier.
	RejectionMalformed
	// RejectionUnknown: names no live session.
	RejectionUnknown
	// RejectionExpiredIdle: the session was live and has just been ended.
	RejectionExpiredIdle
	// RejectionExpiredAbsolute: as above, past the absolute ceiling.
	RejectionExpiredAbsolute
)

// AuthState is what Authenticator.Authenticate decided.
type AuthState struct {
	Kind AuthKind
	// UserAgentChanged is worth logging, never acting on; see
	// Validation.UserAgentChanged.
	UserAgentChanged bool
	// Rejection is set when Kind is AuthUnauthenticated.
	Rejection Rejection
}

// Authenticator decides whether a request carries a live session.
type Authenticator struct {
	// Enabled is true when both a username and a password hash are configured.
	Enabled      bool
	CookieSecure bool
	Signer       CookieSigner
	Sessions     *SessionStore
	Salt         *AuditSalt
	Logger       *slog.Logger
}

// Authenticate applies three gates, cheapest first: signature, identifier
// shape, then the store, the only one that takes a lock or can say the session
// is live.
func (a *Authenticator) Authenticate(r *http.Request) AuthState {
	if !a.Enabled {
		return AuthState{Kind: AuthPublic}
	}
	id, why, ok := a.cookieSessionID(r)
	if !ok {
		return unauthenticated(why)
	}
	return a.validate(id, UserAgent(r))
}

func (a *Authenticator) validate(id, userAgent string) AuthState {
	validation := a.Sessions.Validate(id, userAgent)
	if !validation.Valid {
		return unauthenticated(validation.Rejection)
	}
	return AuthState{Kind: AuthAuthenticated, UserAgentChanged: validation.UserAgentChanged}
}

func unauthenticated(why Rejection) AuthState {
	return AuthState{Kind: AuthUnauthenticated, Rejection: why}
}

// SessionID is the verified session identifier from the request's cookie.
// Never log it directly: hash it with AuditSalt.
func (a *Authenticator) SessionID(r *http.Request) (string, bool) {
	id, _, ok := a.cookieSessionID(r)
	return id, ok
}

// cookieSessionID is the shared prefix of both lookups: it never touches the
// store, and names the first gate that refused.
func (a *Authenticator) cookieSessionID(r *http.Request) (id string, why Rejection, ok bool) {
	signed, found := cookieValue(r, SessionCookieName(a.CookieSecure))
	if !found {
		return "", RejectionAbsent, false
	}
	id, verified := a.Signer.Verify(signed)
	if !verified {
		return "", RejectionBadSignature, false
	}
	if !IsSessionID(id) {
		return "", RejectionMalformed, false
	}
	return id, 0, true
}

// SessionFingerprint is the audit-log form of the request's session: a salted
// hash, or "-" when the request has no verified session.
func (a *Authenticator) SessionFingerprint(r *http.Request) string {
	id, ok := a.SessionID(r)
	if !ok {
		return "-"
	}
	return a.Salt.Fingerprint(id)
}

// LogRejection records why a request was refused. Absent is silent (an
// ordinary anonymous visit). Unknown is DEBUG, since every cookie becomes
// unknown on restart. BadSignature and Malformed cannot happen by accident, so
// they WARN.
func (a *Authenticator) LogRejection(r *http.Request, why Rejection) {
	logger := a.logger()
	userAgent := UserAgent(r)
	switch why {
	case RejectionExpiredIdle:
		a.logExpired(logger, r, "idle")
	case RejectionExpiredAbsolute:
		a.logExpired(logger, r, "absolute")
	case RejectionBadSignature:
		logger.Warn("session cookie was not signed by this key",
			"event", "session_rejected", "reason", "bad_signature", "user_agent", userAgent)
	case RejectionMalformed:
		logger.Warn("session cookie is not a session identifier",
			"event", "session_rejected", "reason", "malformed", "user_agent", userAgent)
	case RejectionUnknown:
		logger.Debug("session cookie names no live session",
			"event", "session_rejected", "session", a.SessionFingerprint(r),
			"reason", "unknown", "user_agent", userAgent)
	}
}

func (a *Authenticator) logExpired(logger *slog.Logger, r *http.Request, reason string) {
	logger.Info("session expired",
		"event", "session_expired", "session", a.SessionFingerprint(r),
		"reason", reason, "user_agent", UserAgent(r))
}

// LogUserAgentChanged records a User-Agent change mid-session. Reported, never
// enforced.
func (a *Authenticator) LogUserAgentChanged(r *http.Request) {
	a.logger().Warn("User-Agent changed mid-session",
		"event", "session_user_agent_changed",
		"session", a.SessionFingerprint(r), "user_agent", UserAgent(r))
}

func (a *Authenticator) logger() *slog.Logger {
	if a.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Logger
}

// UserAgent is the request's User-Agent. A missing or non-ASCII value becomes
// "-", so every audit event carries the field and the store always has
// something stable to compare. A present but empty header stays empty.
func UserAgent(r *http.Request) string {
	values, present := r.Header["User-Agent"]
	if !present || !isVisibleASCII(values[0]) {
		return "-"
	}
	return values[0]
}

// LoginRedirectTarget is where an unauthenticated GET is sent: the login form,
// remembering the requested path and query.
func LoginRedirectTarget(requested *url.URL) string {
	return "/login?next=" + escapeNext(requested.RequestURI())
}

// escapeNext percent-encodes everything but A-Za-z0-9-_.~. QueryEscape writes a
// space as "+", so it becomes %20 to keep one spelling; a literal "+" is
// already %2B, so the replacement cannot touch it.
func escapeNext(next string) string {
	return strings.ReplaceAll(url.QueryEscape(next), "+", "%20")
}

// SafeNext constrains a post-login redirect target to a local path.
//
//   - A path, not an authority: "//evil.example" is protocol-relative, and
//     browsers read "/\evil.example" the same way (WHATWG treats "\" as "/" for
//     http(s)), so the second character must be neither.
//   - A valid header value: next arrives percent-decoded ("?next=/%0Ax" holds a
//     real newline), and a control byte in a Location header is a response
//     splitting vector, reachable anonymously via GET /login.
func SafeNext(next string) string {
	if !isLocalPath(next) || !isValidHeaderValue(next) {
		return "/"
	}
	return next
}

func isLocalPath(next string) bool {
	if next == "" || next[0] != '/' {
		return false
	}
	return len(next) == 1 || (next[1] != '/' && next[1] != '\\')
}

// isValidHeaderValue allows no control byte and no DEL; bytes of 0x80 and above
// are allowed. A tab is rejected too, although header values may contain one:
// URL parsing strips tabs, so a Location of "/\t/evil.example" would become
// "//evil.example", an open redirect.
func isValidHeaderValue(value string) bool {
	for i := range len(value) {
		b := value[i]
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}
