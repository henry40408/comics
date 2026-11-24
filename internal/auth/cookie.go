package auth

import "net/http"

// SessionCookie is the base name of the session cookie, without the __Host-
// prefix.
const SessionCookie = "comics_session"

const sessionCookieHostPrefixed = "__Host-comics_session"

// SessionCookieName is the cookie name, __Host- prefixed when secure.
//
// The prefix has the browser guarantee a host-only, HTTPS, Path=/ cookie,
// closing subdomain overwrites as a session-fixation vector. Only when secure:
// browsers reject a __Host- cookie without Secure, which would silently break
// login on plain-HTTP LAN hosts.
func SessionCookieName(secure bool) string {
	if secure {
		return sessionCookieHostPrefixed
	}
	return SessionCookie
}

// BuildSessionCookie is the cookie that carries id. The value is the store's
// opaque identifier and nothing else.
//
// secure is configurable because browsers silently discard a Secure cookie
// over plain HTTP, which would lock LAN deployments out with no visible error.
//
// SameSite=Strict is affordable here (no OAuth or third-party entry points);
// the cost is that an external link to a book lands on the login form once.
//
// Max-Age is a browser hint only; the server enforces both deadlines.
func BuildSessionCookie(secure bool, id string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName(secure),
		Value:    id,
		Path:     "/",
		MaxAge:   int(DefaultAbsoluteTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// BuildSessionRemovalCookie must mirror BuildSessionCookie in every attribute:
// browsers match a removal on name, Path and Domain, and reject a __Host- name
// without Secure.
func BuildSessionRemovalCookie(secure bool) *http.Cookie {
	cookie := BuildSessionCookie(secure, "")
	// net/http writes Max-Age=0 for a negative MaxAge and omits it for zero.
	cookie.MaxAge = -1
	return cookie
}

// CookieSigner is an empty shell, kept only so the frozen tests still compile;
// removed in the next production commit. The session cookie is no longer
// signed.
type CookieSigner struct{}

// NewCookieSigner ignores key; kept only so the frozen tests still compile,
// removed in the next production commit.
func NewCookieSigner(key [64]byte) CookieSigner {
	return CookieSigner{}
}

// SignCookie returns cookie unchanged; kept only so the frozen tests still
// compile, removed in the next production commit.
func (CookieSigner) SignCookie(cookie *http.Cookie) *http.Cookie {
	return cookie
}

// cookieValue is the value of the last cookie called name in the request, which
// is the one a cookie jar keeps.
func cookieValue(r *http.Request, name string) (string, bool) {
	value, found := "", false
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value, found = cookie.Value, true
		}
	}
	return value, found
}
