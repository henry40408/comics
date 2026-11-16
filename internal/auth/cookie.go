package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
)

// SessionCookie is the base name of the signed session cookie, without the
// __Host- prefix.
const SessionCookie = "comics_session"

const sessionCookieHostPrefixed = "__Host-comics_session"

// signedDigestLen is the length of a base64-encoded HMAC-SHA256 digest.
const signedDigestLen = 44

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
// opaque identifier and nothing else; sign it with CookieSigner.SignCookie
// before sending.
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

// CookieSigner signs and verifies cookie values with the cookie crate's scheme
// (HMAC-SHA256 over the value alone, base64 digest prepended to the value), so
// cookies issued by the Rust implementation stay valid. The cookie name is not
// part of what is signed; the one accepted name is enforced by the lookup.
type CookieSigner struct {
	key [32]byte
}

// NewCookieSigner takes the signing half of secret.Secret.SessionKey().
func NewCookieSigner(sessionKey [64]byte) CookieSigner {
	var signer CookieSigner
	copy(signer.key[:], sessionKey[:32])
	return signer
}

func (s CookieSigner) digest(value string) []byte {
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// Sign returns the signed form of value.
func (s CookieSigner) Sign(value string) string {
	return base64.StdEncoding.EncodeToString(s.digest(value)) + value
}

// Verify splits a signed value and checks its digest, returning the original
// value.
func (s CookieSigner) Verify(signed string) (string, bool) {
	if len(signed) < signedDigestLen {
		return "", false
	}
	digest, err := base64.StdEncoding.DecodeString(signed[:signedDigestLen])
	if err != nil {
		return "", false
	}
	value := signed[signedDigestLen:]
	if !hmac.Equal(digest, s.digest(value)) {
		return "", false
	}
	return value, true
}

// SignCookie returns a copy of cookie with its value signed and
// percent-encoded, ready for Set-Cookie. The encoding matches the Rust
// implementation byte for byte (base64's "/" and "=" become %2F and %3D).
func (s CookieSigner) SignCookie(cookie *http.Cookie) *http.Cookie {
	signed := *cookie
	signed.Value = encodeCookieValue(s.Sign(cookie.Value))
	return &signed
}

// cookieValue is the value of the last cookie called name in the request, which
// is the one a cookie jar keeps. It is percent-decoded, undoing SignCookie.
func cookieValue(r *http.Request, name string) (string, bool) {
	value, found := "", false
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value, found = decodeCookieValue(cookie.Value), true
		}
	}
	return value, found
}

const upperHex = "0123456789ABCDEF"

// needsCookieEscape reports whether b is in the cookie crate's percent-encode
// set: controls, non-ASCII, and the characters RFC 6265 and the URL spec's
// userinfo set reserve.
func needsCookieEscape(b byte) bool {
	if b < 0x20 || b >= 0x7f {
		return true
	}
	return strings.IndexByte(" \"<>`#?{}/:;=@[\\]^|%(),", b) >= 0
}

func encodeCookieValue(value string) string {
	var out strings.Builder
	for i := range len(value) {
		b := value[i]
		if !needsCookieEscape(b) {
			out.WriteByte(b)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(upperHex[b>>4])
		out.WriteByte(upperHex[b&0x0f])
	}
	return out.String()
}

// decodeCookieValue is a lenient percent-decode: a "%" not followed by two hex
// digits stays literal.
func decodeCookieValue(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) && isHexDigit(value[i+1]) && isHexDigit(value[i+2]) {
			decoded, _ := strconv.ParseUint(value[i+1:i+3], 16, 8)
			out.WriteByte(byte(decoded))
			i += 2
			continue
		}
		out.WriteByte(value[i])
	}
	return out.String()
}
