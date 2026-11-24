package auth

import (
	"strings"
	"testing"
)

func TestSessionCookieNameIsPrefixedOnlyWhenSecure(t *testing.T) {
	if got := SessionCookieName(true); got != "__Host-comics_session" {
		t.Errorf("secure = %q", got)
	}
	if got := SessionCookieName(false); got != "comics_session" {
		t.Errorf("plain = %q", got)
	}
}

func TestTheSessionCookieCarriesTheDocumentedAttributes(t *testing.T) {
	header := BuildSessionCookie(true, "id").String()
	for _, want := range []string{"Path=/", "Max-Age=604800", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(header, want) {
			t.Errorf("%q lacks %q", header, want)
		}
	}
	if strings.Contains(BuildSessionCookie(false, "id").String(), "Secure") {
		t.Error("a non-secure cookie carries Secure")
	}
}

func TestRemovalCookieMirrorsTheSessionCookie(t *testing.T) {
	for _, secure := range []bool{false, true} {
		issued := BuildSessionCookie(secure, "id")
		removal := BuildSessionRemovalCookie(secure)

		if issued.Name != removal.Name || issued.Path != removal.Path ||
			issued.HttpOnly != removal.HttpOnly || issued.SameSite != removal.SameSite ||
			issued.Secure != removal.Secure || issued.Domain != removal.Domain {
			t.Errorf("secure=%v: removal %+v does not mirror %+v", secure, removal, issued)
		}
		if removal.Value != "" {
			t.Errorf("secure=%v: removal value = %q", secure, removal.Value)
		}
		// net/http writes Max-Age=0 for a negative MaxAge and omits it for zero.
		if !strings.Contains(removal.String(), "Max-Age=0") {
			t.Errorf("secure=%v: %q does not expire the cookie", secure, removal.String())
		}
	}
}
