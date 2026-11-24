package auth

import (
	"net/http"
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

func TestVerifyRefusesTamperedShortAndForeignValues(t *testing.T) {
	signer := NewCookieSigner(randomSessionKey(t))
	signed := signer.Sign("value")

	for name, bad := range map[string]string{
		"tampered value": signed[:len(signed)-1] + "X",
		"short":          "abc",
		"empty":          "",
		"not base64":     strings.Repeat("!", signedDigestLen) + "value",
	} {
		if _, ok := signer.Verify(bad); ok {
			t.Errorf("%s verified", name)
		}
	}
	if _, ok := NewCookieSigner(randomSessionKey(t)).Verify(signed); ok {
		t.Error("a value verified under another key")
	}
}

// Pinned: HMAC-SHA256 keyed by the first 32 bytes of the session key, over the
// value alone, unpadded base64url digest first.
func TestSigningScheme(t *testing.T) {
	var key [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	signer := NewCookieSigner(key)
	const id = "0123456789abcdef0123456789abcdef"

	want := "Zvxm8ldaBq9fRkNFpJiFvsy3zx-SLH0SbT_jbDFoPgw" + id
	if got := signer.Sign(id); got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}
	if got := signer.SignCookie(BuildSessionCookie(false, id)).Value; got != want {
		t.Fatalf("SignCookie value = %q, want %q", got, want)
	}
}

func TestSignedCookiesNeedNoEscaping(t *testing.T) {
	signer := NewCookieSigner(randomSessionKey(t))
	cookie := signer.SignCookie(BuildSessionCookie(false, strings.Repeat("a", 32)))

	if strings.ContainsAny(cookie.Value, "/+=%") {
		t.Fatalf("value %q has characters that need escaping", cookie.Value)
	}
	if !strings.HasPrefix(cookie.String(), SessionCookie+"="+cookie.Value+";") {
		t.Fatalf("Set-Cookie %q altered the value", cookie.String())
	}
}

func TestSignedCookieRoundTripsThroughARequest(t *testing.T) {
	key := randomSessionKey(t)
	signer := NewCookieSigner(key)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create(testUA)

	setCookie := signer.SignCookie(BuildSessionCookie(false, id)).String()
	request := requestWithCookie("")
	request.Header.Set("Cookie", strings.SplitN(setCookie, ";", 2)[0])

	got, ok := a.SessionID(request)
	if !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
}

func TestSignCookieDoesNotMutateItsInput(t *testing.T) {
	cookie := &http.Cookie{Name: SessionCookie, Value: "v"}
	NewCookieSigner([64]byte{}).SignCookie(cookie)
	if cookie.Value != "v" {
		t.Fatalf("input mutated to %q", cookie.Value)
	}
}
