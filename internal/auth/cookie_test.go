package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestBuildSessionCookieSetsSecureWhenRequested(t *testing.T) {
	if !BuildSessionCookie(true, "id").Secure {
		t.Error("secure=true did not set Secure")
	}
	if BuildSessionCookie(false, "id").Secure {
		t.Error("secure=false set Secure")
	}
}

func TestSessionCookieNameIsPrefixedOnlyWhenSecure(t *testing.T) {
	if got := SessionCookieName(true); got != "__Host-comics_session" {
		t.Errorf("secure = %q", got)
	}
	if got := SessionCookieName(false); got != "comics_session" {
		t.Errorf("plain = %q", got)
	}
}

func TestBuildSessionCookieUsesThePrefixedNameWhenSecure(t *testing.T) {
	if got := BuildSessionCookie(true, "id").Name; got != "__Host-comics_session" {
		t.Errorf("secure = %q", got)
	}
	if got := BuildSessionCookie(false, "id").Name; got != "comics_session" {
		t.Errorf("plain = %q", got)
	}
}

func TestBuildSessionCookieValueIsTheBareIdentifier(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	cookie := BuildSessionCookie(false, id)
	if cookie.Value != id {
		t.Fatalf("value = %q", cookie.Value)
	}
	if !IsSessionID(cookie.Value) {
		t.Fatal("the cookie value is not a session id")
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

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer := NewCookieSigner(randomSessionKey(t))
	signed := signer.Sign("value")

	if got, ok := signer.Verify(signed); !ok || got != "value" {
		t.Fatalf("Verify = %q, %v", got, ok)
	}
	if len(signed) != signedDigestLen+len("value") {
		t.Fatalf("signed value has length %d", len(signed))
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

// Pinned against the cookie crate (0.18): HMAC-SHA256 keyed by the first 32
// bytes of the session key, over the value alone, base64 digest first.
func TestSigningMatchesTheCookieCrateScheme(t *testing.T) {
	var key [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	signer := NewCookieSigner(key)
	const id = "0123456789abcdef0123456789abcdef"

	want := "Zvxm8ldaBq9fRkNFpJiFvsy3zx+SLH0SbT/jbDFoPgw=" + id
	if got := signer.Sign(id); got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}

	// What the cookie crate puts on the wire for the same cookie.
	wire := "Zvxm8ldaBq9fRkNFpJiFvsy3zx+SLH0SbT%2FjbDFoPgw%3D" + id
	if got := signer.SignCookie(BuildSessionCookie(false, id)).Value; got != wire {
		t.Fatalf("SignCookie value = %q, want %q", got, wire)
	}
}

func TestSignedCookiesArePercentEncodedLikeTheCookieCrate(t *testing.T) {
	var key [64]byte
	signer := NewCookieSigner(key)
	cookie := signer.SignCookie(BuildSessionCookie(false, strings.Repeat("a", 32)))

	if strings.ContainsAny(cookie.Value, "/=") {
		t.Fatalf("value %q has unescaped / or =", cookie.Value)
	}
	if !strings.HasSuffix(cookie.Value, "%3D"+strings.Repeat("a", 32)) {
		t.Fatalf("value %q does not end with the escaped padding and the id", cookie.Value)
	}
}

func TestEncodingRoundTripsThroughARequest(t *testing.T) {
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

// A client that sends the value unescaped (as an earlier Go draft did) still
// authenticates: decoding is lenient.
func TestAnUnescapedSignedValueIsAlsoAccepted(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create(testUA)

	raw := SessionCookie + "=" + NewCookieSigner(key).Sign(id)
	if got, ok := a.SessionID(requestWithCookie(raw)); !ok || got != id {
		t.Fatalf("SessionID = %q, %v, want %q", got, ok, id)
	}
}

func TestDecodeCookieValueKeepsInvalidEscapesLiteral(t *testing.T) {
	cases := map[string]string{
		"a%3Db":  "a=b",
		"100%":   "100%",
		"%zz":    "%zz",
		"%2":     "%2",
		"plain":  "plain",
		"%2f%2F": "//",
	}
	for input, want := range cases {
		if got := decodeCookieValue(input); got != want {
			t.Errorf("decodeCookieValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSignCookieDoesNotMutateItsInput(t *testing.T) {
	cookie := &http.Cookie{Name: SessionCookie, Value: "v"}
	NewCookieSigner([64]byte{}).SignCookie(cookie)
	if cookie.Value != "v" {
		t.Fatalf("input mutated to %q", cookie.Value)
	}
}
