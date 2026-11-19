package secret

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// What `openssl rand -hex 32` emits.
const valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The length is a floor, not a fixed size.
const longer = valid + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func mustParse(t *testing.T, raw string) Secret {
	t.Helper()
	s, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	return s
}

func signingKey(s Secret) []byte {
	key := s.SessionKey()
	return key[:32]
}

func TestAccepts64HexCharsAndLonger(t *testing.T) {
	for _, raw := range []string{valid, longer, "  " + valid + "\n", strings.ToUpper(valid)} {
		if _, err := Parse(raw); err != nil {
			t.Errorf("Parse(%q): %v", raw, err)
		}
	}
}

// Pins the decoding, which a nil-error check alone does not.
func TestDecodesEveryHexPairInOrder(t *testing.T) {
	for _, raw := range []string{valid, longer, strings.ToUpper(valid)} {
		if got := hex.EncodeToString(mustParse(t, raw).raw); got != strings.ToLower(raw) {
			t.Errorf("decoded %q, want %q", got, strings.ToLower(raw))
		}
	}
}

func TestRejectsShortOddAndNonHex(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"short", "abcd", "at least 64 hex characters"},
		{"length reported", valid[:63], "got 63"},
		{"odd", valid + "a", "even number"},
		{"non hex", "zz" + valid[2:], "hex characters only"},
	}
	for _, c := range cases {
		_, err := Parse(c.raw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v does not contain %q", c.name, err, c.want)
		}
	}
}

// A longer secret is a different secret, not the same one padded.
func TestLengthIsPartOfTheSecret(t *testing.T) {
	if bytes.Equal(signingKey(mustParse(t, valid)), signingKey(mustParse(t, longer))) {
		t.Fatal("a prefix must not derive the same key as the whole")
	}
}

func TestDerivationIsDeterministic(t *testing.T) {
	a, b := mustParse(t, valid), mustParse(t, valid)
	if !bytes.Equal(signingKey(a), signingKey(b)) || a.IDSeed() != b.IDSeed() {
		t.Fatal("same secret derived different values")
	}
}

func TestDifferentSecretsDeriveDifferentValues(t *testing.T) {
	a, b := mustParse(t, valid), mustParse(t, "ff"+valid[2:])
	if bytes.Equal(signingKey(a), signingKey(b)) {
		t.Error("same signing key")
	}
	if a.IDSeed() == b.IDSeed() {
		t.Error("same id seed")
	}
}

func TestTheIDSeedIsNotAPrefixOfTheSigningKey(t *testing.T) {
	s := mustParse(t, valid)
	seed := s.IDSeed()
	seedBytes := []byte{
		byte(seed >> 56), byte(seed >> 48), byte(seed >> 40), byte(seed >> 32),
		byte(seed >> 24), byte(seed >> 16), byte(seed >> 8), byte(seed),
	}
	if bytes.Contains(signingKey(s), seedBytes) {
		t.Fatal("the id seed appears verbatim in the signing key")
	}
}

func TestPrintingDoesNotLeakTheSecret(t *testing.T) {
	s := mustParse(t, valid)
	for _, rendered := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s),
		fmt.Sprintf("%v", &s), fmt.Sprintf("%+v", struct{ S Secret }{s}),
	} {
		if !strings.Contains(rendered, "Secret([redacted])") || strings.Contains(rendered, "0123") {
			t.Errorf("leaky rendering %q", rendered)
		}
	}
}

func TestGenerateProducesDistinctSecrets(t *testing.T) {
	a, b := Generate(), Generate()
	if bytes.Equal(signingKey(a), signingKey(b)) {
		t.Fatal("two generated secrets derived the same key")
	}
}

func TestZeroValueSecretPanics(t *testing.T) {
	derivations := map[string]func(){
		"SessionKey": func() { Secret{}.SessionKey() },
		"IDSeed":     func() { Secret{}.IDSeed() },
	}
	for name, derive := range derivations {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "zero-value Secret") {
					t.Errorf("%s: recovered %v, want a zero-value Secret panic", name, r)
				}
			}()
			derive()
		}()
	}
}
