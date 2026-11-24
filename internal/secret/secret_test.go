package secret

import (
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

// Pins the decoding, which a nil-error check alone does not.
func TestDecodesEveryHexPairInOrder(t *testing.T) {
	for _, raw := range []string{valid, longer, strings.ToUpper(valid), "  " + valid + "\n"} {
		want := strings.ToLower(strings.TrimSpace(raw))
		if got := hex.EncodeToString(mustParse(t, raw).raw); got != want {
			t.Errorf("decoded %q, want %q", got, want)
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
	if mustParse(t, valid).IDSeed() == mustParse(t, longer).IDSeed() {
		t.Fatal("a prefix must not derive the same seed as the whole")
	}
}

func TestDifferentSecretsDeriveDifferentValues(t *testing.T) {
	a, b := mustParse(t, valid), mustParse(t, "ff"+valid[2:])
	if a.IDSeed() == b.IDSeed() {
		t.Error("same id seed")
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
	if a.IDSeed() == b.IDSeed() {
		t.Fatal("two generated secrets derived the same seed")
	}
}

func TestZeroValueSecretPanics(t *testing.T) {
	derivations := map[string]func(){
		"IDSeed": func() { Secret{}.IDSeed() },
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
