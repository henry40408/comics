package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestASessionIsExpiredExactlyWhenItsAbsoluteLifetimeIsReached(t *testing.T) {
	clock := &fakeClock{elapsed: 10 * time.Hour}
	store := NewSessionStore(100*time.Hour, 2*time.Hour, clock.now)
	id := store.Create(testUA)

	clock.advance(2*time.Hour - time.Nanosecond)
	if !isLive(store, id) {
		t.Fatal("session expired one nanosecond before its absolute lifetime")
	}
	clock.advance(time.Nanosecond)
	want := Validation{Rejection: RejectionExpiredAbsolute}
	if got := store.Validate(id, testUA); got != want {
		t.Fatalf("Validate = %+v, want %+v", got, want)
	}
}

func TestCreateDropsASessionExactlyWhenItsAbsoluteLifetimeIsReached(t *testing.T) {
	for name, tc := range map[string]struct {
		advance time.Duration
		wantLen int
	}{
		"one nanosecond before": {2*time.Hour - time.Nanosecond, 2},
		"exactly at":            {2 * time.Hour, 1},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{elapsed: 10 * time.Hour}
			store := NewSessionStore(100*time.Hour, 2*time.Hour, clock.now)
			store.Create(testUA)
			clock.advance(tc.advance)
			store.Create(testUA)
			if got := store.Len(); got != tc.wantLen {
				t.Fatalf("Len = %d, want %d", got, tc.wantLen)
			}
		})
	}
}

func TestSessionIDShapeAcceptsOnlyHexDigits(t *testing.T) {
	for _, c := range "09afAF" {
		if id := strings.Repeat(string(c), SessionIDHexLen); !IsSessionID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, c := range "/:`g@G" {
		id := strings.Repeat("a", SessionIDHexLen-1) + string(c)
		if IsSessionID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}

func TestVerifyAcceptsASignatureOfExactlyTheDigestLength(t *testing.T) {
	signer := NewCookieSigner(randomSessionKey(t))
	signed := signer.Sign("")
	if len(signed) != signedDigestLen {
		t.Fatalf("signed empty value has length %d, want %d", len(signed), signedDigestLen)
	}
	if got, ok := signer.Verify(signed); !ok || got != "" {
		t.Fatalf("Verify = %q, %v, want empty value accepted", got, ok)
	}
	if _, ok := signer.Verify(signed[:signedDigestLen-1]); ok {
		t.Fatal("a signature one byte short verified")
	}
}

func TestURLEncodeKeepsTheUnreservedRangesIncludingTheirEnds(t *testing.T) {
	for _, kept := range []string{"A", "Z", "a", "z", "0", "9"} {
		if got := escapeNext(kept); got != kept {
			t.Errorf("escapeNext(%q) = %q, want it unchanged", kept, got)
		}
	}
	for in, want := range map[string]string{"@": "%40", "[": "%5B", "`": "%60", "{": "%7B", "/": "%2F", ":": "%3A"} {
		if got := escapeNext(in); got != want {
			t.Errorf("escapeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeNextHeaderValueByteBoundaries(t *testing.T) {
	for _, next := range []string{"/ a", "/~", "/é"} {
		if got := SafeNext(next); got != next {
			t.Errorf("SafeNext(%q) = %q, want it kept", next, got)
		}
	}
	for _, next := range []string{"/\x1f", "/\x7f", "/\t"} {
		if got := SafeNext(next); got != "/" {
			t.Errorf("SafeNext(%q) = %q, want /", next, got)
		}
	}
}

func TestUserAgentVisibleASCIIBoundaries(t *testing.T) {
	for ua, want := range map[string]string{
		" ":    " ",
		"~":    "~",
		"a\tb": "a\tb",
		"\x1f": "-",
		"\x7f": "-",
	} {
		r := &http.Request{Header: http.Header{"User-Agent": {ua}}}
		if got := UserAgent(r); got != want {
			t.Errorf("UserAgent(%q) = %q, want %q", ua, got, want)
		}
	}
}

const (
	saltOf8Bytes = "AAAAAAAAAAA"
	saltOf7Bytes = "AAAAAAAAAA"
	digestOf4    = "AAAAAA"
	digestOf3    = "AAAA"
)

func TestParsePasswordHashBoundaries(t *testing.T) {
	const ok = "$argon2id$v=19$m=19456,t=2,p=1$"
	for name, tc := range map[string]struct {
		phc     string
		wantErr bool
	}{
		"algorithm and salt only":           {"$argon2id$" + saltOf8Bytes, true},
		"version only, no salt":             {"$argon2id$v=19", true},
		"salt and no digest":                {ok + saltOf8Bytes, true},
		"salt of exactly the minimum":       {ok + saltOf8Bytes + "$" + digestOf4, false},
		"salt one byte short":               {ok + saltOf7Bytes + "$" + digestOf4, true},
		"digest one byte short":             {ok + saltOf8Bytes + "$" + digestOf3, true},
		"memory exactly 8 per lane (p=1)":   {"$argon2id$v=19$m=8,t=1,p=1$" + saltOf8Bytes + "$" + digestOf4, false},
		"memory one under 8 per lane (p=1)": {"$argon2id$v=19$m=7,t=1,p=1$" + saltOf8Bytes + "$" + digestOf4, true},
		"memory exactly 8 per lane (p=2)":   {"$argon2id$v=19$m=16,t=1,p=2$" + saltOf8Bytes + "$" + digestOf4, false},
		"memory one under 8 per lane (p=2)": {"$argon2id$v=19$m=15,t=1,p=2$" + saltOf8Bytes + "$" + digestOf4, true},
		"memory exactly 8 per lane (p=3)":   {"$argon2id$v=19$m=24,t=1,p=3$" + saltOf8Bytes + "$" + digestOf4, false},
		"memory one under 8 per lane (p=3)": {"$argon2id$v=19$m=23,t=1,p=3$" + saltOf8Bytes + "$" + digestOf4, true},
		"memory exactly at the cap":         {"$argon2id$v=19$m=262144,t=1,p=1$" + saltOf8Bytes + "$" + digestOf4, false},
		"memory one over the cap":           {"$argon2id$v=19$m=262145,t=1,p=1$" + saltOf8Bytes + "$" + digestOf4, true},
		"memory of 4 TiB":                   {"$argon2id$v=19$m=4294967295,t=1,p=1$" + saltOf8Bytes + "$" + digestOf4, true},
		"time exactly at the cap":           {"$argon2id$v=19$m=8,t=16,p=1$" + saltOf8Bytes + "$" + digestOf4, false},
		"time one over the cap":             {"$argon2id$v=19$m=8,t=17,p=1$" + saltOf8Bytes + "$" + digestOf4, true},
		"time of zero":                      {"$argon2id$v=19$m=8,t=0,p=1$" + saltOf8Bytes + "$" + digestOf4, true},
		"threads of zero":                   {"$argon2id$v=19$m=8,t=1,p=0$" + saltOf8Bytes + "$" + digestOf4, true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePasswordHash(tc.phc)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePasswordHash(%q) error = %v, wantErr %v", tc.phc, err, tc.wantErr)
			}
		})
	}
}

func TestAWindowCountsSecondsFromItsOwnStartNotFromZero(t *testing.T) {
	w := window{started: 10 * time.Second}
	if got := w.secondsUntilReset(20*time.Second, 60); got != 50 {
		t.Errorf("secondsUntilReset = %d, want 50", got)
	}
	if w.isExpired(60*time.Second, 60) {
		t.Error("window opened at 10s reported expired at 60s")
	}
	if !w.isExpired(70*time.Second, 60) {
		t.Error("window opened at 10s still live at 70s")
	}
}

func TestReleaseNeverDrivesACounterBelowZero(t *testing.T) {
	limiter := NewRateLimiter(1, 1, 60, nil)
	limiter.maxEntries = 0 // every source shares the overflow window
	limiter.Release(testIP(1))

	if !allowed(limiter, testIP(1)) {
		t.Fatal("a refund with nothing charged made the next attempt refused")
	}
	if allowed(limiter, testIP(1)) {
		t.Fatal("the attempt limit was not enforced after a stray refund")
	}
}
