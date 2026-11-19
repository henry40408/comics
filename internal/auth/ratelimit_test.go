package auth

import (
	"bytes"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func testIP(last uint8) netip.Addr { return netip.AddrFrom4([4]byte{203, 0, 113, last}) }

// newLimiter returns a limiter whose global window never refuses.
func newLimiter(maxAttempts, windowSecs int) *RateLimiter {
	return NewRateLimiter(maxAttempts, math.MaxUint32, windowSecs, nil)
}

func allowed(l *RateLimiter, ip netip.Addr) bool { return l.TryAcquire(ip).Allowed }

func countAllowed(l *RateLimiter, ips func(yield func(netip.Addr) bool)) int {
	count := 0
	for ip := range ips {
		if allowed(l, ip) {
			count++
		}
	}
	return count
}

func ipRange(from, to uint8) func(yield func(netip.Addr) bool) {
	return func(yield func(netip.Addr) bool) {
		for last := from; last < to; last++ {
			if !yield(testIP(last)) {
				return
			}
		}
	}
}

func TestAllowsUpToMaxAttempts(t *testing.T) {
	limiter := newLimiter(5, 60)
	for i := range 5 {
		if !allowed(limiter, testIP(1)) {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if allowed(limiter, testIP(1)) {
		t.Fatal("sixth attempt allowed")
	}
}

func TestWindowExpiryResetsTheCounter(t *testing.T) {
	// A zero-second window is elapsed the moment it is recorded.
	limiter := newLimiter(1, 0)
	firstAllowed := allowed(limiter, testIP(2))
	secondAllowed := allowed(limiter, testIP(2))
	if !firstAllowed || !secondAllowed {
		t.Fatal("an expired window did not reset")
	}
}

func TestDistinctIPsHaveIndependentBuckets(t *testing.T) {
	limiter := newLimiter(1, 60)
	if !allowed(limiter, testIP(3)) {
		t.Fatal("first attempt refused")
	}
	if allowed(limiter, testIP(3)) {
		t.Fatal("second attempt allowed")
	}
	if !allowed(limiter, testIP(4)) {
		t.Fatal("another address was refused")
	}
}

func TestReleaseReturnsTheReservedAttempt(t *testing.T) {
	limiter := newLimiter(2, 60)
	for round := range 10 {
		if !allowed(limiter, testIP(5)) {
			t.Fatalf("round %d refused", round)
		}
		limiter.Release(testIP(5))
	}
	if len(limiter.buckets.perIP) != 0 {
		t.Fatalf("perIP has %d entries, want 0", len(limiter.buckets.perIP))
	}
}

func TestMapIsPrunedAtCapacity(t *testing.T) {
	limiter := newLimiter(5, 60)
	limiter.maxEntries = 4
	countAllowed(limiter, ipRange(0, 50))
	if got := len(limiter.buckets.perIP); got > 4 {
		t.Fatalf("perIP has %d entries, cap is 4", got)
	}
}

// A spray of fresh keys must not reset a throttled source's counter.
func TestCapacitySprayDoesNotResetAnExistingCounter(t *testing.T) {
	limiter := newLimiter(1, 60)
	limiter.maxEntries = 4
	victim := testIP(200)
	if !allowed(limiter, victim) {
		t.Fatal("first attempt refused")
	}
	if allowed(limiter, victim) {
		t.Fatal("second attempt allowed")
	}

	countAllowed(limiter, ipRange(0, 50))

	if allowed(limiter, victim) {
		t.Fatal("spray reset the counter")
	}
}

// At capacity, holding more addresses than the cap must not buy unlimited
// attempts.
func TestOverflowBucketIsSharedAndFinite(t *testing.T) {
	limiter := newLimiter(3, 60)
	limiter.maxEntries = 0
	if got := countAllowed(limiter, ipRange(0, 50)); got != 3 {
		t.Fatalf("50 distinct sources got %d attempts, want 3", got)
	}
}

// A spray exhausting the overflow window must not spend a tracked source's
// budget.
func TestOverflowDoesNotSpendATrackedSourceBudget(t *testing.T) {
	limiter := newLimiter(3, 60)
	limiter.maxEntries = 1
	tracked := testIP(1)
	if !allowed(limiter, tracked) {
		t.Fatal("first attempt refused")
	}

	// Map full: these all land on the overflow window.
	countAllowed(limiter, ipRange(10, 40))

	// Two of the tracked source's three attempts are still there.
	firstTracked := allowed(limiter, tracked)
	secondTracked := allowed(limiter, tracked)
	if !firstTracked || !secondTracked {
		t.Fatal("the tracked source lost budget to the overflow spray")
	}
	if allowed(limiter, tracked) {
		t.Fatal("a fourth attempt was allowed")
	}
}

func TestOverflowWindowExpiresLikeAnyOther(t *testing.T) {
	limiter := newLimiter(1, 0)
	limiter.maxEntries = 0
	if !allowed(limiter, testIP(1)) || !allowed(limiter, testIP(2)) {
		t.Fatal("the overflow window did not expire")
	}
}

func TestReleaseRefundsTheOverflowBucket(t *testing.T) {
	limiter := newLimiter(1, 60)
	limiter.maxEntries = 0
	for round := range 10 {
		if !allowed(limiter, testIP(1)) {
			t.Fatalf("round %d refused", round)
		}
		limiter.Release(testIP(1))
	}
}

func TestARefusalNamesTheWindowThatSaidNo(t *testing.T) {
	perIP := NewRateLimiter(1, 100, 60, nil)
	allowed(perIP, testIP(1))
	if got := perIP.TryAcquire(testIP(1)); got.Allowed || got.Scope != ScopePerIP {
		t.Fatalf("per-IP refusal = %+v", got)
	}

	shared := NewRateLimiter(1, 100, 60, nil)
	shared.maxEntries = 0
	allowed(shared, testIP(1))
	if got := shared.TryAcquire(testIP(2)); got.Allowed || got.Scope != ScopeShared {
		t.Fatalf("shared refusal = %+v", got)
	}

	// Only the global window can refuse; testIP(2) has its own budget unspent.
	global := NewRateLimiter(100, 1, 60, nil)
	allowed(global, testIP(1))
	if got := global.TryAcquire(testIP(2)); got.Allowed || got.Scope != ScopeGlobal {
		t.Fatalf("global refusal = %+v", got)
	}
}

func TestARefusalSaysWhenTheWindowResets(t *testing.T) {
	for _, limiter := range []*RateLimiter{
		NewRateLimiter(1, 100, 60, nil),
		NewRateLimiter(100, 1, 60, nil),
	} {
		allowed(limiter, testIP(1))
		got := limiter.TryAcquire(testIP(1))
		if got.Allowed {
			t.Fatal("the second attempt was allowed")
		}
		if got.RetryAfterSecs < 1 || got.RetryAfterSecs > 60 {
			t.Errorf("RetryAfterSecs = %d, want 1..=60", got.RetryAfterSecs)
		}
	}
}

func TestGlobalWindowBoundsASprayFromManyAddresses(t *testing.T) {
	limiter := NewRateLimiter(5, 7, 60, nil)
	if got := countAllowed(limiter, ipRange(0, 50)); got != 7 {
		t.Fatalf("50 distinct addresses got %d attempts, want 7", got)
	}
}

// Otherwise one throttled source could exhaust everyone's shared budget.
func TestASourceRefusedPerIPDoesNotSpendTheGlobalWindow(t *testing.T) {
	limiter := NewRateLimiter(2, 10, 60, nil)
	noisy := testIP(1)
	allowed(limiter, noisy)
	allowed(limiter, noisy)
	for range 20 {
		if allowed(limiter, noisy) {
			t.Fatal("per-IP window let a third by")
		}
	}
	// Two charged, so eight of the global ten remain.
	if got := countAllowed(limiter, ipRange(10, 50)); got != 8 {
		t.Fatalf("got %d, want 8: the refused attempts were charged globally", got)
	}
}

// The global ceiling is the looser one, so the final count measures the
// per-IP window.
func TestGlobalRefusalDoesNotSpendASourceBudget(t *testing.T) {
	clock := &fakeClock{}
	limiter := NewRateLimiter(5, 8, 60, clock.now)
	for last := uint8(10); last < 18; last++ {
		if !allowed(limiter, testIP(last)) {
			t.Fatalf("attempt from %d refused", last)
		}
	}
	reader := testIP(1)
	for range 10 {
		if allowed(limiter, reader) {
			t.Fatal("global window let one by")
		}
	}

	// Roll the global window over by hand; the reader's five must remain.
	limiter.buckets.global = window{started: clock.now()}
	granted := 0
	for range 10 {
		if allowed(limiter, reader) {
			granted++
		}
	}
	if granted != 5 {
		t.Fatalf("got %d, want 5: the reader's budget was spent while locked out", granted)
	}
}

func TestReleaseRefundsTheGlobalWindow(t *testing.T) {
	limiter := NewRateLimiter(5, 3, 60, nil)
	for round := range 20 {
		if !allowed(limiter, testIP(1)) {
			t.Fatalf("round %d refused", round)
		}
		limiter.Release(testIP(1))
	}
	if limiter.buckets.global.count != 0 {
		t.Fatalf("global count = %d, want 0", limiter.buckets.global.count)
	}
}

// Fixed, not escalating: this bounds the lockout a global counter invites.
func TestGlobalWindowExpiresLikeAnyOther(t *testing.T) {
	limiter := NewRateLimiter(5, 1, 0, nil)
	for last := uint8(1); last <= 3; last++ {
		if !allowed(limiter, testIP(last)) {
			t.Fatalf("attempt from %d refused", last)
		}
	}
}

func TestAWindowRollsOverOnceItsLengthHasPassed(t *testing.T) {
	clock := &fakeClock{}
	limiter := NewRateLimiter(1, 100, 60, clock.now)
	allowed(limiter, testIP(1))
	if allowed(limiter, testIP(1)) {
		t.Fatal("second attempt allowed inside the window")
	}

	clock.advance(59 * time.Second)
	if allowed(limiter, testIP(1)) {
		t.Fatal("allowed one second early")
	}
	clock.advance(time.Second)
	if !allowed(limiter, testIP(1)) {
		t.Fatal("refused after the window rolled over")
	}
}

func TestConcurrentAttemptsCannotExceedTheLimit(t *testing.T) {
	const threads = 64
	limiter := newLimiter(5, 60)
	start := make(chan struct{})
	results := make(chan bool, threads)

	var wg sync.WaitGroup
	for range threads {
		wg.Go(func() {
			<-start
			results <- allowed(limiter, testIP(7))
		})
	}
	close(start)
	wg.Wait()
	close(results)

	granted := 0
	for ok := range results {
		if ok {
			granted++
		}
	}
	if granted != 5 {
		t.Fatalf("concurrent requests got %d attempts, want 5", granted)
	}
}

func TestRetryAfterCountsDownFromTheWindowAndIsNeverZero(t *testing.T) {
	w := window{started: 0}
	if got := w.secondsUntilReset(0, 60); got != 60 {
		t.Errorf("fresh window = %d, want 60", got)
	}
	// A window already over still says one second, not zero.
	if got := w.secondsUntilReset(0, 0); got != 1 {
		t.Errorf("zero-length window = %d, want 1", got)
	}
	if got := w.secondsUntilReset(45*time.Second, 60); got != 15 {
		t.Errorf("after 45s = %d, want 15", got)
	}
}

const proxyAddr = "10.0.0.5"

func keysTrusting(t *testing.T, raw string) *ClientKeys {
	t.Helper()
	return NewClientKeys(mustParseProxies(t, raw), nil)
}

func xff(lines ...string) http.Header {
	headers := http.Header{}
	for _, line := range lines {
		headers.Add("X-Forwarded-For", line)
	}
	return headers
}

func keyOf(keys *ClientKeys, peer string, headers http.Header) netip.Addr {
	return keys.keyFor(addr(peer), true, headers)
}

// The default trusts nothing, loopback included.
func TestXFFIsIgnoredWhenNoProxyIsTrusted(t *testing.T) {
	keys := keysTrusting(t, "")
	headers := xff("203.0.113.9")
	for _, peer := range []string{"127.0.0.1", proxyAddr} {
		if got := keyOf(keys, peer, headers); got != addr(peer) {
			t.Errorf("peer %s keyed as %s", peer, got)
		}
	}
}

func TestXFFIsHonouredOnlyFromATrustedPeer(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	headers := xff("203.0.113.9")

	if got := keyOf(keys, proxyAddr, headers); got != addr("203.0.113.9") {
		t.Errorf("trusted peer keyed as %s", got)
	}
	if got := keyOf(keys, "198.51.100.1", headers); got != addr("198.51.100.1") {
		t.Errorf("stranger keyed as %s", got)
	}
}

// Proxies append, so the leftmost hops are client-chosen.
func TestSpoofedLeadingXFFHopsDoNotChangeTheKey(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	for _, spoof := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9, 8.8.8.8"} {
		got := keyOf(keys, proxyAddr, xff(spoof+", 198.51.100.7"))
		if got != addr("198.51.100.7") {
			t.Errorf("spoof %q keyed as %s", spoof, got)
		}
	}
}

// Taking the last entry would key on the inner proxy.
func TestTrustedHopsAreSkippedFromTheRight(t *testing.T) {
	keys := keysTrusting(t, "10.0.0.0/24")
	got := keyOf(keys, proxyAddr, xff("203.0.113.9, 10.0.0.9, 10.0.0.5"))
	if got != addr("203.0.113.9") {
		t.Fatalf("keyed as %s", got)
	}
}

// HAProxy's `option forwardfor` and Caddy's `header_up +X-Forwarded-For`
// append a new line; reading only the first would key on the client's own.
func TestXFFSpreadAcrossHeaderLinesIsReadWhole(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	got := keyOf(keys, proxyAddr, xff("1.2.3.4", "198.51.100.7"))
	if got != addr("198.51.100.7") {
		t.Fatalf("keyed as %s", got)
	}
}

func TestAllTrustedHopsFallsBackToThePeer(t *testing.T) {
	keys := keysTrusting(t, "10.0.0.0/24")
	if got := keyOf(keys, proxyAddr, xff("10.0.0.9, 10.0.0.5")); got != addr(proxyAddr) {
		t.Fatalf("keyed as %s", got)
	}
}

func TestGarbageAndAbsentHeadersFallBackToThePeer(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	for name, headers := range map[string]http.Header{
		"garbage": xff("not-an-ip"),
		"absent":  {},
	} {
		if got := keyOf(keys, proxyAddr, headers); got != addr(proxyAddr) {
			t.Errorf("%s keyed as %s", name, got)
		}
	}
}

// A [::]-bound listener reports IPv4 peers in mapped form, which match no IPv4
// prefix until canonicalised.
func TestIPv4MappedPeerIsCanonicalisedBeforeMatching(t *testing.T) {
	keys := keysTrusting(t, "10.0.0.0/24")
	r := &http.Request{RemoteAddr: "[::ffff:10.0.0.5]:4000", Header: xff("203.0.113.9")}
	if got := keys.Key(r); got != addr("203.0.113.9") {
		t.Fatalf("keyed as %s", got)
	}
}

func TestIPv4MappedHopsKeyTheSameAsTheirPlainForm(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	plain := keyOf(keys, proxyAddr, xff("203.0.113.9"))
	mapped := keyOf(keys, proxyAddr, xff("::ffff:203.0.113.9"))
	if plain != mapped {
		t.Fatalf("plain %s != mapped %s", plain, mapped)
	}
}

func TestMissingPeerFailsClosed(t *testing.T) {
	keys := keysTrusting(t, proxyAddr)
	loopback := addr("127.0.0.1")
	for name, headers := range map[string]http.Header{"xff": xff("203.0.113.9"), "none": {}} {
		if got := keys.keyFor(netip.Addr{}, false, headers); got != loopback {
			t.Errorf("%s keyed as %s", name, got)
		}
	}
	unparseable := &http.Request{RemoteAddr: "pipe", Header: xff("203.0.113.9")}
	if got := keys.Key(unparseable); got != loopback {
		t.Errorf("unparseable RemoteAddr keyed as %s", got)
	}
}

func TestIPv6PeerAndHopsWorkEndToEnd(t *testing.T) {
	keys := keysTrusting(t, "fd00::/8")
	headers := xff("2001:db8::1, fd00::5")
	if got := keyOf(keys, "fd00::5", headers); got != addr("2001:db8::1") {
		t.Errorf("trusted v6 peer keyed as %s", got)
	}
	if got := keyOf(keys, "::1", headers); got != addr("::1") {
		t.Errorf("untrusted v6 peer keyed as %s", got)
	}
}

func TestTheClientKeyIsTheTCPPeerWhenNoProxyIsTrusted(t *testing.T) {
	keys := keysTrusting(t, "")
	r := &http.Request{RemoteAddr: "203.0.113.7:4000", Header: xff("198.51.100.1")}
	if got := keys.Key(r); got != addr("203.0.113.7") {
		t.Fatalf("keyed as %s", got)
	}
}

func TestIgnoredForwardingWarnsOncePerResolver(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	keys := NewClientKeys(TrustedProxies{}, logger)
	headers := xff("203.0.113.9")

	keyOf(keys, proxyAddr, headers)
	keyOf(keys, proxyAddr, headers)
	keyOf(keys, proxyAddr, http.Header{})

	if got := strings.Count(logs.String(), "ignoring X-Forwarded-For"); got != 1 {
		t.Fatalf("warned %d times, want 1:\n%s", got, logs.String())
	}

	other := NewClientKeys(TrustedProxies{}, logger)
	keyOf(other, proxyAddr, headers)
	if got := strings.Count(logs.String(), "ignoring X-Forwarded-For"); got != 2 {
		t.Fatalf("a second resolver should warn on its own; total %d", got)
	}
}

func TestNoWarningWithoutAForwardedHeader(t *testing.T) {
	var logs bytes.Buffer
	keys := NewClientKeys(TrustedProxies{}, slog.New(slog.NewTextHandler(&logs, nil)))
	keyOf(keys, proxyAddr, http.Header{})
	if logs.Len() != 0 {
		t.Fatalf("unexpected log: %s", logs.String())
	}
}
