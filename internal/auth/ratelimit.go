package auth

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxTrackedIPs is the hard cap on tracked IPs; expired windows are pruned
// first, so a spray from many sources cannot grow the map without bound.
const maxTrackedIPs = 10_000

// Login attempt budgets, per fixed window.
const (
	LoginMaxAttemptsPerIP  = 5
	LoginMaxAttemptsGlobal = 20
	LoginWindowSecs        = 60
)

// loopbackFallbackAddress keys a request with no usable peer, so it fails
// closed onto one shared bucket.
const loopbackFallbackAddress = "127.0.0.1"

type window struct {
	count   int
	started time.Duration
}

// isExpired is a fixed window: measured from when it opened, not from the last
// attempt.
func (w window) isExpired(now time.Duration, windowSecs int) bool {
	return elapsedSecs(now, w.started) >= windowSecs
}

// secondsUntilReset is for Retry-After. Never zero: a client told zero retries
// at once and is refused again.
func (w window) secondsUntilReset(now time.Duration, windowSecs int) int {
	return max(windowSecs-elapsedSecs(now, w.started), 1)
}

func elapsedSecs(now, started time.Duration) int {
	return int(max(now-started, 0) / time.Second)
}

// Scope names the window that refused an attempt; the three mean very
// different things in the log.
type Scope string

const (
	// ScopePerIP is this client's own window: one person mistyping.
	ScopePerIP Scope = "per_ip"
	// ScopeShared is the overflow window shared once the per-IP map is full.
	ScopeShared Scope = "shared"
	// ScopeGlobal is every address together: distributed guessing, and the
	// reader is locked out too.
	ScopeGlobal Scope = "global"
)

// Throttle is what RateLimiter.TryAcquire decided.
type Throttle struct {
	Allowed bool
	// Scope is the window that refused; meaningful only when not Allowed.
	Scope Scope
	// RetryAfterSecs is the time until the refusing window rolls over;
	// meaningful only when not Allowed.
	RetryAfterSecs int
}

// buckets holds all windows behind one lock: check-and-charge must be a single
// critical section, or concurrent requests all observe the pre-attack count.
type buckets struct {
	perIP map[netip.Addr]*window
	// overflow is shared by every new source once perIP is full.
	overflow window
	// global counts every attempt, whatever its source.
	global window
}

// RateLimiter is a fixed-window, in-memory limiter for login attempts, keyed
// per client IP and globally. Argon2id's per-verification cost alone is a speed
// bump, not a control against online guessing (OWASP Authentication Cheat
// Sheet).
//
// # Why a global window
//
// OWASP's Account Lockout asks that failures be counted per account, not per
// source. Per-IP alone gives every fresh address a full budget, and an IPv6 /64
// supplies thousands before maxTrackedIPs fills. comics has one credential
// pair, so the global window is the account-scoped counter.
//
// # The lockout trade
//
// A global counter can be exhausted deliberately, locking the reader out too.
// That is accepted because the threshold is well above one person's use, the
// window is fixed and short (no escalation: comics has no recovery path), and
// a successful login refunds both windows (Release). The alternative leaves
// distributed guessing unbounded.
type RateLimiter struct {
	mu                sync.Mutex
	buckets           buckets
	clock             func() time.Duration
	maxAttempts       int
	globalMaxAttempts int
	windowSecs        int
	maxEntries        int
}

// NewRateLimiter builds a limiter. globalMaxAttempts should sit well above
// maxAttempts; see the type docs. clock reports elapsed time from a fixed
// origin; nil means real monotonic time.
func NewRateLimiter(maxAttempts, globalMaxAttempts, windowSecs int, clock func() time.Duration) *RateLimiter {
	if clock == nil {
		clock = monotonicClock()
	}
	now := clock()
	return &RateLimiter{
		buckets: buckets{
			perIP:    make(map[netip.Addr]*window),
			overflow: window{started: now},
			global:   window{started: now},
		},
		clock:             clock,
		maxAttempts:       maxAttempts,
		globalMaxAttempts: globalMaxAttempts,
		windowSecs:        windowSecs,
		maxEntries:        maxTrackedIPs,
	}
}

// TryAcquire reserves an attempt for ip before the (expensive) credential
// check; Release refunds it on success, so only failures count.
//
// At capacity the map is pruned of expired windows; if still full, the attempt
// shares the overflow window. The alternatives are worse: admitting untracked
// makes guessing unbounded, clearing the map lets a throttled source reset
// itself by spraying keys, and refusing turns a spray into a total lockout.
func (l *RateLimiter) TryAcquire(ip netip.Addr) Throttle {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()

	own, scope := l.windowFor(now, ip)

	// Check both before charging either, so a refusal spends from neither.
	if !l.hasRoom(own, now, l.maxAttempts) {
		return refused(scope, own.secondsUntilReset(now, l.windowSecs))
	}
	if !l.hasRoom(&l.buckets.global, now, l.globalMaxAttempts) {
		return refused(ScopeGlobal, l.buckets.global.secondsUntilReset(now, l.windowSecs))
	}
	l.charge(own, now)
	l.charge(&l.buckets.global, now)
	return Throttle{Allowed: true}
}

func refused(scope Scope, retryAfterSecs int) Throttle {
	return Throttle{Scope: scope, RetryAfterSecs: retryAfterSecs}
}

// windowFor picks ip's own window, or the overflow window if the map is full
// even after pruning. A missing own window is created empty, so a refused
// attempt still leaves its (empty) entry behind.
func (l *RateLimiter) windowFor(now time.Duration, ip netip.Addr) (*window, Scope) {
	perIP := l.buckets.perIP
	if own, tracked := perIP[ip]; tracked {
		return own, ScopePerIP
	}
	if len(perIP) >= l.maxEntries {
		l.pruneExpired(now)
	}
	if len(perIP) >= l.maxEntries {
		return &l.buckets.overflow, ScopeShared
	}
	own := &window{started: now}
	perIP[ip] = own
	return own, ScopePerIP
}

func (l *RateLimiter) pruneExpired(now time.Duration) {
	for ip, w := range l.buckets.perIP {
		if w.isExpired(now, l.windowSecs) {
			delete(l.buckets.perIP, ip)
		}
	}
}

// hasRoom treats an expired window as having room: charge rolls it over.
func (l *RateLimiter) hasRoom(w *window, now time.Duration, maxAttempts int) bool {
	return w.isExpired(now, l.windowSecs) || w.count < maxAttempts
}

// charge is only called after hasRoom, so the ceiling is not re-checked.
func (l *RateLimiter) charge(w *window, now time.Duration) {
	if w.isExpired(now, l.windowSecs) {
		*w = window{count: 1, started: now}
		return
	}
	w.count++
}

// Release refunds the attempt reserved by TryAcquire after a successful login
// (see RateLimiter). An address without its own window was charged to
// overflow, so that is refunded instead.
func (l *RateLimiter) Release(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets.global.count = decrement(l.buckets.global.count)

	own, tracked := l.buckets.perIP[ip]
	if !tracked {
		l.buckets.overflow.count = decrement(l.buckets.overflow.count)
		return
	}
	own.count = decrement(own.count)
	if own.count == 0 {
		delete(l.buckets.perIP, ip)
	}
}

func decrement(count int) int { return max(count-1, 0) }

// ClientKeys derives the rate-limit key of a request.
type ClientKeys struct {
	trusted TrustedProxies
	logger  *slog.Logger
	warned  atomic.Bool
}

// NewClientKeys builds a resolver. logger receives the one-time warning about
// an ignored X-Forwarded-For.
func NewClientKeys(trusted TrustedProxies, logger *slog.Logger) *ClientKeys {
	return &ClientKeys{trusted: trusted, logger: logger}
}

// Key is the client address used as the rate-limit key.
//
// X-Forwarded-For is honoured only when the TCP peer is in TrustedProxies
// (empty by default): anyone can write the header. No usable peer at all fails
// closed onto one shared bucket (127.0.0.1).
func (c *ClientKeys) Key(r *http.Request) netip.Addr {
	peer, ok := peerAddr(r)
	return c.keyFor(peer, ok, r.Header)
}

// peerAddr is the request's TCP peer, canonicalised; ok is false when
// RemoteAddr does not parse.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return canonicalAddr(addrPort.Addr()), true
}

func canonicalAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// keyFor picks the rightmost X-Forwarded-For hop that is not a trusted proxy:
// proxies append, so the leftmost entry is attacker-chosen. Hops are
// canonicalised (a ::ffff: form must not open a second bucket), and every
// header line is read, since some proxies append a line rather than extend one.
func (c *ClientKeys) keyFor(peer netip.Addr, hasPeer bool, headers http.Header) netip.Addr {
	if !hasPeer {
		return netip.MustParseAddr(loopbackFallbackAddress)
	}
	if !c.trusted.Contains(peer) {
		c.warnOnceAboutIgnoredForwarding(peer, headers)
		return peer
	}
	if client, ok := forwardedClient(headers, c.trusted); ok {
		return client
	}
	return peer
}

// warnOnceAboutIgnoredForwarding warns, once per resolver, that an untrusted
// peer's X-Forwarded-For is being dropped. Done on first sight rather than at
// startup, which cannot tell whether a proxy exists: here it is either a
// missing trusted-proxies entry (every client collapses into one bucket) or a
// forgery.
func (c *ClientKeys) warnOnceAboutIgnoredForwarding(peer netip.Addr, headers http.Header) {
	if len(headers.Values("X-Forwarded-For")) == 0 || c.logger == nil {
		return
	}
	if c.warned.Swap(true) {
		return
	}
	c.logger.Warn("ignoring X-Forwarded-For from a peer that is not a trusted proxy; "+
		"if this is your reverse proxy, add its address to --trusted-proxies "+
		"(COMICS_TRUSTED_PROXIES), or every client behind it shares one "+
		"login rate-limit bucket", "peer", peer.String())
}

// forwardedClient is the rightmost untrusted X-Forwarded-For hop; false (the
// caller falls back to the peer) when absent, unparseable, or all trusted.
func forwardedClient(headers http.Header, trusted TrustedProxies) (netip.Addr, bool) {
	var hops []netip.Addr
	for _, line := range headers.Values("X-Forwarded-For") {
		if !isVisibleASCII(line) {
			continue
		}
		for raw := range strings.SplitSeq(line, ",") {
			hop, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil || hop.Zone() != "" {
				continue
			}
			hops = append(hops, canonicalAddr(hop))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !trusted.Contains(hops[i]) {
			return hops[i], true
		}
	}
	return netip.Addr{}, false
}

// isVisibleASCII reports whether value holds only visible ASCII and tab; a
// forwarded-for line with any other byte is ignored.
func isVisibleASCII(value string) bool {
	for i := range len(value) {
		b := value[i]
		if b != '\t' && (b < 0x20 || b > 0x7e) {
			return false
		}
	}
	return true
}
