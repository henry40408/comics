use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use http::HeaderMap;
use parking_lot::Mutex;
use tracing::warn;

use super::TrustedProxies;

/// Hard cap on tracked IPs. When the cap is hit the map is pruned of expired
/// windows first, so a spray from many source addresses cannot grow it without
/// bound.
const MAX_ENTRIES: usize = 10_000;

/// One fixed window: attempts charged so far, and when the window opened.
#[derive(Clone, Copy)]
struct Window {
    count: u32,
    started: Instant,
}

impl Window {
    /// A window that has just opened with nothing charged to it.
    fn empty() -> Self {
        Self {
            count: 0,
            started: Instant::now(),
        }
    }

    /// Whether nothing has been charged to this window for `window_secs`.
    fn is_expired(&self, window_secs: u64) -> bool {
        self.started.elapsed().as_secs() >= window_secs
    }
}

/// Every window the limiter owns, behind one lock.
///
/// One lock rather than two so that check-and-charge stays a single critical
/// section on both paths; concurrent requests must never all observe the same
/// pre-attack count.
struct Buckets {
    per_ip: HashMap<IpAddr, Window>,
    /// Shared by every source that arrives once `per_ip` is full. See
    /// [`RateLimiter::try_acquire`].
    overflow: Window,
}

/// Per-client-IP fixed-window limiter for login attempts.
///
/// In-memory only: comics has no database, and a restart resetting the counters
/// is acceptable for a single-account self-hosted service. Its purpose is to
/// remove the zero cost of an online dictionary attack against the one static
/// credential pair (OWASP Authentication Cheat Sheet, "Protect Against
/// Automated Attacks"); bcrypt's ~100 ms per verification is a speed bump, not
/// a control.
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
    max_attempts: u32,
    window_secs: u64,
    max_entries: usize,
}

impl RateLimiter {
    /// Create a limiter allowing `max_attempts` within `window_secs`.
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            buckets: Mutex::new(Buckets {
                per_ip: HashMap::new(),
                overflow: Window::empty(),
            }),
            max_attempts,
            window_secs,
            max_entries: MAX_ENTRIES,
        }
    }

    /// Reserve an attempt for `ip`, returning whether it may proceed.
    ///
    /// Checking and counting happen under a single lock, so concurrent requests
    /// cannot all observe the pre-attack count. The reservation is taken
    /// *before* the credential comparison — which costs ~100 ms of bcrypt — and
    /// is handed back by [`release`](Self::release) when the credentials turn
    /// out to be valid, so only failures ultimately consume the window.
    ///
    /// At capacity the map is first pruned of expired windows. If it is still
    /// full — a spray from more live sources than the cap — the attempt is
    /// charged to a single shared *overflow* window instead. The three
    /// alternatives are all worse: admitting the source untracked makes password
    /// guessing free and unbounded (an attacker with a `/64` has effectively
    /// unlimited source addresses, and each admitted attempt still costs a
    /// bcrypt verify); `clear()`ing the map hands anyone already throttled a way
    /// to reset their own budget by spraying keys; and refusing outright turns
    /// the same spray into a total login lockout. Sharing one finite window
    /// degrades to a global limit under attack while keeping every source
    /// already in the map on its own budget.
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock();
        if buckets.per_ip.len() >= self.max_entries && !buckets.per_ip.contains_key(&ip) {
            let window_secs = self.window_secs;
            buckets
                .per_ip
                .retain(|_, window| !window.is_expired(window_secs));
            if buckets.per_ip.len() >= self.max_entries {
                return self.charge(&mut buckets.overflow);
            }
        }
        let window = buckets.per_ip.entry(ip).or_insert_with(Window::empty);
        self.charge(window)
    }

    /// Charge one attempt to `window`, returning whether it fit.
    ///
    /// An expired window is rolled over rather than topped up, which is what
    /// makes this a fixed-window rather than a sliding-window limiter.
    fn charge(&self, window: &mut Window) -> bool {
        if window.is_expired(self.window_secs) {
            *window = Window {
                count: 1,
                started: Instant::now(),
            };
            return true;
        }
        if window.count >= self.max_attempts {
            return false;
        }
        window.count += 1;
        true
    }

    /// Hand back the attempt reserved by [`try_acquire`](Self::try_acquire).
    ///
    /// Called after a *successful* login. The control exists to stop password
    /// guessing, and a legitimate user who signs in repeatedly (new device,
    /// cleared cookies, a test suite) should not be locked out by it; an
    /// attacker's every attempt is a failure, so their budget is unchanged.
    ///
    /// An address with no window of its own was charged to the overflow bucket,
    /// so that is what gets the refund — otherwise signing in during a spray
    /// would quietly eat the shared budget everyone else is waiting on. Only a
    /// caller who passed the credential check reaches here, so the refund cannot
    /// be used to top the shared window back up.
    pub fn release(&self, ip: IpAddr) {
        let mut buckets = self.buckets.lock();
        let Some(window) = buckets.per_ip.get_mut(&ip) else {
            buckets.overflow.count = buckets.overflow.count.saturating_sub(1);
            return;
        };
        window.count = window.count.saturating_sub(1);
        if window.count == 0 {
            buckets.per_ip.remove(&ip);
        }
    }
}

/// Client address used as the rate-limit key.
///
/// `X-Forwarded-For` is honoured **only** when the TCP peer is inside
/// [`TrustedProxies`] — an explicit operator setting, empty by default. Header
/// presence proves nothing: anyone who can reach the port can write one, and the
/// minimal nginx snippet in wide circulation sets only `X-Real-IP` while
/// forwarding a client-supplied `X-Forwarded-For` verbatim. So the header is
/// believed on the strength of *who sent it*, never of the fact that it exists.
/// A missing peer means no connection info at all: fail closed onto a single
/// shared bucket, which throttles rather than exempts.
///
/// Which hop is the client is decided by walking the chain from the right and
/// skipping every address that is itself a trusted proxy. Right-to-left because
/// nginx's stock `$proxy_add_x_forwarded_for` (and Caddy's `reverse_proxy`)
/// *append* the peer to whatever the client sent, leaving the leftmost entry
/// attacker-chosen; skipping trusted hops because that generalises the same rule
/// to a proxy chain, which the old fixed "take the last one" could not express.
/// Every hop is canonicalised, so a mapped `::ffff:` form cannot open a second
/// bucket for one client.
///
/// All `X-Forwarded-For` header lines are read, not just the first. Proxies that
/// *append a line* rather than extending the existing one (`HAProxy`'s `option
/// forwardfor`, Caddy's `header_up +X-Forwarded-For`) put the trusted hop in the
/// last line, so reading only `headers.get(..)` would hand back a line the client
/// wrote.
pub fn rate_limit_key(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> IpAddr {
    let Some(peer) = peer.as_ref().map(IpAddr::to_canonical) else {
        return IpAddr::V4(Ipv4Addr::LOCALHOST);
    };
    if !trusted.contains(peer) {
        warn_once_about_ignored_forwarding(peer, headers);
        return peer;
    }
    forwarded_client(headers, trusted).unwrap_or(peer)
}

/// Fires at most once per process, the first time a forwarding header arrives
/// from a peer that is not a configured proxy.
static UNTRUSTED_FORWARD_WARNED: AtomicBool = AtomicBool::new(false);

/// Point out a forwarding header that is being dropped.
///
/// A startup warning cannot tell whether a proxy exists, so it would either cry
/// wolf at every direct deployment or say nothing. Waiting for a header to
/// actually show up makes the signal exact: either a proxy is in front and its
/// address is missing from the list — the misconfiguration worth catching, since
/// it silently collapses every client into one bucket — or somebody is trying to
/// forge the header, which is worth seeing too. Once is enough for both.
fn warn_once_about_ignored_forwarding(peer: IpAddr, headers: &HeaderMap) {
    if headers.contains_key("x-forwarded-for")
        && !UNTRUSTED_FORWARD_WARNED.swap(true, Ordering::Relaxed)
    {
        warn!(
            %peer,
            "ignoring X-Forwarded-For from a peer that is not a trusted proxy; \
             if this is your reverse proxy, add its address to --trusted-proxies \
             (COMICS_TRUSTED_PROXIES), or every client behind it shares one \
             login rate-limit bucket"
        );
    }
}

/// The rightmost `X-Forwarded-For` hop that is not itself a trusted proxy.
///
/// `None` when the header is absent, unparseable, or names nothing but trusted
/// infrastructure — in each case the caller falls back to the peer, so a
/// misconfigured proxy degrades to "everything behind it shares one bucket"
/// rather than to "no limit at all".
fn forwarded_client(headers: &HeaderMap, trusted: &TrustedProxies) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .rfind(|ip| !trusted.contains(*ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::Ipv6Addr,
        sync::{Arc, Barrier},
        thread,
    };

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn allows_up_to_max_attempts() {
        let limiter = RateLimiter::new(5, 60);
        let addr = ip(1);
        for _ in 0..5 {
            assert!(limiter.try_acquire(addr));
        }
        assert!(!limiter.try_acquire(addr));
    }

    #[test]
    fn window_expiry_resets_the_counter() {
        // A zero-second window is elapsed the moment it is recorded.
        let limiter = RateLimiter::new(1, 0);
        let addr = ip(2);
        assert!(limiter.try_acquire(addr));
        assert!(limiter.try_acquire(addr));
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.try_acquire(ip(3)));
        assert!(!limiter.try_acquire(ip(3)));
        assert!(limiter.try_acquire(ip(4)));
    }

    /// A successful login hands its reservation back, so signing in repeatedly
    /// never exhausts the window.
    #[test]
    fn release_returns_the_reserved_attempt() {
        let limiter = RateLimiter::new(2, 60);
        let addr = ip(5);
        for _ in 0..10 {
            assert!(limiter.try_acquire(addr));
            limiter.release(addr);
        }
        assert!(limiter.buckets.lock().per_ip.is_empty());
    }

    #[test]
    fn map_is_pruned_at_capacity() {
        let mut limiter = RateLimiter::new(5, 60);
        limiter.max_entries = 4;
        for last in 0..50u8 {
            limiter.try_acquire(ip(last));
        }
        assert!(limiter.buckets.lock().per_ip.len() <= 4);
    }

    /// Regression: a spray of fresh keys used to hit `map.clear()`, handing an
    /// already-throttled source a way to reset its own counter.
    #[test]
    fn capacity_spray_does_not_reset_an_existing_counter() {
        let mut limiter = RateLimiter::new(1, 60);
        limiter.max_entries = 4;
        let victim = ip(200);
        assert!(limiter.try_acquire(victim));
        assert!(!limiter.try_acquire(victim));

        for last in 0..50u8 {
            limiter.try_acquire(ip(last));
        }
        assert!(!limiter.try_acquire(victim), "spray reset the counter");
    }

    /// Regression: at capacity the limiter used to admit a fresh source *without*
    /// inserting it, so anyone holding more addresses than the cap — a single
    /// IPv6 `/64` is enough — got unlimited attempts, each still costing a bcrypt
    /// verify. The shared overflow window is what bounds that.
    #[test]
    fn overflow_bucket_is_shared_and_finite() {
        let mut limiter = RateLimiter::new(3, 60);
        // Nothing can be tracked individually, so every source overflows.
        limiter.max_entries = 0;

        let allowed = (0..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)))
            .count();
        assert_eq!(3, allowed, "50 distinct sources got {allowed} attempts");
    }

    /// Exhausting the shared window must not spend the budget of a source that
    /// already has one — otherwise a spray locks out whoever is mid-login.
    #[test]
    fn overflow_does_not_spend_a_tracked_source_budget() {
        let mut limiter = RateLimiter::new(3, 60);
        limiter.max_entries = 1;
        let tracked = ip(1);
        assert!(limiter.try_acquire(tracked));

        // The map is now full, so these all land on the shared window.
        for last in 10..40u8 {
            limiter.try_acquire(ip(last));
        }

        // Two of the tracked source's three attempts are still there.
        assert!(limiter.try_acquire(tracked));
        assert!(limiter.try_acquire(tracked));
        assert!(!limiter.try_acquire(tracked));
    }

    /// The shared window rolls over on expiry like any other, so an attack does
    /// not lock the form out permanently once it stops.
    #[test]
    fn overflow_window_expires_like_any_other() {
        let mut limiter = RateLimiter::new(1, 0);
        limiter.max_entries = 0;
        assert!(limiter.try_acquire(ip(1)));
        assert!(limiter.try_acquire(ip(2)));
    }

    /// A successful login costs nothing even when it was charged to the shared
    /// window — otherwise signing in during a spray eats budget others wait on.
    #[test]
    fn release_refunds_the_overflow_bucket() {
        let mut limiter = RateLimiter::new(1, 60);
        limiter.max_entries = 0;
        for round in 0..10 {
            assert!(limiter.try_acquire(ip(1)), "round {round}");
            limiter.release(ip(1));
        }
    }

    /// Regression: checking and counting used to take the lock separately, so
    /// requests arriving together all observed the pre-attack count.
    #[test]
    fn concurrent_attempts_cannot_exceed_the_limit() {
        const THREADS: usize = 64;
        let limiter = Arc::new(RateLimiter::new(5, 60));
        let barrier = Arc::new(Barrier::new(THREADS));
        let addr = ip(7);

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    limiter.try_acquire(addr)
                })
            })
            .collect();
        let allowed = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread panicked"))
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(5, allowed, "concurrent requests overran the limit");
    }

    const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

    fn trusting(raw: &str) -> TrustedProxies {
        raw.parse().expect("valid trusted proxy list")
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    /// The default. Nothing is trusted, so the header is not even looked at —
    /// including from loopback, which the previous rule trusted implicitly.
    #[test]
    fn xff_is_ignored_when_no_proxy_is_trusted() {
        let trusted = TrustedProxies::default();
        let headers = xff("203.0.113.9");
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert_eq!(loopback, rate_limit_key(Some(loopback), &headers, &trusted));
        assert_eq!(PROXY, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

    #[test]
    fn xff_is_honoured_only_from_a_trusted_peer() {
        let trusted = trusting("10.0.0.5");
        let headers = xff("203.0.113.9");
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        assert_eq!(client, rate_limit_key(Some(PROXY), &headers, &trusted));

        // Same header, a peer nobody vouched for: the header is ignored.
        let stranger = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(stranger, rate_limit_key(Some(stranger), &headers, &trusted));
    }

    /// Regression: nginx's stock `$proxy_add_x_forwarded_for` appends the peer,
    /// so the leftmost entry is whatever the client sent. Keying on it let an
    /// attacker mint a fresh bucket per request.
    #[test]
    fn spoofed_leading_xff_hops_do_not_change_the_key() {
        let trusted = trusting("10.0.0.5");
        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        for spoof in ["1.2.3.4", "5.6.7.8", "9.9.9.9, 8.8.8.8"] {
            let headers = xff(&format!("{spoof}, 198.51.100.7"));
            assert_eq!(real, rate_limit_key(Some(PROXY), &headers, &trusted));
        }
    }

    /// A chain of two proxies. The rightmost *untrusted* hop is the client; the
    /// old fixed "take the last entry" would have keyed on the inner proxy and
    /// collapsed every client behind it into one bucket.
    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        let trusted = trusting("10.0.0.0/24");
        let headers = xff("203.0.113.9, 10.0.0.9, 10.0.0.5");
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(client, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

    /// Regression for reading only the first header line: `HAProxy`'s `option
    /// forwardfor` and Caddy's `header_up +X-Forwarded-For` append a *new* line,
    /// putting the trusted hop last. `headers.get(..)` returns only the first,
    /// which is the one the client wrote.
    #[test]
    fn xff_spread_across_header_lines_is_read_whole() {
        let trusted = trusting("10.0.0.5");
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());

        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(real, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

    /// Every hop is infrastructure, so there is no client to find. Falling back
    /// to the peer throttles the proxy as a whole rather than lifting the limit.
    #[test]
    fn all_trusted_hops_falls_back_to_the_peer() {
        let trusted = trusting("10.0.0.0/24");
        let headers = xff("10.0.0.9, 10.0.0.5");
        assert_eq!(PROXY, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

    #[test]
    fn garbage_and_absent_headers_fall_back_to_the_peer() {
        let trusted = trusting("10.0.0.5");
        assert_eq!(
            PROXY,
            rate_limit_key(Some(PROXY), &xff("not-an-ip"), &trusted)
        );
        assert_eq!(
            PROXY,
            rate_limit_key(Some(PROXY), &HeaderMap::new(), &trusted)
        );
    }

    /// Regression: a `[::]`-bound listener reports an IPv4 peer in mapped form,
    /// which matches no IPv4 prefix until canonicalised — so the proxy would not
    /// be recognised and every client behind it would share the peer's bucket.
    #[test]
    fn ipv4_mapped_peer_is_canonicalised_before_matching() {
        let trusted = trusting("10.0.0.0/24");
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        let headers = xff("203.0.113.9");
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(client, rate_limit_key(Some(mapped), &headers, &trusted));
    }

    /// A mapped and a plain form of one address must not open two buckets.
    #[test]
    fn ipv4_mapped_hops_key_the_same_as_their_plain_form() {
        let trusted = trusting("10.0.0.5");
        let plain = rate_limit_key(Some(PROXY), &xff("203.0.113.9"), &trusted);
        let mapped = rate_limit_key(Some(PROXY), &xff("::ffff:203.0.113.9"), &trusted);
        assert_eq!(plain, mapped);
    }

    /// No connection info: fail closed onto one shared bucket. It throttles
    /// everyone rather than exempting anyone, which is the safe direction.
    #[test]
    fn missing_peer_fails_closed() {
        let trusted = trusting("10.0.0.5");
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            loopback,
            rate_limit_key(None, &xff("203.0.113.9"), &trusted)
        );
        assert_eq!(loopback, rate_limit_key(None, &HeaderMap::new(), &trusted));
    }

    #[test]
    fn ipv6_peer_and_hops_work_end_to_end() {
        let trusted = trusting("fd00::/8");
        let headers = xff("2001:db8::1, fd00::5");
        let client: IpAddr = "2001:db8::1".parse().unwrap();
        let peer: IpAddr = "fd00::5".parse().unwrap();
        assert_eq!(client, rate_limit_key(Some(peer), &headers, &trusted));
        assert_eq!(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            rate_limit_key(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), &headers, &trusted)
        );
    }
}
