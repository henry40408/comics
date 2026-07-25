use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use http::HeaderMap;
use parking_lot::Mutex;

/// Hard cap on tracked IPs. When the cap is hit the map is pruned of expired
/// windows first, so a spray from many source addresses cannot grow it without
/// bound.
const MAX_ENTRIES: usize = 10_000;

/// Per-client-IP fixed-window limiter for login attempts.
///
/// In-memory only: comics has no database, and a restart resetting the counters
/// is acceptable for a single-account self-hosted service. Its purpose is to
/// remove the zero cost of an online dictionary attack against the one static
/// credential pair (OWASP Authentication Cheat Sheet, "Protect Against
/// Automated Attacks"); bcrypt's ~100 ms per verification is a speed bump, not
/// a control.
pub struct RateLimiter {
    attempts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_attempts: u32,
    window_secs: u64,
    max_entries: usize,
}

impl RateLimiter {
    /// Create a limiter allowing `max_attempts` within `window_secs`.
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
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
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut map = self.attempts.lock();
        if map.len() >= self.max_entries && !map.contains_key(&ip) {
            let window_secs = self.window_secs;
            map.retain(|_, (_, started)| started.elapsed().as_secs() < window_secs);
            if map.len() >= self.max_entries {
                // Every entry is still live: a spray from more distinct sources
                // than the cap. Leave the existing counters alone and let this
                // untracked source through. Clearing the map instead would hand
                // anyone who is already throttled a way to reset their own
                // budget, and refusing would turn the same spray into a global
                // login lockout. Whoever can hold this many live buckets already
                // commands more addresses than the limit meaningfully bounds.
                return true;
            }
        }
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            *entry = (1, Instant::now());
            return true;
        }
        if entry.0 >= self.max_attempts {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// Hand back the attempt reserved by [`try_acquire`](Self::try_acquire).
    ///
    /// Called after a *successful* login. The control exists to stop password
    /// guessing, and a legitimate user who signs in repeatedly (new device,
    /// cleared cookies, a test suite) should not be locked out by it; an
    /// attacker's every attempt is a failure, so their budget is unchanged.
    pub fn release(&self, ip: IpAddr) {
        let mut map = self.attempts.lock();
        if let Some(entry) = map.get_mut(&ip) {
            entry.0 = entry.0.saturating_sub(1);
            if entry.0 == 0 {
                map.remove(&ip);
            }
        }
    }
}

/// Client address used as the rate-limit key.
///
/// `X-Forwarded-For` is honoured **only** when the TCP peer is loopback — the
/// standard same-host/docker-compose reverse-proxy layout. From any other peer
/// the header is client-controlled, and honouring it would let an attacker
/// rotate a fake source IP to bypass the limit entirely. A missing peer is
/// treated the same way: fail closed rather than let a degraded service stack
/// silently re-open the header.
///
/// The **last** hop is the one taken, not the first. nginx's stock
/// `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` (and Caddy's
/// `reverse_proxy`) *append* the peer address to whatever the client sent, so
/// the leftmost entry is attacker-chosen and only the rightmost was written by
/// the trusted proxy. Reading the left would make the limit free to bypass by
/// varying a header. This assumes exactly one trusted proxy; a chain would need
/// the Nth from the right, which is what a `--trusted-proxies` option would buy.
pub fn rate_limit_key(peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
    if peer.is_some_and(|ip| ip.is_loopback())
        && let Some(value) = headers.get("x-forwarded-for")
        && let Ok(raw) = value.to_str()
        && let Some(last) = raw.rsplit(',').next()
        && let Ok(ip) = last.trim().parse::<IpAddr>()
    {
        return ip;
    }
    peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
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
        assert!(limiter.attempts.lock().is_empty());
    }

    #[test]
    fn map_is_pruned_at_capacity() {
        let mut limiter = RateLimiter::new(5, 60);
        limiter.max_entries = 4;
        for last in 0..50u8 {
            limiter.try_acquire(ip(last));
        }
        assert!(limiter.attempts.lock().len() <= 4);
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

    #[test]
    fn rate_limit_key_prefers_xff_only_from_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let appended = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(appended, rate_limit_key(Some(loopback), &headers));

        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(proxy, rate_limit_key(Some(proxy), &headers));

        // No TCP peer: fail closed, the header is not trusted either.
        assert_eq!(loopback, rate_limit_key(None, &headers));
        assert_eq!(loopback, rate_limit_key(None, &HeaderMap::new()));
        assert_eq!(proxy, rate_limit_key(Some(proxy), &HeaderMap::new()));
    }

    /// Regression: nginx's stock `$proxy_add_x_forwarded_for` appends the peer,
    /// so the leftmost entry is whatever the client sent. Keying on it let an
    /// attacker mint a fresh bucket per request.
    #[test]
    fn spoofed_leading_xff_hops_do_not_change_the_key() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        for spoof in ["1.2.3.4", "5.6.7.8", "9.9.9.9, 8.8.8.8"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                format!("{spoof}, 198.51.100.7").parse().unwrap(),
            );
            assert_eq!(real, rate_limit_key(Some(loopback), &headers));
        }
    }

    #[test]
    fn rate_limit_key_honours_ipv6_loopback_and_ignores_garbage_headers() {
        let v6_loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(v6_loopback, rate_limit_key(Some(v6_loopback), &headers));
    }
}
