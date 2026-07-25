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

/// Per-client-IP sliding-window limiter for login attempts.
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

    /// Whether `ip` may make another attempt.
    pub fn check(&self, ip: IpAddr) -> bool {
        let map = self.attempts.lock();
        match map.get(&ip) {
            // An elapsed window is as good as no record; `record` resets it.
            Some((_, started)) if started.elapsed().as_secs() >= self.window_secs => true,
            Some((count, _)) => *count < self.max_attempts,
            None => true,
        }
    }

    /// Record an attempt from `ip`, resetting the window when it has elapsed.
    pub fn record(&self, ip: IpAddr) {
        let mut map = self.attempts.lock();
        if map.len() >= self.max_entries && !map.contains_key(&ip) {
            let window_secs = self.window_secs;
            map.retain(|_, (_, started)| started.elapsed().as_secs() < window_secs);
            // Every entry may still be live (a genuine distributed spray). Drop
            // the map rather than let it grow past the cap: the alternative is
            // unbounded memory driven by attacker-chosen source addresses.
            if map.len() >= self.max_entries {
                map.clear();
            }
        }
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }
}

/// Client address used as the rate-limit key.
///
/// `X-Forwarded-For`'s first hop is honoured **only** when the TCP peer is
/// loopback — the standard same-host/docker-compose reverse-proxy layout. From
/// any other peer the header is client-controlled, and honouring it would let an
/// attacker rotate a fake source IP to bypass the limit entirely. `peer` is
/// `None` in unit tests that bypass the service stack.
pub fn rate_limit_key(peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
    let trust_headers = match peer {
        None => true,
        Some(ip) => ip.is_loopback(),
    };
    if trust_headers
        && let Some(value) = headers.get("x-forwarded-for")
        && let Ok(raw) = value.to_str()
        && let Some(first) = raw.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn allows_up_to_max_attempts() {
        let limiter = RateLimiter::new(5, 60);
        let addr = ip(1);
        for _ in 0..4 {
            assert!(limiter.check(addr));
            limiter.record(addr);
        }
        assert!(limiter.check(addr));
        limiter.record(addr);
        assert!(!limiter.check(addr));
    }

    #[test]
    fn window_expiry_resets_the_counter() {
        // A zero-second window is elapsed the moment it is recorded.
        let limiter = RateLimiter::new(1, 0);
        let addr = ip(2);
        limiter.record(addr);
        assert!(limiter.check(addr));
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let limiter = RateLimiter::new(1, 60);
        limiter.record(ip(3));
        assert!(!limiter.check(ip(3)));
        assert!(limiter.check(ip(4)));
    }

    #[test]
    fn map_is_pruned_at_capacity() {
        let mut limiter = RateLimiter::new(5, 60);
        limiter.max_entries = 4;
        for last in 0..50u8 {
            limiter.record(ip(last));
        }
        assert!(limiter.attempts.lock().len() <= 4);
    }

    #[test]
    fn rate_limit_key_prefers_xff_only_from_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(ip(9), rate_limit_key(Some(loopback), &headers));

        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(proxy, rate_limit_key(Some(proxy), &headers));

        assert_eq!(loopback, rate_limit_key(None, &HeaderMap::new()));
        assert_eq!(proxy, rate_limit_key(Some(proxy), &HeaderMap::new()));
    }

    #[test]
    fn rate_limit_key_honours_ipv6_loopback_and_ignores_garbage_headers() {
        let v6_loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(v6_loopback, rate_limit_key(Some(v6_loopback), &headers));
    }
}
