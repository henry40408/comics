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

/// Hard cap on tracked IPs; expired windows are pruned first, so a spray from
/// many sources cannot grow the map without bound.
const MAX_ENTRIES: usize = 10_000;

#[derive(Clone, Copy)]
struct Window {
    count: u32,
    started: Instant,
}

impl Window {
    fn empty() -> Self {
        Self {
            count: 0,
            started: Instant::now(),
        }
    }

    /// Fixed window: measured from when it opened, not from the last attempt.
    fn is_expired(&self, window_secs: u64) -> bool {
        self.started.elapsed().as_secs() >= window_secs
    }

    /// Seconds until rollover, for `Retry-After`. Never zero: a client told zero
    /// retries at once and is refused again.
    fn seconds_until_reset(&self, window_secs: u64) -> u64 {
        window_secs
            .saturating_sub(self.started.elapsed().as_secs())
            .max(1)
    }
}

/// Which window refused an attempt; the three mean very different things in
/// the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// This client's own window: one person mistyping.
    PerIp,
    /// The overflow window shared once the per-IP map is full.
    Shared,
    /// Every address together: distributed guessing, and the reader is locked
    /// out too.
    Global,
}

impl Scope {
    /// Stable identifier for the `scope` field of an audit event.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerIp => "per_ip",
            Self::Shared => "shared",
            Self::Global => "global",
        }
    }
}

/// What [`RateLimiter::try_acquire`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Throttle {
    Allowed,
    Refused {
        scope: Scope,
        /// Seconds until the window that refused rolls over.
        retry_after_secs: u64,
    },
}

impl Throttle {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// All windows behind one lock: check-and-charge must be a single critical
/// section, or concurrent requests all observe the pre-attack count.
struct Buckets {
    per_ip: HashMap<IpAddr, Window>,
    /// Shared by every new source once `per_ip` is full.
    overflow: Window,
    /// Every attempt, whatever its source.
    global: Window,
}

/// Fixed-window, in-memory limiter for login attempts, keyed per client IP
/// *and* globally. Argon2id's per-verification cost alone is a speed bump, not
/// a control against online guessing (OWASP Authentication Cheat Sheet).
///
/// # Why a global window
///
/// OWASP's *Account Lockout* asks that failures be counted per **account**, not
/// per source. Per-IP alone gives every fresh address a full budget, and an IPv6
/// `/64` supplies thousands before `MAX_ENTRIES` fills. comics has one
/// credential pair, so `global` is the account-scoped counter.
///
/// # The lockout trade
///
/// A global counter can be exhausted deliberately, locking the reader out too.
/// That is accepted because the threshold is well above one person's use, the
/// window is fixed and short (no escalation — comics has no recovery path), and
/// a successful login refunds both windows ([`release`](Self::release)). The
/// alternative leaves distributed guessing unbounded.
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
    max_attempts: u32,
    global_max_attempts: u32,
    window_secs: u64,
    max_entries: usize,
}

impl RateLimiter {
    /// `global_max_attempts` should sit well above `max_attempts`; see the type
    /// docs.
    pub fn new(max_attempts: u32, global_max_attempts: u32, window_secs: u64) -> Self {
        Self {
            buckets: Mutex::new(Buckets {
                per_ip: HashMap::new(),
                overflow: Window::empty(),
                global: Window::empty(),
            }),
            max_attempts,
            global_max_attempts,
            window_secs,
            max_entries: MAX_ENTRIES,
        }
    }

    /// Reserve an attempt for `ip` before the (expensive) credential check;
    /// [`release`](Self::release) refunds it on success, so only failures count.
    ///
    /// At capacity the map is pruned of expired windows; if still full, the
    /// attempt shares the *overflow* window. The alternatives are worse:
    /// admitting untracked makes guessing unbounded, `clear()`ing lets a
    /// throttled source reset itself by spraying keys, and refusing turns a spray
    /// into a total lockout.
    pub fn try_acquire(&self, ip: IpAddr) -> Throttle {
        let mut buckets = self.buckets.lock();
        let Buckets {
            per_ip,
            overflow,
            global,
        } = &mut *buckets;
        let (window, scope) = self.window_for(per_ip, overflow, ip);

        // Check both before charging either, so a refusal spends from neither.
        if !self.has_room(window, self.max_attempts) {
            return Throttle::Refused {
                scope,
                retry_after_secs: window.seconds_until_reset(self.window_secs),
            };
        }
        if !self.has_room(global, self.global_max_attempts) {
            return Throttle::Refused {
                scope: Scope::Global,
                retry_after_secs: global.seconds_until_reset(self.window_secs),
            };
        }
        self.charge(window);
        self.charge(global);
        Throttle::Allowed
    }

    /// `ip`'s own window, or the overflow window if the map is full even after
    /// pruning.
    fn window_for<'a>(
        &self,
        per_ip: &'a mut HashMap<IpAddr, Window>,
        overflow: &'a mut Window,
        ip: IpAddr,
    ) -> (&'a mut Window, Scope) {
        if per_ip.len() >= self.max_entries && !per_ip.contains_key(&ip) {
            let window_secs = self.window_secs;
            per_ip.retain(|_, window| !window.is_expired(window_secs));
            if per_ip.len() >= self.max_entries {
                return (overflow, Scope::Shared);
            }
        }
        (per_ip.entry(ip).or_insert_with(Window::empty), Scope::PerIp)
    }

    /// An expired window has room: [`charge`](Self::charge) rolls it over.
    fn has_room(&self, window: &Window, max_attempts: u32) -> bool {
        window.is_expired(self.window_secs) || window.count < max_attempts
    }

    /// Only called after [`has_room`](Self::has_room), so the ceiling is not
    /// re-checked.
    fn charge(&self, window: &mut Window) {
        if window.is_expired(self.window_secs) {
            *window = Window {
                count: 1,
                started: Instant::now(),
            };
        } else {
            window.count += 1;
        }
    }

    /// Refund the attempt reserved by [`try_acquire`](Self::try_acquire) after a
    /// *successful* login, so legitimate sign-ins never spend a budget meant for
    /// guessing — least of all the global one the reader shares with attackers.
    /// An address without its own window was charged to overflow, so that is
    /// refunded instead. Only callers past the credential check reach here.
    pub fn release(&self, ip: IpAddr) {
        let mut buckets = self.buckets.lock();
        buckets.global.count = buckets.global.count.saturating_sub(1);
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
/// `X-Forwarded-For` is honoured **only** when the TCP peer is in
/// [`TrustedProxies`] (empty by default): anyone can write the header. No peer
/// at all fails closed onto one shared bucket.
///
/// The client is the rightmost hop that is not a trusted proxy — proxies
/// *append*, so the leftmost entry is attacker-chosen. Hops are canonicalised
/// (a `::ffff:` form must not open a second bucket), and every header *line* is
/// read, since some proxies append a line rather than extend one.
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

static UNTRUSTED_FORWARD_WARNED: AtomicBool = AtomicBool::new(false);

/// Warn, once per process, that an untrusted peer's `X-Forwarded-For` is being
/// dropped. Done on first sight rather than at startup, which cannot tell
/// whether a proxy exists: here it is either a missing `--trusted-proxies`
/// entry (every client collapses into one bucket) or a forgery.
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

/// The rightmost untrusted `X-Forwarded-For` hop; `None` (caller falls back to
/// the peer) when absent, unparseable, or all trusted.
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

    /// A limiter whose global window never refuses.
    fn limiter(max_attempts: u32, window_secs: u64) -> RateLimiter {
        RateLimiter::new(max_attempts, u32::MAX, window_secs)
    }

    #[test]
    fn allows_up_to_max_attempts() {
        let limiter = limiter(5, 60);
        let addr = ip(1);
        for _ in 0..5 {
            assert!(limiter.try_acquire(addr).is_allowed());
        }
        assert!(!limiter.try_acquire(addr).is_allowed());
    }

    #[test]
    fn window_expiry_resets_the_counter() {
        // A zero-second window is elapsed the moment it is recorded.
        let limiter = limiter(1, 0);
        let addr = ip(2);
        assert!(limiter.try_acquire(addr).is_allowed());
        assert!(limiter.try_acquire(addr).is_allowed());
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let limiter = limiter(1, 60);
        assert!(limiter.try_acquire(ip(3)).is_allowed());
        assert!(!limiter.try_acquire(ip(3)).is_allowed());
        assert!(limiter.try_acquire(ip(4)).is_allowed());
    }

    #[test]
    fn release_returns_the_reserved_attempt() {
        let limiter = limiter(2, 60);
        let addr = ip(5);
        for _ in 0..10 {
            assert!(limiter.try_acquire(addr).is_allowed());
            limiter.release(addr);
        }
        assert!(limiter.buckets.lock().per_ip.is_empty());
    }

    #[test]
    fn map_is_pruned_at_capacity() {
        let mut limiter = limiter(5, 60);
        limiter.max_entries = 4;
        for last in 0..50u8 {
            limiter.try_acquire(ip(last)).is_allowed();
        }
        assert!(limiter.buckets.lock().per_ip.len() <= 4);
    }

    /// A spray of fresh keys must not reset a throttled source's counter.
    #[test]
    fn capacity_spray_does_not_reset_an_existing_counter() {
        let mut limiter = limiter(1, 60);
        limiter.max_entries = 4;
        let victim = ip(200);
        assert!(limiter.try_acquire(victim).is_allowed());
        assert!(!limiter.try_acquire(victim).is_allowed());

        for last in 0..50u8 {
            limiter.try_acquire(ip(last)).is_allowed();
        }
        assert!(
            !limiter.try_acquire(victim).is_allowed(),
            "spray reset the counter"
        );
    }

    /// At capacity, holding more addresses than the cap must not buy unlimited
    /// attempts.
    #[test]
    fn overflow_bucket_is_shared_and_finite() {
        let mut limiter = limiter(3, 60);
        limiter.max_entries = 0;

        let allowed = (0..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(3, allowed, "50 distinct sources got {allowed} attempts");
    }

    /// A spray exhausting the overflow window must not spend a tracked source's
    /// budget.
    #[test]
    fn overflow_does_not_spend_a_tracked_source_budget() {
        let mut limiter = limiter(3, 60);
        limiter.max_entries = 1;
        let tracked = ip(1);
        assert!(limiter.try_acquire(tracked).is_allowed());

        // Map full: these all land on the overflow window.
        for last in 10..40u8 {
            limiter.try_acquire(ip(last)).is_allowed();
        }

        // Two of the tracked source's three attempts are still there.
        assert!(limiter.try_acquire(tracked).is_allowed());
        assert!(limiter.try_acquire(tracked).is_allowed());
        assert!(!limiter.try_acquire(tracked).is_allowed());
    }

    #[test]
    fn overflow_window_expires_like_any_other() {
        let mut limiter = limiter(1, 0);
        limiter.max_entries = 0;
        assert!(limiter.try_acquire(ip(1)).is_allowed());
        assert!(limiter.try_acquire(ip(2)).is_allowed());
    }

    #[test]
    fn release_refunds_the_overflow_bucket() {
        let mut limiter = limiter(1, 60);
        limiter.max_entries = 0;
        for round in 0..10 {
            assert!(limiter.try_acquire(ip(1)).is_allowed(), "round {round}");
            limiter.release(ip(1));
        }
    }

    #[test]
    fn a_refusal_names_the_window_that_said_no() {
        let per_ip = RateLimiter::new(1, 100, 60);
        assert!(per_ip.try_acquire(ip(1)).is_allowed());
        assert!(matches!(
            per_ip.try_acquire(ip(1)),
            Throttle::Refused {
                scope: Scope::PerIp,
                ..
            }
        ));

        let mut shared = RateLimiter::new(1, 100, 60);
        shared.max_entries = 0;
        assert!(shared.try_acquire(ip(1)).is_allowed());
        assert!(matches!(
            shared.try_acquire(ip(2)),
            Throttle::Refused {
                scope: Scope::Shared,
                ..
            }
        ));

        // Only the global window can refuse; ip(2) has its own budget unspent.
        let global = RateLimiter::new(100, 1, 60);
        assert!(global.try_acquire(ip(1)).is_allowed());
        assert!(matches!(
            global.try_acquire(ip(2)),
            Throttle::Refused {
                scope: Scope::Global,
                ..
            }
        ));
    }

    #[test]
    fn a_refusal_says_when_the_window_resets() {
        for limiter in [RateLimiter::new(1, 100, 60), RateLimiter::new(100, 1, 60)] {
            assert!(limiter.try_acquire(ip(1)).is_allowed());
            let Throttle::Refused {
                retry_after_secs, ..
            } = limiter.try_acquire(ip(1))
            else {
                panic!("the second attempt was allowed");
            };
            assert!((1..=60).contains(&retry_after_secs), "{retry_after_secs}");
        }
    }

    #[test]
    fn global_window_bounds_a_spray_from_many_addresses() {
        let limiter = RateLimiter::new(5, 7, 60);
        let allowed = (0..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(7, allowed, "50 distinct addresses got {allowed} attempts");
    }

    /// Otherwise one throttled source could exhaust everyone's shared budget.
    #[test]
    fn a_source_refused_per_ip_does_not_spend_the_global_window() {
        let limiter = RateLimiter::new(2, 10, 60);
        let noisy = ip(1);
        assert!(limiter.try_acquire(noisy).is_allowed());
        assert!(limiter.try_acquire(noisy).is_allowed());
        for _ in 0..20 {
            assert!(
                !limiter.try_acquire(noisy).is_allowed(),
                "per-IP window let a third by"
            );
        }
        // Two charged, so eight of the global ten remain.
        let allowed = (10..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(8, allowed, "the refused attempts were charged globally");
    }

    /// The global ceiling is the looser one, so the final count measures the
    /// per-IP window.
    #[test]
    fn global_refusal_does_not_spend_a_source_budget() {
        let limiter = RateLimiter::new(5, 8, 60);
        for last in 10..18u8 {
            assert!(limiter.try_acquire(ip(last)).is_allowed());
        }
        let reader = ip(1);
        for _ in 0..10 {
            assert!(
                !limiter.try_acquire(reader).is_allowed(),
                "global window let one by"
            );
        }

        // Roll the global window over by hand; the reader's five must remain.
        limiter.buckets.lock().global = Window::empty();
        let allowed = (0..10)
            .filter(|_| limiter.try_acquire(reader).is_allowed())
            .count();
        assert_eq!(5, allowed, "the reader's budget was spent while locked out");
    }

    #[test]
    fn release_refunds_the_global_window() {
        let limiter = RateLimiter::new(5, 3, 60);
        for round in 0..20 {
            assert!(limiter.try_acquire(ip(1)).is_allowed(), "round {round}");
            limiter.release(ip(1));
        }
        assert_eq!(0, limiter.buckets.lock().global.count);
    }

    /// Fixed, not escalating: this bounds the lockout a global counter invites.
    #[test]
    fn global_window_expires_like_any_other() {
        let limiter = RateLimiter::new(5, 1, 0);
        assert!(limiter.try_acquire(ip(1)).is_allowed());
        assert!(limiter.try_acquire(ip(2)).is_allowed());
        assert!(limiter.try_acquire(ip(3)).is_allowed());
    }

    #[test]
    fn concurrent_attempts_cannot_exceed_the_limit() {
        const THREADS: usize = 64;
        let limiter = Arc::new(limiter(5, 60));
        let barrier = Arc::new(Barrier::new(THREADS));
        let addr = ip(7);

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    limiter.try_acquire(addr).is_allowed()
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

    /// The default trusts nothing, loopback included.
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

        let stranger = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(stranger, rate_limit_key(Some(stranger), &headers, &trusted));
    }

    /// Proxies append, so the leftmost hops are client-chosen.
    #[test]
    fn spoofed_leading_xff_hops_do_not_change_the_key() {
        let trusted = trusting("10.0.0.5");
        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        for spoof in ["1.2.3.4", "5.6.7.8", "9.9.9.9, 8.8.8.8"] {
            let headers = xff(&format!("{spoof}, 198.51.100.7"));
            assert_eq!(real, rate_limit_key(Some(PROXY), &headers, &trusted));
        }
    }

    /// Taking the last entry would key on the inner proxy.
    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        let trusted = trusting("10.0.0.0/24");
        let headers = xff("203.0.113.9, 10.0.0.9, 10.0.0.5");
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(client, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

    /// `HAProxy`'s `option forwardfor` and Caddy's `header_up +X-Forwarded-For`
    /// append a new line; `headers.get(..)` would read only the client's.
    #[test]
    fn xff_spread_across_header_lines_is_read_whole() {
        let trusted = trusting("10.0.0.5");
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());

        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(real, rate_limit_key(Some(PROXY), &headers, &trusted));
    }

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

    /// A `[::]`-bound listener reports IPv4 peers in mapped form, which match no
    /// IPv4 prefix until canonicalised.
    #[test]
    fn ipv4_mapped_peer_is_canonicalised_before_matching() {
        let trusted = trusting("10.0.0.0/24");
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        let headers = xff("203.0.113.9");
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(client, rate_limit_key(Some(mapped), &headers, &trusted));
    }

    #[test]
    fn ipv4_mapped_hops_key_the_same_as_their_plain_form() {
        let trusted = trusting("10.0.0.5");
        let plain = rate_limit_key(Some(PROXY), &xff("203.0.113.9"), &trusted);
        let mapped = rate_limit_key(Some(PROXY), &xff("::ffff:203.0.113.9"), &trusted);
        assert_eq!(plain, mapped);
    }

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
