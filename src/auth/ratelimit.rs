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

    /// Measured from when the window opened, not from the last attempt — this is
    /// a fixed window, not a sliding one.
    fn is_expired(&self, window_secs: u64) -> bool {
        self.started.elapsed().as_secs() >= window_secs
    }

    /// Seconds until this window rolls over, for `Retry-After`.
    ///
    /// Never zero — an already-expired window included: a client told to retry
    /// in zero seconds retries immediately and is refused again.
    fn seconds_until_reset(&self, window_secs: u64) -> u64 {
        window_secs
            .saturating_sub(self.started.elapsed().as_secs())
            .max(1)
    }
}

/// Which window refused an attempt.
///
/// Distinguished because the three mean very different things to whoever reads
/// the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// This client's own window. One person mistyping a password.
    PerIp,
    /// The window shared by every source once the map is full — more live
    /// addresses than comics tracks individually.
    Shared,
    /// The account-scoped window: every address together. Distributed guessing,
    /// and the legitimate reader is locked out alongside the attacker.
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

/// Every window the limiter owns, behind one lock: check-and-charge must stay a
/// single critical section, or concurrent requests all observe the pre-attack
/// count.
struct Buckets {
    per_ip: HashMap<IpAddr, Window>,
    /// Shared by every source that arrives once `per_ip` is full. See
    /// [`RateLimiter::try_acquire`].
    overflow: Window,
    /// Every attempt, whatever its source. See [`RateLimiter`].
    global: Window,
}

/// Fixed-window limiter for login attempts, keyed per client IP *and* globally.
///
/// In-memory only: comics has no database, and a restart resetting the counters
/// is acceptable for a single-account service. Its purpose is to remove the zero
/// cost of an online dictionary attack against the one static credential pair
/// (OWASP Authentication Cheat Sheet, "Protect Against Automated Attacks");
/// Argon2id's ~15 ms and 19 MiB per verification is a speed bump, not a control.
///
/// # Why a global window as well
///
/// The cheat sheet asks, under *Account Lockout*, that the failure counter track
/// **the account** rather than the source address, "in order to prevent an
/// attacker from making login attempts from a large number of different IP
/// addresses". Per-IP alone was exactly that: every fresh address arrived with a
/// full budget, so an IPv6 `/64` bought five attempts apiece across tens of
/// thousands of addresses before [`MAX_ENTRIES`] filled and the overflow window
/// applied. comics authenticates one credential pair, so *the account* and
/// *everything* coincide: `global` is that account-scoped counter.
///
/// # The lockout trade
///
/// A global counter can be exhausted deliberately, refusing the legitimate
/// reader too — the denial of service the cheat sheet warns about. Three things
/// keep that acceptable: the threshold is far above one person's use (five
/// failures a minute per client, so a global twenty needs four addresses failing
/// within the minute); the window is fixed and short, costing at most the rest
/// of one minute rather than an exponential lockout's hours — escalation
/// protects an account with a recovery path, and comics has none; and a
/// successful login refunds both windows ([`release`](Self::release)). The
/// alternative was leaving distributed guessing unbounded, trading a minute of
/// unavailability under attack for the password itself.
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
    max_attempts: u32,
    global_max_attempts: u32,
    window_secs: u64,
    max_entries: usize,
}

impl RateLimiter {
    /// `global_max_attempts` bounds every source together, so it must sit well
    /// above `max_attempts`, which bounds one; see the type docs for the trade.
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

    /// Reserve an attempt for `ip`, returning whether it may proceed.
    ///
    /// Checked and counted under a single lock, so concurrent requests cannot
    /// all observe the pre-attack count. The reservation is taken *before* the
    /// credential comparison — which costs a full Argon2id verification — and
    /// handed back by [`release`](Self::release) once the credentials prove
    /// valid, so only failures ultimately consume the window.
    ///
    /// At capacity the map is pruned of expired windows; if it is still full the
    /// attempt shares a single *overflow* window. The alternatives are worse:
    /// admitting the source untracked makes guessing free and unbounded (a `/64`
    /// supplies effectively unlimited addresses, each still costing a
    /// verification); `clear()`ing lets anyone throttled reset their own budget
    /// by spraying keys; and refusing outright turns the spray into a total
    /// lockout. Sharing degrades to a global limit under attack while leaving
    /// every source already in the map on its own budget.
    ///
    /// The refusal names *which* window said no ([`Scope`]): reporting all three
    /// as "rate limited" buries the account lockout, which the cheat sheet asks
    /// specifically be logged and reviewed.
    pub fn try_acquire(&self, ip: IpAddr) -> Throttle {
        let mut buckets = self.buckets.lock();
        // Split the borrow: both windows are charged together.
        let Buckets {
            per_ip,
            overflow,
            global,
        } = &mut *buckets;
        let (window, scope) = self.window_for(per_ip, overflow, ip);

        // Both consulted before either is charged, or a source the other window
        // rejects would still spend from a budget it was never allowed to use.
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

    /// The window an attempt from `ip` is counted against: ordinarily its own,
    /// created on first sight; the shared overflow window once the map is full
    /// even after pruning — see [`try_acquire`](Self::try_acquire) for why.
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

    /// Whether `window` would admit one more attempt. An expired window has room
    /// by definition: [`charge`](Self::charge) is about to roll it over.
    fn has_room(&self, window: &Window, max_attempts: u32) -> bool {
        window.is_expired(self.window_secs) || window.count < max_attempts
    }

    /// An expired window is rolled over rather than topped up — what makes this
    /// fixed-window rather than sliding. Only called once
    /// [`has_room`](Self::has_room) said yes, so the ceiling is not re-checked.
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

    /// Hand back the attempt reserved by [`try_acquire`](Self::try_acquire),
    /// after a *successful* login: repeated legitimate sign-ins (new device,
    /// cleared cookies, a test suite) must not spend a budget aimed at guessing,
    /// and an attacker's attempts are all failures, so theirs is unchanged.
    ///
    /// An address with no window of its own was charged to the overflow bucket,
    /// so that is what gets the refund. The global window is refunded too, and
    /// for the sharper version of the same reason: it is the one window the
    /// reader shares with their attacker, so leaving sign-ins charged to it
    /// would walk ordinary use into a lockout no failure caused. Only a caller
    /// past the credential check reaches here, so neither refund is a way to top
    /// a shared window back up.
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
/// `X-Forwarded-For` is honoured **only** when the TCP peer is inside
/// [`TrustedProxies`] — an explicit operator setting, empty by default. Header
/// presence proves nothing: anyone who can reach the port can write one, and the
/// nginx snippet in wide circulation sets only `X-Real-IP` while forwarding a
/// client-supplied `X-Forwarded-For` verbatim. A missing peer means no
/// connection info at all: fail closed onto one shared bucket, which throttles
/// rather than exempts.
///
/// The client is the rightmost hop that is not itself a trusted proxy.
/// Right-to-left because nginx's `$proxy_add_x_forwarded_for` (and Caddy's
/// `reverse_proxy`) *append* the peer to whatever the client sent, leaving the
/// leftmost entry attacker-chosen; skipping trusted hops generalises that to a
/// chain. Hops are canonicalised, so a mapped `::ffff:` form cannot open a
/// second bucket for one client. Every header *line* is read: proxies that
/// append a line rather than extend one (`HAProxy`'s `option forwardfor`,
/// Caddy's `header_up +X-Forwarded-For`) leave the trusted hop in the last.
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
/// A startup warning cannot tell whether a proxy exists, so it would cry wolf at
/// every direct deployment. Waiting for a header makes the signal exact: either
/// a proxy is in front and missing from the list — which silently collapses
/// every client into one bucket — or somebody is forging the header. Once is
/// enough for both.
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
/// `None` when the header is absent, unparseable, or names only trusted
/// infrastructure; the caller then falls back to the peer, so a misconfigured
/// proxy degrades to one shared bucket rather than to no limit at all.
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

    /// A limiter whose global window can never be the reason for a refusal, so
    /// the tests below measure the per-IP and overflow windows alone. The ones
    /// that are *about* the global window build their own.
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

    /// A successful login hands its reservation back, so signing in repeatedly
    /// never exhausts the window.
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

    /// Regression: a spray of fresh keys used to hit `map.clear()`, handing an
    /// already-throttled source a way to reset its own counter.
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

    /// Regression: at capacity the limiter used to admit a fresh source *without*
    /// inserting it, so anyone holding more addresses than the cap — a single
    /// IPv6 `/64` is enough — got unlimited attempts, each still costing a
    /// verification. The shared overflow window is what bounds that.
    #[test]
    fn overflow_bucket_is_shared_and_finite() {
        let mut limiter = limiter(3, 60);
        // Nothing can be tracked individually, so every source overflows.
        limiter.max_entries = 0;

        let allowed = (0..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(3, allowed, "50 distinct sources got {allowed} attempts");
    }

    /// Exhausting the shared window must not spend the budget of a source that
    /// already has one — otherwise a spray locks out whoever is mid-login.
    #[test]
    fn overflow_does_not_spend_a_tracked_source_budget() {
        let mut limiter = limiter(3, 60);
        limiter.max_entries = 1;
        let tracked = ip(1);
        assert!(limiter.try_acquire(tracked).is_allowed());

        // The map is now full, so these all land on the shared window.
        for last in 10..40u8 {
            limiter.try_acquire(ip(last)).is_allowed();
        }

        // Two of the tracked source's three attempts are still there.
        assert!(limiter.try_acquire(tracked).is_allowed());
        assert!(limiter.try_acquire(tracked).is_allowed());
        assert!(!limiter.try_acquire(tracked).is_allowed());
    }

    /// The shared window rolls over on expiry like any other, so an attack does
    /// not lock the form out permanently once it stops.
    #[test]
    fn overflow_window_expires_like_any_other() {
        let mut limiter = limiter(1, 0);
        limiter.max_entries = 0;
        assert!(limiter.try_acquire(ip(1)).is_allowed());
        assert!(limiter.try_acquire(ip(2)).is_allowed());
    }

    /// A successful login costs nothing even when it was charged to the shared
    /// window — otherwise signing in during a spray eats budget others wait on.
    #[test]
    fn release_refunds_the_overflow_bucket() {
        let mut limiter = limiter(1, 60);
        limiter.max_entries = 0;
        for round in 0..10 {
            assert!(limiter.try_acquire(ip(1)).is_allowed(), "round {round}");
            limiter.release(ip(1));
        }
    }

    /// The three refusals are told apart, because the log has to tell them apart:
    /// one is a person mistyping, one is more sources than comics can track, and
    /// one is an account-wide lockout that catches the reader too.
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

        // Nothing can be tracked individually, so a second source shares a window.
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

        // A per-IP ceiling out of reach, so only the global window can refuse —
        // and ip(2) arrives with its own budget entirely unspent.
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

    /// `Retry-After` has to be inside the window and never zero — zero invites an
    /// immediate retry into the very same refusal.
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

    /// The gap the global window exists to close: per-IP alone, an attacker who
    /// holds addresses in bulk simply used a fresh one for each burst and was
    /// never throttled at all — the case the cheat sheet's *Account Lockout*
    /// section describes.
    #[test]
    fn global_window_bounds_a_spray_from_many_addresses() {
        let limiter = RateLimiter::new(5, 7, 60);
        let allowed = (0..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(7, allowed, "50 distinct addresses got {allowed} attempts");
    }

    /// An attempt the per-IP window refuses must not spend from the global one.
    /// Otherwise a single throttled source could exhaust the budget that every
    /// other source — including the reader — shares.
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
        // Two charged, so eight of the global ten must remain for everyone else.
        let allowed = (10..50u8)
            .filter(|&last| limiter.try_acquire(ip(last)).is_allowed())
            .count();
        assert_eq!(8, allowed, "the refused attempts were charged globally");
    }

    /// The mirror image: exhausting the global window must not quietly spend a
    /// source's own budget, which it would if the two were charged in sequence
    /// rather than checked together.
    ///
    /// The global ceiling is the looser of the two so that the per-IP window is
    /// what the final count measures; were it tighter, this would only be
    /// re-testing the global limit.
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

        // Roll the global window over by hand — what waiting out the minute does
        // — and the reader's own five must all still be there.
        limiter.buckets.lock().global = Window::empty();
        let allowed = (0..10)
            .filter(|_| limiter.try_acquire(reader).is_allowed())
            .count();
        assert_eq!(5, allowed, "the reader's budget was spent while locked out");
    }

    /// A successful login refunds the global window too — otherwise ordinary use
    /// would walk into a lockout that no failed attempt caused.
    #[test]
    fn release_refunds_the_global_window() {
        let limiter = RateLimiter::new(5, 3, 60);
        for round in 0..20 {
            assert!(limiter.try_acquire(ip(1)).is_allowed(), "round {round}");
            limiter.release(ip(1));
        }
        assert_eq!(0, limiter.buckets.lock().global.count);
    }

    /// Fixed, not escalating: once the window passes, the form works again. This
    /// is what bounds the denial of service a global counter otherwise invites.
    #[test]
    fn global_window_expires_like_any_other() {
        let limiter = RateLimiter::new(5, 1, 0);
        assert!(limiter.try_acquire(ip(1)).is_allowed());
        assert!(limiter.try_acquire(ip(2)).is_allowed());
        assert!(limiter.try_acquire(ip(3)).is_allowed());
    }

    /// Regression: checking and counting used to take the lock separately, so
    /// requests arriving together all observed the pre-attack count.
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
