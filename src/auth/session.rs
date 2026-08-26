use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use sha2::{Digest as _, Sha256};

use crate::secret::hex_lower;

/// Bytes of the session identifier (128 bits), per the OWASP Session Management
/// Cheat Sheet's minimum for a value it also requires to be meaningless.
const SESSION_ID_BYTES: usize = 16;

pub const SESSION_ID_HEX_LEN: usize = SESSION_ID_BYTES * 2;

/// Bytes of the stored `User-Agent` digest. Only ever compared, so eight is
/// ample and the string itself would just be a larger thing to leak. Exactly a
/// `u64`, which is what lets it live in an atomic — see [`Record::user_agent`].
const USER_AGENT_DIGEST_BYTES: usize = 8;

/// The cheat sheet's 15–30 minutes assumes a session is a unit of work. A comic
/// reader is opened, left, and come back to; that short a window would teach the
/// one user to pick a weaker password rather than retype a strong one. Three
/// days still keeps an abandoned session on a borrowed device inside the loan,
/// which is the threat the idle window actually addresses here.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(72 * 60 * 60);

/// Hard ceiling on a session's age regardless of activity, unchanged from the
/// cookie-only implementation this replaced.
pub const DEFAULT_ABSOLUTE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Live sessions kept before the oldest is evicted.
///
/// Unreachable in practice: the store only grows on a *successful* login, which
/// needs the credentials and is already throttled. A backstop against unbounded
/// memory, not a control — hence evicting rather than refusing, which would turn
/// a full store into a login lockout.
const MAX_SESSIONS: usize = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    Idle,
    /// Outlived the ceiling, however active it was.
    Absolute,
}

impl Expiry {
    /// Stable identifier for the `reason` field of an audit event.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Absolute => "absolute",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validation {
    Valid {
        /// The `User-Agent` differs from the one the session was created with.
        ///
        /// Reported, never enforced. The cheat sheet binds a session to client
        /// properties for *detection* and is explicit they cannot defend: a
        /// browser rewrites its `User-Agent` every major version, so terminating
        /// would log the one legitimate user out every few weeks to inconvenience
        /// an attacker who need only copy the header.
        user_agent_changed: bool,
    },
    /// The identifier was well-formed but names no live session — expired long
    /// ago, already destroyed, or issued by a previous process.
    Unknown,
    /// The session existed and has just been destroyed for the given reason.
    Expired(Expiry),
}

struct Record {
    created_at: Instant,
    /// Seconds since [`SessionStore::start`] at the most recent request.
    ///
    /// Atomic, and behind an [`Arc`], so refreshing it needs only a *read* lock
    /// on the map: one page turn is an HTML request plus one per image, all
    /// through the auth middleware, and a write lock each would serialise them.
    last_seen: AtomicU64,
    /// Digest of the `User-Agent` last seen on this session.
    ///
    /// Swapped rather than merely compared, so a change is reported *once*:
    /// otherwise one browser update warns for every image of every page turn.
    user_agent: AtomicU64,
}

/// The live sessions, in memory.
///
/// Sessions do not survive a restart — the identifier is opaque and the state
/// lives only here. That is the price of being able to *end* a session: the
/// signed self-describing cookie this replaced survived restarts precisely
/// because the server held no record of it, so logout could only ask the browser
/// nicely and a leaked cookie stayed valid for its full seven days, revocable
/// only by rotating `COMICS_SECRET` — which also changes every book and page
/// URL. The absolute ceiling already forced a fresh login weekly, so restarts
/// merely move that re-login off a fixed schedule.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Arc<Record>>>,
    /// Monotonic base for `last_seen`; `Instant` itself cannot live in an atomic.
    start: Instant,
    idle_ttl: Duration,
    absolute_ttl: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(idle_ttl: Duration, absolute_ttl: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            start: Instant::now(),
            idle_ttl,
            absolute_ttl,
            max_sessions: MAX_SESSIONS,
        }
    }

    /// Seconds since this store was created.
    fn now(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// The identifier is 128 CSPRNG bits as hex and carries no structure at
    /// all: expiry, `User-Agent` and creation time are held here, so there is
    /// nothing in the value to decode or to accidentally trust.
    pub fn create(&self, user_agent: &str) -> String {
        let id = hex_lower(&rand::random::<[u8; SESSION_ID_BYTES]>());
        let record = Arc::new(Record {
            created_at: Instant::now(),
            last_seen: AtomicU64::new(self.now()),
            user_agent: AtomicU64::new(digest(user_agent)),
        });

        let mut sessions = self.sessions.write();
        self.drop_expired(&mut sessions);
        if sessions.len() >= self.max_sessions {
            evict_oldest(&mut sessions);
        }
        sessions.insert(id.clone(), record);
        id
    }

    /// Look `id` up, refreshing its idle window when it is still valid.
    ///
    /// An expired session is destroyed here rather than left to the next prune,
    /// so that the window between "expired" and "gone" is never observable.
    pub fn validate(&self, id: &str, user_agent: &str) -> Validation {
        let Some(record) = self.sessions.read().get(id).map(Arc::clone) else {
            return Validation::Unknown;
        };

        if record.created_at.elapsed() >= self.absolute_ttl {
            self.destroy(id);
            return Validation::Expired(Expiry::Absolute);
        }
        let now = self.now();
        if now.saturating_sub(record.last_seen.load(Ordering::Relaxed)) >= self.idle_ttl.as_secs() {
            self.destroy(id);
            return Validation::Expired(Expiry::Idle);
        }

        record.last_seen.store(now, Ordering::Relaxed);
        let user_agent = digest(user_agent);
        Validation::Valid {
            user_agent_changed: record.user_agent.swap(user_agent, Ordering::Relaxed) != user_agent,
        }
    }

    /// After this the identifier is refused on every subsequent request — the
    /// server-side revocation a cookie-only implementation cannot do.
    pub fn destroy(&self, id: &str) -> bool {
        self.sessions.write().remove(id).is_some()
    }

    /// End every live session, but only when `id` names one of them.
    ///
    /// What logout calls: comics authenticates one set of credentials, so every
    /// session is the same person's and "log me out" can mean all of them — the
    /// only way to invalidate a stolen cookie short of a restart (the cheat
    /// sheet leaves this to the application, under *Simultaneous Session
    /// Logons*).
    ///
    /// **Membership is the authorisation.** `/logout` sits outside the auth
    /// middleware and the CSRF guard passes header-less clients, so an
    /// unconditional clear would let any anonymous `POST /logout` sign everyone
    /// out. One write lock, so the count cannot race a concurrent login.
    pub fn destroy_all(&self, id: &str) -> usize {
        let mut sessions = self.sessions.write();
        if !sessions.contains_key(id) {
            return 0;
        }
        let ended = sessions.len();
        sessions.clear();
        ended
    }

    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forget every session past either deadline.
    fn drop_expired(&self, sessions: &mut HashMap<String, Arc<Record>>) {
        let now = self.now();
        let idle = self.idle_ttl.as_secs();
        sessions.retain(|_, record| {
            record.created_at.elapsed() < self.absolute_ttl
                && now.saturating_sub(record.last_seen.load(Ordering::Relaxed)) < idle
        });
    }
}

/// Drop the least recently used session, so a full store still admits a login.
fn evict_oldest(sessions: &mut HashMap<String, Arc<Record>>) {
    let oldest = sessions
        .iter()
        .min_by_key(|(_, record)| record.last_seen.load(Ordering::Relaxed))
        .map(|(id, _)| id.clone());
    if let Some(id) = oldest {
        sessions.remove(&id);
    }
}

/// Truncated SHA-256 of a `User-Agent`, for comparison only.
fn digest(user_agent: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(user_agent.as_bytes());
    let mut out = [0u8; USER_AGENT_DIGEST_BYTES];
    out.copy_from_slice(&hasher.finalize()[..USER_AGENT_DIGEST_BYTES]);
    u64::from_be_bytes(out)
}

/// A cheap filter so a malformed cookie is refused without touching the lock.
/// It says nothing about whether the session exists.
pub fn is_session_id(value: &str) -> bool {
    value.len() == SESSION_ID_HEX_LEN && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "Mozilla/5.0 (X11; Linux x86_64)";

    fn store() -> SessionStore {
        SessionStore::new(DEFAULT_IDLE_TTL, DEFAULT_ABSOLUTE_TTL)
    }

    fn valid(store: &SessionStore, id: &str) -> bool {
        matches!(store.validate(id, UA), Validation::Valid { .. })
    }

    #[test]
    fn a_created_session_validates() {
        let store = store();
        let id = store.create(UA);
        assert!(valid(&store, &id));
        assert_eq!(1, store.len());
    }

    #[test]
    fn identifiers_are_opaque_and_unique() {
        let store = store();
        let ids: std::collections::HashSet<String> = (0..100).map(|_| store.create(UA)).collect();
        assert_eq!(100, ids.len());
        for id in &ids {
            assert!(is_session_id(id), "{id}");
        }
    }

    /// The point of the whole change: after logout the identifier is refused,
    /// which a signed self-describing cookie could never achieve.
    #[test]
    fn destroy_makes_the_identifier_useless() {
        let store = store();
        let id = store.create(UA);
        assert!(valid(&store, &id));

        assert!(store.destroy(&id));
        assert_eq!(Validation::Unknown, store.validate(&id, UA));
        assert!(store.is_empty());

        // Destroying twice is not an error, just a no-op.
        assert!(!store.destroy(&id));
    }

    /// Logout ends the other sessions too, which is what makes a cookie copied
    /// from another device invalidatable without restarting the server.
    #[test]
    fn destroy_all_ends_every_session() {
        let store = store();
        let phone = store.create(UA);
        let desktop = store.create(UA);
        let stolen = store.create(UA);

        assert_eq!(3, store.destroy_all(&phone));

        assert_eq!(Validation::Unknown, store.validate(&desktop, UA));
        assert_eq!(Validation::Unknown, store.validate(&stolen, UA));
        assert!(store.is_empty());
    }

    /// Membership is the authorisation: `/logout` is public, so an identifier
    /// the store never issued must not be able to sign everyone else out.
    #[test]
    fn destroy_all_ignores_an_identifier_it_never_issued() {
        let store = store();
        let live = store.create(UA);

        assert_eq!(0, store.destroy_all(&"0".repeat(32)));
        assert!(valid(&store, &live), "an outsider ended a live session");
    }

    #[test]
    fn an_unissued_identifier_is_unknown() {
        let store = store();
        assert_eq!(Validation::Unknown, store.validate(&"0".repeat(32), UA));
    }

    /// A zero idle window is elapsed the moment it is recorded.
    #[test]
    fn idle_expiry_destroys_the_session() {
        let store = SessionStore::new(Duration::ZERO, DEFAULT_ABSOLUTE_TTL);
        let id = store.create(UA);
        assert_eq!(Validation::Expired(Expiry::Idle), store.validate(&id, UA));
        // Expired means gone, not merely refused.
        assert!(store.is_empty());
        assert_eq!(Validation::Unknown, store.validate(&id, UA));
    }

    /// The absolute ceiling is checked first, so an active session still dies.
    #[test]
    fn absolute_expiry_beats_activity() {
        let store = SessionStore::new(DEFAULT_IDLE_TTL, Duration::ZERO);
        let id = store.create(UA);
        assert_eq!(
            Validation::Expired(Expiry::Absolute),
            store.validate(&id, UA)
        );
        assert!(store.is_empty());
    }

    /// A changed `User-Agent` is reported, never enforced — a browser update
    /// must not log the one legitimate user out.
    #[test]
    fn a_changed_user_agent_is_reported_but_still_valid() {
        let store = store();
        let id = store.create(UA);

        assert_eq!(
            Validation::Valid {
                user_agent_changed: false
            },
            store.validate(&id, UA)
        );
        assert_eq!(
            Validation::Valid {
                user_agent_changed: true
            },
            store.validate(&id, "curl/8.0")
        );
        // Still usable afterwards: detection only.
        assert!(valid(&store, &id));
    }

    /// The digest is swapped in, not just compared, so one change is one report.
    /// Otherwise a browser update would warn on every image of every page turn.
    #[test]
    fn a_changed_user_agent_is_reported_only_once() {
        let store = store();
        let id = store.create(UA);

        assert_eq!(
            Validation::Valid {
                user_agent_changed: true
            },
            store.validate(&id, "curl/8.0")
        );
        for _ in 0..5 {
            assert_eq!(
                Validation::Valid {
                    user_agent_changed: false
                },
                store.validate(&id, "curl/8.0")
            );
        }
    }

    /// At capacity a session is evicted rather than the login refused — a full
    /// store must not become a lockout.
    ///
    /// Pinned at one session so the choice is forced: `last_seen` has
    /// second resolution, so sessions touched within the same second tie and the
    /// least-recently-used pick among them is arbitrary. That is immaterial
    /// against a three-day idle window, but it does mean the *selection* cannot
    /// be asserted without controlling the clock.
    #[test]
    fn at_capacity_a_session_is_evicted_rather_than_the_login_refused() {
        let mut store = store();
        store.max_sessions = 1;

        let first = store.create(UA);
        let second = store.create(UA);

        assert_eq!(1, store.len());
        assert_eq!(Validation::Unknown, store.validate(&first, UA));
        assert!(valid(&store, &second));
    }

    /// Creating a session sweeps out the ones that have already lapsed, so an
    /// abandoned session does not occupy the cap forever.
    #[test]
    fn create_prunes_expired_sessions() {
        let store = SessionStore::new(Duration::ZERO, DEFAULT_ABSOLUTE_TTL);
        for _ in 0..5 {
            store.create(UA);
        }
        // Each create prunes the previous ones, leaving only the newest.
        assert_eq!(1, store.len());
    }

    #[test]
    fn is_session_id_accepts_only_the_issued_shape() {
        let store = store();
        assert!(is_session_id(&store.create(UA)));

        assert!(!is_session_id(""));
        assert!(!is_session_id(&"0".repeat(31)));
        assert!(!is_session_id(&"0".repeat(33)));
        assert!(!is_session_id(&format!("{}z", "0".repeat(31))));
        // The old `<nonce>.<expiry>` value shape.
        assert!(!is_session_id(&format!("{}.1700000000", "0".repeat(32))));
    }
}
