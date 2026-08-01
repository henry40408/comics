use std::{path::PathBuf, sync::Arc};

use cookie::Key;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::auth::{AuthConfig, RateLimiter, SessionAuditSalt, SessionStore, TrustedProxies};
use crate::models::BookScan;

#[derive(Clone)]
pub struct AppState {
    pub auth_config: AuthConfig,
    /// Key signing session cookies, derived from `COMICS_SECRET`; when that is
    /// unset a random secret is generated at startup, in which case a restart
    /// invalidates every existing session.
    pub key: Key,
    pub data_dir: PathBuf,
    pub scan: Arc<RwLock<Option<BookScan>>>,
    /// Salt for hashed book/page IDs, derived from `COMICS_SECRET` through a
    /// different domain separator than [`key`](Self::key).
    pub seed: u64,
    pub cache_dir: PathBuf,
    /// Bounds concurrent thumbnail generation (CPU-bound decode + resize).
    pub thumb_sem: Arc<Semaphore>,
    /// Bounds concurrent password verifications. Argon2id is memory-hard by
    /// design — 19 MiB a time — so without this the login attempts the rate
    /// limiter admits could all allocate at once. See
    /// [`MAX_CONCURRENT_VERIFICATIONS`](crate::MAX_CONCURRENT_VERIFICATIONS).
    pub verify_sem: Arc<Semaphore>,
    pub cookie_secure: bool,
    pub login_limiter: Arc<RateLimiter>,
    /// Reverse proxies whose `X-Forwarded-For` is believed when deriving that
    /// client IP. Empty by default, which means the TCP peer is used instead.
    pub trusted_proxies: TrustedProxies,
    /// The live sessions. Held in memory only, so a restart ends every session —
    /// the price of being able to end one deliberately.
    pub sessions: Arc<SessionStore>,
    /// Salts session identifiers before they reach the audit log. Never logged.
    pub audit_salt: Arc<SessionAuditSalt>,
    /// `Strict-Transport-Security` max-age, in seconds.
    pub hsts_max_age: Option<u64>,
}
