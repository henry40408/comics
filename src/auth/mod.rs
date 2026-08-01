mod audit;
mod config;
mod middleware;
mod ratelimit;
mod session;
mod trusted_proxies;

pub use audit::SessionAuditSalt;
pub use config::AuthConfig;
pub use middleware::{
    AuthState, Rejection, SESSION_COOKIE, auth_middleware_fn, authenticate, build_session_cookie,
    build_session_removal_cookie, session_cookie_name, session_id_of, user_agent,
};
pub use ratelimit::{RateLimiter, Scope, Throttle, rate_limit_key};
pub use session::{
    DEFAULT_ABSOLUTE_TTL, DEFAULT_IDLE_TTL, Expiry, SessionStore, Validation, is_session_id,
};
pub use trusted_proxies::TrustedProxies;
