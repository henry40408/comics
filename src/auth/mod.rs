mod audit;
mod config;
mod key;
mod middleware;
mod ratelimit;

pub use audit::SessionAuditSalt;
pub use config::AuthConfig;
pub use key::{hex_lower, parse_session_key};
pub use middleware::{
    AuthState, SESSION_COOKIE, auth_middleware_fn, authenticate, build_session_cookie,
    build_session_removal_cookie, session_cookie_name, session_cookie_nonce, session_nonce_of,
};
pub use ratelimit::{RateLimiter, rate_limit_key};
