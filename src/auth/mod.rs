mod config;
mod key;
mod middleware;
mod ratelimit;

pub use config::AuthConfig;
pub use key::{hex_lower, parse_session_key};
pub use middleware::{
    AuthState, SESSION_COOKIE, auth_middleware_fn, authenticate, build_session_cookie,
};
pub use ratelimit::{RateLimiter, rate_limit_key};
