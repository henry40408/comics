mod config;
mod middleware;

pub use config::AuthConfig;
pub use middleware::{
    AuthState, SESSION_COOKIE, auth_middleware_fn, authenticate, build_session_cookie,
};
