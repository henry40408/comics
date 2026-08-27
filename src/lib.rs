pub mod assets;
pub mod auth;
pub mod csrf;
pub mod error;
pub mod handlers;
pub mod helpers;
pub mod models;
pub mod secret;
pub mod security_headers;
pub mod state;

pub use assets::{
    APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, FAVICON_PNG, FAVICON_SVG, THEME_JS, assets_version,
};
pub use auth::{
    AuthConfig, DEFAULT_ABSOLUTE_TTL, DEFAULT_IDLE_TTL, RateLimiter, SessionAuditSalt,
    SessionStore, TrustedProxies, auth_middleware_fn, build_session_removal_cookie, rate_limit_key,
    session_cookie_name,
};
pub use csrf::csrf_origin_guard;
pub use error::{AppError, AppResult};
pub use handlers::{
    Healthz, healthz_route, index_route, login_route, login_submit_route, logout_route,
    rescan_books_route, show_book_route, show_page_route, show_thumb_route, shuffle_book_route,
    shuffle_route,
};
pub use models::{Book, BookScan, Page, scan_books};
pub use secret::{Secret, hex_lower};
pub use security_headers::{no_store_html, security_headers_layer};
pub use state::AppState;

pub const VERSION: &str = env!("APP_VERSION");

/// Longest password accepted, in bytes.
///
/// Not the algorithm's ceiling — RFC 9106 allows 2^32-1 bytes and the password
/// only feeds a linear `BLAKE2b` pre-hash, so length costs nothing the way
/// bcrypt's 72-byte truncation did. It is the "maximum input length" the OWASP
/// Authentication Cheat Sheet asks of a comparison function, set as a backstop
/// against absurd input. A kilobyte is 1024 ASCII characters or roughly 341
/// Traditional Chinese ones, comfortably past the 64 the cheat sheet asks be
/// supported — which the old bcrypt ceiling could not honour for a non-ASCII
/// passphrase.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Shortest password `hash-password` accepts without comment, in **characters**.
///
/// The OWASP Authentication Cheat Sheet calls a password under 15 characters
/// weak when no second factor is available, and comics has none. Advice rather
/// than a rule: the one user is also the operator, so their own password length
/// is their call, and a hard floor would only teach them to generate the hash
/// elsewhere.
///
/// Counted in characters where [`MAX_PASSWORD_BYTES`] counts bytes: the ceiling
/// is about resource use, the floor about how much a person had to remember. A
/// 15-*byte* floor would pass a Traditional Chinese passphrase at five
/// characters, a third of what is asked of an ASCII one.
pub const MIN_PASSWORD_CHARS: usize = 15;

/// How many password verifications may run at once.
///
/// Argon2id at the parameters below allocates **19 MiB per verification**,
/// against bcrypt's four kilobytes. Being memory-hard is the point, but it means
/// concurrency has to be bounded, or the twenty attempts a minute the rate
/// limiter admits could ask for 380 MiB at once — on what may well be a NAS.
/// Four caps it near 76 MiB while leaving room for a household's simultaneous
/// sign-ins; beyond that requests queue for the ~15 ms, rather than being
/// refused.
pub const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// An Argon2 hash at parameters far below the real ones.
///
/// Test-only. Verification reads its parameters from the hash itself, so the
/// tests exercise the server's code path without paying 19 MiB and ~25 ms per
/// fixture. One mebibyte and one pass still leave a verification three orders of
/// magnitude above a string comparison, which is what the timing test needs.
#[cfg(test)]
pub(crate) fn test_password_hash(password: &str) -> String {
    use argon2::{
        Algorithm, Argon2, Params, PasswordHasher as _, Version,
        password_hash::{SaltString, rand_core::OsRng},
    };
    let params = Params::new(1024, 1, 1, None).expect("valid test parameters");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .expect("hashing a test password")
        .to_string()
}
