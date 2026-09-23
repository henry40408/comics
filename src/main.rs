use std::{io, io::Write as _, net::SocketAddr, path::PathBuf, sync::Arc, thread};

use anyhow::{anyhow, bail};
use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _};
use axum::{
    Router, middleware,
    routing::{get, post},
};
use clap::{Parser, Subcommand, ValueEnum};
use http::header;
use parking_lot::RwLock;
use tokio::{
    net::TcpListener,
    signal,
    sync::{
        Semaphore,
        oneshot::{self, Sender},
    },
};
use tower_http::{
    csrf::CsrfLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::{
    Layer as _, Registry, filter::Targets, fmt::format::FmtSpan, layer::Filter,
    layer::SubscriberExt, util::SubscriberInitExt,
};

use comics::{
    APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, AppState, AuthConfig, DEFAULT_ABSOLUTE_TTL,
    DEFAULT_IDLE_TTL, FAVICON_PNG, FAVICON_SVG, MAX_CONCURRENT_VERIFICATIONS, MAX_PASSWORD_BYTES,
    MIN_PASSWORD_CHARS, RateLimiter, Secret, SessionAuditSalt, SessionStore, THEME_JS,
    TrustedProxies, VERSION, auth_middleware_fn, healthz_route, index_route, login_route,
    login_submit_route, logout_route, no_store_html, rescan_books_route, scan_books,
    security_headers_layer, show_book_route, show_page_route, show_thumb_route, shuffle_book_route,
    shuffle_route,
};

// The release image links musl, whose allocator is slow under concurrent,
// allocation-heavy work (rayon scans, thumbnail decoding).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Assets are fingerprinted in the URL (`?v=<hash>`), so they can be cached forever.
type AssetHeaders = [(header::HeaderName, &'static str); 2];
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const CSS_HEADERS: AssetHeaders = [
    (header::CONTENT_TYPE, "text/css"),
    (header::CACHE_CONTROL, IMMUTABLE),
];
const JS_HEADERS: AssetHeaders = [
    (header::CONTENT_TYPE, "text/javascript"),
    (header::CACHE_CONTROL, IMMUTABLE),
];
const SVG_HEADERS: AssetHeaders = [
    (header::CONTENT_TYPE, "image/svg+xml"),
    (header::CACHE_CONTROL, IMMUTABLE),
];
const PNG_HEADERS: AssetHeaders = [
    (header::CONTENT_TYPE, "image/png"),
    (header::CACHE_CONTROL, IMMUTABLE),
];

#[derive(Parser, Debug)]
#[command(author, version=VERSION, about, long_about=None)]
struct Opts {
    /// Username for the login form
    #[arg(long, env = "COMICS_AUTH_USERNAME")]
    auth_username: Option<String>,
    /// Hashed password for the login form
    #[arg(long, env = "COMICS_AUTH_PASSWORD_HASH")]
    auth_password_hash: Option<String>,
    /// Send the session cookie with the `Secure` attribute (HTTPS only).
    /// Off by default: comics cannot detect HTTPS behind a proxy, and a browser
    /// discards a `Secure` cookie over plain HTTP, locking LAN hosts out.
    #[arg(
        long,
        env = "COMICS_COOKIE_SECURE",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    cookie_secure: Option<bool>,
    /// At least 64 hex characters (`openssl rand -hex 32`); the cookie signing
    /// key and the book/page ID salt derive from it. Sessions end at every
    /// restart regardless; it keeps URLs stable and lets a stale cookie be told
    /// from a forged one. Unset means a random secret, and new URLs, per start.
    #[arg(long, env = "COMICS_SECRET")]
    secret: Option<Secret>,
    /// Send `Strict-Transport-Security` with this `max-age` (seconds). Off by
    /// default: a cached HSTS policy strands a plain-HTTP LAN host for the whole
    /// max-age. Enable only when always reached over HTTPS (e.g. 63072000).
    #[arg(long, env = "COMICS_HSTS_MAX_AGE")]
    hsts_max_age: Option<u64>,
    /// Reverse proxies whose `X-Forwarded-For` may set the login rate-limit key:
    /// comma-separated IPs and CIDR prefixes (e.g. `172.16.0.0/12,10.0.0.2`),
    /// naming the address the proxy connects *from*. Empty by default, which
    /// ignores the forgeable header; behind a proxy that is safe but makes every
    /// client share one bucket.
    #[arg(long, env = "COMICS_TRUSTED_PROXIES")]
    trusted_proxies: Option<TrustedProxies>,
    /// Turn off the CSRF origin guard entirely. Only for a plain-HTTP LAN host
    /// whose browser sends `Origin: null`, which locks the operator out of the
    /// login form; serving over HTTPS is the better fix. `SameSite=Strict` on the
    /// cookie remains. See the comment on the layer in `init_route`.
    #[arg(
        long,
        env = "COMICS_DISABLE_CSRF_GUARD",
        num_args = 0..=1,
        default_missing_value = "true",
        default_value = "false"
    )]
    disable_csrf_guard: bool,
    /// Bind host & port. Loopback by default; the container image sets
    /// `COMICS_BIND=0.0.0.0:8080`.
    #[arg(
        long,
        short = 'b',
        env = "COMICS_BIND",
        default_value = "127.0.0.1:8080"
    )]
    bind: String,
    /// Data directory
    #[arg(long, env = "COMICS_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,
    /// Directory for cached thumbnails (defaults to a "comics-thumbs" dir under the system temp dir)
    #[arg(long, env = "COMICS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
    /// Log format
    #[arg(long, env = "COMICS_LOG_FORMAT", default_value = "full")]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum LogFormat {
    #[default]
    Full,
    Compact,
    Pretty,
    Json,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Hash password
    #[command()]
    HashPassword {},
    /// List books
    #[command(alias = "ls")]
    List {},
}

/// Login attempts allowed per client IP within [`LOGIN_WINDOW_SECS`].
const LOGIN_MAX_ATTEMPTS: u32 = 5;
const LOGIN_WINDOW_SECS: u64 = 60;

/// Login attempts allowed across *every* client IP within [`LOGIN_WINDOW_SECS`]:
/// the account-scoped counter OWASP asks for. See [`RateLimiter`] for the
/// lockout trade-off.
const LOGIN_GLOBAL_MAX_ATTEMPTS: u32 = 20;

/// Whether the session cookie carries `Secure`. comics never terminates TLS, so
/// the explicit flag is the only input.
fn resolve_cookie_secure(override_value: Option<bool>) -> bool {
    override_value.unwrap_or(false)
}

fn spawn_initial_scan(state: Arc<AppState>, shutdown_tx: Sender<()>) {
    thread::spawn(move || {
        let new_scan = match scan_books(state.seed, &state.data_dir) {
            Ok(s) => s,
            Err(err) => {
                error!(?err, "initial scan failed");
                if shutdown_tx.send(()).is_err() {
                    error!("failed to send shutdown signal");
                }
                return;
            }
        };

        let books = new_scan.books.len();
        let pages = new_scan.pages_map.len();
        let duration_ms = new_scan.scan_duration.num_milliseconds();
        info!(books, pages, duration_ms, "initial scan finished");

        *state.scan.write() = Some(new_scan);
    });
}

fn init_route(opts: &Opts) -> (Router, Arc<AppState>) {
    let data_dir = &opts.data_dir;

    let secret = opts.secret.clone().unwrap_or_else(|| {
        warn!(
            "no --secret provided; generating a random one — every session will \
             be invalidated and every book/page URL will change on restart. \
             Generate a persistent secret with `openssl rand -hex 32` and set \
             COMICS_SECRET."
        );
        Secret::generate()
    });
    let key = secret.session_key();
    let seed = secret.id_seed();
    let state = Arc::new(AppState {
        auth_config: match (opts.auth_username.clone(), opts.auth_password_hash.clone()) {
            (Some(u), Some(p)) => AuthConfig::Some {
                username: u,
                password_hash: p,
            },
            _ => AuthConfig::None,
        },
        key,
        data_dir: data_dir.clone(),
        scan: Arc::new(RwLock::new(None)),
        seed,
        cache_dir: opts
            .cache_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("comics-thumbs")),
        thumb_sem: Arc::new(Semaphore::new(
            thread::available_parallelism().map_or(4, std::num::NonZero::get),
        )),
        // Fixed, not per-core: this bounds memory.
        verify_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
        cookie_secure: resolve_cookie_secure(opts.cookie_secure),
        login_limiter: Arc::new(RateLimiter::new(
            LOGIN_MAX_ATTEMPTS,
            LOGIN_GLOBAL_MAX_ATTEMPTS,
            LOGIN_WINDOW_SECS,
        )),
        sessions: Arc::new(SessionStore::new(DEFAULT_IDLE_TTL, DEFAULT_ABSOLUTE_TTL)),
        audit_salt: Arc::new(SessionAuditSalt::generate()),
        hsts_max_age: opts.hsts_max_age,
        trusted_proxies: opts.trusted_proxies.clone().unwrap_or_default(),
    });

    let router = Router::new()
        .route("/book/{id}", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/shuffle/{id}", post(shuffle_book_route))
        .route("/shuffle", post(shuffle_route))
        .route("/", get(index_route))
        .route("/data/{id}", get(show_page_route))
        .route("/thumb/{size}/{id}", get(show_thumb_route))
        // Authenticated HTML must not outlive logout in a cache.
        .route_layer(middleware::from_fn(no_store_html))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware_fn,
        ))
        // Public routes: declared after `route_layer`, so outside auth.
        .route("/login", get(login_route).post(login_submit_route))
        .route("/logout", post(logout_route))
        .route("/healthz", get(healthz_route))
        .route("/assets/app.css", get(|| async { (CSS_HEADERS, APP_CSS) }))
        .route("/assets/app.js", get(|| async { (JS_HEADERS, APP_JS) }))
        // Separate from app.js: loaded synchronously in <head>.
        .route("/assets/theme.js", get(|| async { (JS_HEADERS, THEME_JS) }))
        .route("/favicon.svg", get(|| async { (SVG_HEADERS, FAVICON_SVG) }))
        .route(
            "/favicon-32.png",
            get(|| async { (PNG_HEADERS, FAVICON_PNG) }),
        )
        .route(
            "/apple-touch-icon.png",
            get(|| async { (PNG_HEADERS, APPLE_TOUCH_ICON_PNG) }),
        )
        .layer(
            // DEBUG: per-request logs are noisy for an image-heavy app. Failures
            // still log at ERROR.
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        );

    // Stateless fetch-metadata CSRF check; the rules are `tower_http::csrf`'s.
    // Global so it also covers the public `/login` and `/logout` POSTs; inert
    // for GET/HEAD/OPTIONS.
    //
    // Escape hatch: browsers send `Sec-Fetch-Site` only to HTTPS or
    // `localhost`, so a plain-HTTP LAN host falls back to `Origin`, and an
    // opaque `Origin: null` rejects the login POST with no way back in.
    // `--disable-csrf-guard` drops the layer rather than using
    // `CsrfLayer::with_insecure_bypass`, whose predicate sees only method and
    // URI, so it could not be narrower than "every unsafe route" anyway. HTTPS
    // or a `localhost` tunnel is the better fix. The cookie's `SameSite=Strict`
    // is the real cross-site defence; this layer is defence in depth.
    let router = if opts.disable_csrf_guard {
        warn!(
            "CSRF origin guard disabled by --disable-csrf-guard; every \
             state-changing request is accepted whatever its origin. The \
             session cookie's SameSite=Strict is the only cross-site defence \
             left. Serving over HTTPS is the way to undo this."
        );
        router
    } else {
        router.layer(CsrfLayer::new())
    };

    let router = router
        // Outermost, so public routes and assets get the headers too.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers_layer,
        ))
        .with_state(state.clone());

    (router, state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// bcrypt hash prefixes, matched only to name the migration: the bare parse
/// error (`salt invalid: too short`) is unactionable.
const BCRYPT_PREFIXES: [&str; 4] = ["$2a$", "$2b$", "$2x$", "$2y$"];

/// Reject a `COMICS_AUTH_PASSWORD_HASH` the login route could not use.
///
/// Otherwise the server starts with auth enabled and refuses the correct
/// password exactly as it refuses a typo. Deliberately *not* run before the
/// `hash-password` subcommand, which is how the operator fixes a bad hash.
///
/// A parse is not enough: `PasswordHash::new` accepts a salt with no digest
/// (`$argon2id$v=19$m=19456$nope`), and `PasswordVerifier` then reports it as
/// `Error::PasswordInvalid`, same as a wrong password — hence the `parsed.hash`
/// check. The trial verification catches the rest: another algorithm's hash,
/// or parameters that do not reconstruct.
fn ensure_password_hash_is_usable(opts: &Opts) -> anyhow::Result<()> {
    let Some(hash) = opts.auth_password_hash.as_deref() else {
        return Ok(());
    };
    if BCRYPT_PREFIXES
        .iter()
        .any(|prefix| hash.starts_with(prefix))
    {
        bail!(
            "COMICS_AUTH_PASSWORD_HASH is a bcrypt hash, which comics no longer accepts — \
             it now hashes passwords with Argon2id. Your password itself is unchanged: \
             run `comics hash-password`, enter it again, and replace the value of \
             COMICS_AUTH_PASSWORD_HASH with the new hash."
        );
    }
    let parsed = PasswordHash::new(hash).map_err(|err| {
        anyhow!(
            "COMICS_AUTH_PASSWORD_HASH is not an Argon2 hash ({err}); \
             generate one with `comics hash-password`"
        )
    })?;
    if parsed.hash.is_none() {
        bail!(
            "COMICS_AUTH_PASSWORD_HASH carries no digest — it is a salt without a \
             hash after it, which can never match any password; \
             generate a complete one with `comics hash-password`"
        );
    }
    match Argon2::default().verify_password(b"", &parsed) {
        Ok(()) | Err(argon2::password_hash::Error::PasswordInvalid) => Ok(()),
        Err(err) => bail!(
            "COMICS_AUTH_PASSWORD_HASH cannot verify a password ({err}); \
             generate one with `comics hash-password`"
        ),
    }
}

async fn run_server(addr: SocketAddr, opts: &Opts) -> anyhow::Result<()> {
    ensure_password_hash_is_usable(opts)?;
    let (tx, rx) = oneshot::channel::<()>();
    let (app, state) = init_route(opts);
    if opts.auth_username.is_none() || opts.auth_password_hash.is_none() {
        warn!("no authorization enabled, server is publicly accessible");
    } else if !resolve_cookie_secure(opts.cookie_secure) {
        warn!(
            "session cookie is issued without the Secure attribute; \
             set --cookie-secure (COMICS_COOKIE_SECURE=true) when serving over HTTPS"
        );
    }
    if opts.hsts_max_age.is_some() && !resolve_cookie_secure(opts.cookie_secure) {
        warn!(
            "HSTS is enabled but the session cookie is not marked Secure; \
             set --cookie-secure (COMICS_COOKIE_SECURE=true) too"
        );
    }
    let version = VERSION;
    let listener = TcpListener::bind(&addr).await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    info!(addr = %local_addr, %version, "server started");
    spawn_initial_scan(state, tx);
    // Connect info supplies the TCP peer the login rate limiter keys on.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        tokio::select! {
            result = rx => {
                if result.is_ok() {
                    warn!("fatal error occurred, shutdown the server");
                } else {
                    // Sender dropped after a successful scan; wait for a real signal.
                    shutdown_signal().await;
                    info!("received shutdown signal");
                }
            }
            () = shutdown_signal() => {
                info!("received shutdown signal");
            }
        }
    })
    .await
    .expect("failed to start the server");
    Ok(())
}

/// Refuse an empty password, or one past [`comics::MAX_PASSWORD_BYTES`].
///
/// Mirrors the ceiling in `verify_credentials`, so a password that hashes here
/// always verifies there. Split out of [`hash_password`], which reads a tty.
fn ensure_password_fits(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        // Merely short passwords get `password_strength_warning` instead.
        bail!("Password is empty.");
    }
    let len = password.len();
    if len > MAX_PASSWORD_BYTES {
        bail!(
            "Password is {len} bytes, and comics accepts at most {MAX_PASSWORD_BYTES}. \
             Shorten it — note that non-ASCII characters cost several bytes each."
        );
    }
    Ok(())
}

/// A warning for a password shorter than [`comics::MIN_PASSWORD_CHARS`]:
/// advice, not enforcement. Returned rather than printed so it can be tested.
fn password_strength_warning(password: &str) -> Option<String> {
    let chars = password.chars().count();
    (chars < MIN_PASSWORD_CHARS).then(|| {
        format!(
            "password is {chars} characters; OWASP advises at least \
             {MIN_PASSWORD_CHARS} when no second factor is available, and comics \
             has none. The hash below is still valid — this is advice, not a refusal."
        )
    })
}

/// Hash with Argon2id at [`Argon2::default`]'s parameters (`m=19456, t=2,
/// p=1`, an OWASP-listed configuration). They are recorded in the PHC string,
/// so raising them later leaves existing hashes verifiable.
fn argon2_hash(password: &str) -> anyhow::Result<String> {
    ensure_password_fits(password)?;
    let hash: PasswordHash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|err| anyhow!("failed to hash the password: {err}"))?;
    Ok(hash.to_string())
}

/// Write the hash to `out` and any advice to `err`.
///
/// `$(comics hash-password)` captures stdout, so a warning there would be baked
/// into the configured hash. Not a `warn!`: tracing also writes to stdout.
fn emit_password_hash(
    password: &str,
    out: &mut impl io::Write,
    err: &mut impl io::Write,
) -> anyhow::Result<()> {
    let hashed = argon2_hash(password)?;
    if let Some(warning) = password_strength_warning(password) {
        writeln!(err, "warning: {warning}")?;
    }
    writeln!(out, "{hashed}")?;
    Ok(())
}

fn hash_password() -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirmation: ")?;
    if password != confirmation {
        bail!("Password mismatch");
    }
    emit_password_hash(&password, &mut io::stdout(), &mut io::stderr())
}

/// Used when `RUST_LOG` is unset or unparseable.
const DEFAULT_FILTER: &str = "error,comics=info";

fn init_tracing(format: LogFormat) {
    // `Targets`, not `EnvFilter`: same directive syntax without the regex
    // engine; span/field filtering is unused. Note a bare word is a target, so
    // a mistyped `RUST_LOG=nonsense` parses and silences the log.
    let filter: Targets = std::env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse().ok())
        .unwrap_or_else(|| DEFAULT_FILTER.parse().expect("the default filter parses"));
    let span_events =
        <Targets as Filter<Registry>>::max_level_hint(&filter).map_or(FmtSpan::CLOSE, |l| {
            if l >= tracing::Level::DEBUG {
                FmtSpan::CLOSE
            } else {
                FmtSpan::NONE
            }
        });
    // Per no-color.org, only a non-empty `NO_COLOR` disables colour.
    let use_ansi = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let layer = tracing_subscriber::fmt::layer()
        .with_span_events(span_events)
        .with_ansi(use_ansi)
        .log_internal_errors(true);
    let layer = match format {
        LogFormat::Full => layer.with_filter(filter).boxed(),
        LogFormat::Compact => layer.compact().with_filter(filter).boxed(),
        LogFormat::Pretty => layer.pretty().with_filter(filter).boxed(),
        LogFormat::Json => layer.json().with_filter(filter).boxed(),
    };
    tracing_subscriber::registry().with(layer).init();
}

/// Retired environment variables, paired with their replacement.
const LEGACY_ENV_VARS: [(&str, &str); 9] = [
    ("AUTH_USERNAME", "COMICS_AUTH_USERNAME"),
    ("AUTH_PASSWORD_HASH", "COMICS_AUTH_PASSWORD_HASH"),
    ("BIND", "COMICS_BIND"),
    ("DATA_DIR", "COMICS_DATA_DIR"),
    ("CACHE_DIR", "COMICS_CACHE_DIR"),
    ("LOG_FORMAT", "COMICS_LOG_FORMAT"),
    ("SEED", "COMICS_SECRET"),
    ("COMICS_SEED", "COMICS_SECRET"),
    ("COMICS_SESSION_KEY", "COMICS_SECRET"),
];

/// Fail fast when a retired variable is set: silently ignoring, say, a leftover
/// `COMICS_SESSION_KEY` would fall back to a random secret that looks like it
/// works.
fn ensure_no_legacy_env_vars() -> anyhow::Result<()> {
    let found: Vec<String> = LEGACY_ENV_VARS
        .iter()
        .filter(|(old, _)| std::env::var_os(old).is_some())
        .map(|(old, new)| format!("  {old} -> {new}"))
        .collect();
    if !found.is_empty() {
        bail!(
            "these environment variables no longer exist; \
             rename (or unset) them to continue:\n{}",
            found.join("\n")
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ensure_no_legacy_env_vars()?;

    let opts = Opts::parse();
    debug!("Parsed options: {opts:?}");

    init_tracing(opts.log_format);

    match &opts.command {
        Some(Commands::HashPassword { .. }) => hash_password()?,
        Some(Commands::List { .. }) => {
            let seed = 0u64; // dummy salt
            let scan = scan_books(seed, &opts.data_dir)?;
            let mut stdout = std::io::stdout().lock();
            // Ignore write errors (e.g. broken pipe into `head`).
            for book in &scan.books {
                let _ = writeln!(stdout, "{} ({}P)", book.title, book.pages.len());
            }
            let _ = writeln!(
                stdout,
                "{} book(s), {} page(s), scanned in {:?}",
                scan.books.len(),
                scan.pages_map.len(),
                scan.scan_duration
                    .to_std()
                    .expect("failed to convert duration")
            );
        }
        None => {
            let bind: SocketAddr = opts.bind.parse()?;
            run_server(bind, &opts).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        LOGIN_GLOBAL_MAX_ATTEMPTS, LOGIN_MAX_ATTEMPTS, Opts, argon2_hash, emit_password_hash,
        ensure_password_fits, ensure_password_hash_is_usable, init_route,
        password_strength_warning, resolve_cookie_secure, spawn_initial_scan,
    };
    use argon2::PasswordHash;
    use axum_test::TestServer;
    use clap::Parser as _;
    use comics::{MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, VERSION};
    use http::Method;
    use tokio::sync::oneshot;

    /// Fixed so the derived IDs, and so `DATA_IDS`, are stable.
    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Book IDs under `TEST_SECRET`. To recompute, run `comics --secret
    /// <TEST_SECRET> --data-dir fixtures/data` and read the `/book/…` hrefs.
    const DATA_IDS: [&str; 2] = [
        // Pepper and Carrot 01 - Potion of Flight
        "1f1c111677715adf",
        // Pepper and Carrot 02 - Rainbow Potions
        "b8799902927c8bf6",
    ];

    async fn build_server() -> TestServer {
        build_server_at("./fixtures/data").await
    }

    async fn build_server_at(data_dir: &str) -> TestServer {
        build_server_with(data_dir, &[]).await
    }

    async fn build_server_with(data_dir: &str, extra_args: &[&str]) -> TestServer {
        use std::{thread, time};

        let (tx, _) = oneshot::channel::<()>();
        let mut args = vec!["comics", "--data-dir", data_dir];
        args.extend_from_slice(extra_args);
        let mut opts = Opts::parse_from(args);
        opts.secret
            .get_or_insert_with(|| TEST_SECRET.parse().unwrap());
        let (router, state) = init_route(&opts);
        spawn_initial_scan(state, tx);

        let server =
            TestServer::new(router.into_make_service_with_connect_info::<std::net::SocketAddr>());
        for _ in 0..10 {
            let res = server.get("/healthz").await;
            if res.status_code() == 200 {
                break;
            }
            thread::sleep(time::Duration::from_millis(100));
        }
        server
    }

    #[tokio::test]
    async fn get_books() {
        let server = build_server().await;
        let res = server.get("/").await;
        assert_eq!(200, res.status_code());

        let t = res.text();
        assert!(t.contains("2 book(s)"));
        assert!(t.contains("Pepper and Carrot 01 - Potion of Flight"));
        assert!(t.contains("Pepper and Carrot 02 - Rainbow Potions"));
    }

    // Not a customized built-in (`<time is="…">`): WebKit lacks them. Opt-in
    // per element, so the duration `<time>` is left alone.
    #[tokio::test]
    async fn index_opts_timestamps_into_client_side_localisation() {
        let server = build_server().await;
        let t = server.get("/").await.text();

        assert!(!t.contains("is=\"x-time\""));
        assert_eq!(1, t.matches("data-localtime").count());
    }

    // Seconds need the `T` designator: `P0.003S` is invalid.
    #[tokio::test]
    async fn index_renders_the_scan_duration_as_a_valid_duration() {
        let server = build_server().await;
        let t = server.get("/").await.text();

        let marker = "<time datetime=\"";
        let start = t.find(marker).expect("a duration <time>") + marker.len();
        let end = start + t[start..].find('"').expect("a closing quote");
        let duration = &t[start..end];

        assert!(
            duration.starts_with("PT") && duration.ends_with('S'),
            "not a valid duration string: {duration}"
        );
    }

    #[tokio::test]
    async fn get_book() {
        let book_id = DATA_IDS.first().unwrap();
        let path = format!("/book/{book_id}");
        let server = build_server().await;
        let res = server.get(&path).await;
        assert_eq!(200, res.status_code());

        let t = res.text();
        assert!(t.contains("Pepper and Carrot 01 - Potion of Flight"));
    }

    #[tokio::test]
    async fn get_page() {
        let server = build_server().await;
        // Discovered rather than hard-coded, so fixture changes do not break it.
        let book_id = DATA_IDS.first().unwrap();
        let html = server.get(&format!("/book/{book_id}")).await.text();
        let marker = "/data/";
        let start = html.find(marker).expect("a page image") + marker.len();
        let page_id: String = html[start..].chars().take_while(|&c| c != '"').collect();
        assert!(!page_id.is_empty());

        let res = server.get(&format!("/data/{page_id}")).await;
        assert_eq!(200, res.status_code());
        let content = res.as_bytes();
        assert!(content.starts_with(b"\xFF\xD8\xFF")); // JPEG magic bytes
    }

    #[tokio::test]
    async fn page_missing_file_returns_404() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let book = dir.path().join("Temp Book");
        fs::create_dir(&book).unwrap();
        let page = book.join("01.jpg");
        fs::copy(
            "./fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg",
            &page,
        )
        .unwrap();

        let server = build_server_at(dir.path().to_str().unwrap()).await;

        let html = server.get("/").await.text();
        let marker = "/thumb/md/";
        let start = html.find(marker).expect("a cover link") + marker.len();
        let id: String = html[start..].chars().take_while(|&c| c != '"').collect();
        assert!(!id.is_empty());

        assert_eq!(200, server.get(&format!("/data/{id}")).await.status_code());
        fs::remove_file(&page).unwrap();
        assert_eq!(404, server.get(&format!("/data/{id}")).await.status_code());
    }

    #[tokio::test]
    async fn thumbnail_serves_jpeg() {
        let server = build_server().await;

        let html = server.get("/").await.text();
        let marker = "/thumb/md/";
        let start = html.find(marker).expect("a cover thumbnail") + marker.len();
        let id: String = html[start..].chars().take_while(|&c| c != '"').collect();

        for size in ["md", "sm"] {
            let res = server.get(&format!("/thumb/{size}/{id}")).await;
            assert_eq!(200, res.status_code(), "size {size}");
            assert!(
                res.as_bytes().starts_with(b"\xFF\xD8\xFF"),
                "JPEG magic for {size}"
            );
        }

        // Served from the disk cache.
        let cached = server.get(&format!("/thumb/md/{id}")).await;
        assert_eq!(200, cached.status_code());
        assert!(cached.as_bytes().starts_with(b"\xFF\xD8\xFF"));

        assert_eq!(
            404,
            server.get(&format!("/thumb/xl/{id}")).await.status_code()
        );
        assert_eq!(404, server.get("/thumb/md/deadbeef").await.status_code());
    }

    #[tokio::test]
    async fn thumbnail_falls_back_to_original_when_undecodable() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let book = dir.path().join("Bogus Book");
        fs::create_dir(&book).unwrap();
        let page = book.join("01.jpg");
        fs::write(&page, b"this is not an image").unwrap();

        let server = build_server_at(dir.path().to_str().unwrap()).await;
        let html = server.get("/").await.text();
        let marker = "/thumb/md/";
        let start = html.find(marker).expect("a cover link") + marker.len();
        let id: String = html[start..].chars().take_while(|&c| c != '"').collect();

        let res = server.get(&format!("/thumb/sm/{id}")).await;
        assert_eq!(200, res.status_code());
        assert_eq!(res.as_bytes(), &b"this is not an image"[..]);

        fs::remove_file(&page).unwrap();
        assert_eq!(
            404,
            server.get(&format!("/thumb/sm/{id}")).await.status_code()
        );
    }

    #[tokio::test]
    async fn shuffle() {
        let server = build_server().await;
        let res = server.post("/shuffle").await;
        assert_eq!(303, res.status_code());

        let splitted = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .split('/')
            .collect::<Vec<&str>>();
        assert!(DATA_IDS.contains(splitted.get(2).unwrap()));
    }

    #[tokio::test]
    async fn shuffle_from_a_book() {
        let book_id = DATA_IDS.first().unwrap();
        let path = format!("/shuffle/{book_id}");
        let server = build_server().await;
        let res = server.post(&path).await;
        assert_eq!(303, res.status_code());

        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/book/"));
        let redirected_id = location.strip_prefix("/book/").unwrap();
        assert_ne!(*book_id, redirected_id);
        assert!(DATA_IDS.contains(&redirected_id));
    }

    #[tokio::test]
    async fn rescan() {
        let server = build_server().await;
        let res = server.post("/rescan").await;
        assert_eq!(303, res.status_code());

        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!("/", location);
    }

    #[tokio::test]
    async fn healthz() {
        let server = build_server().await;
        let res = server.get("/healthz").await;
        assert_eq!(200, res.status_code());
    }

    /// Includes the public `/login` and `/logout`, outside the auth layer.
    #[tokio::test]
    async fn csrf_cross_site_post_is_forbidden() {
        let server = build_server().await;
        for path in ["/rescan", "/shuffle", "/login", "/logout"] {
            let res = server
                .post(path)
                .add_header("sec-fetch-site", "cross-site")
                .await;
            assert_eq!(403, res.status_code(), "POST {path} cross-site");
        }
    }

    #[tokio::test]
    async fn csrf_same_origin_post_is_allowed() {
        let server = build_server().await;

        let res = server
            .post("/shuffle")
            .add_header("sec-fetch-site", "same-origin")
            .await;
        assert_eq!(303, res.status_code());

        let res = server
            .post("/shuffle")
            .add_header("origin", "http://localhost")
            .add_header("host", "localhost")
            .await;
        assert_eq!(303, res.status_code());
    }

    /// The plain-HTTP LAN lockout `--disable-csrf-guard` exists for.
    #[tokio::test]
    async fn csrf_null_origin_post_is_forbidden_by_default() {
        let server = build_server().await;
        let res = server
            .post("/shuffle")
            .add_header("origin", "null")
            .add_header("host", "nas.local")
            .await;
        assert_eq!(403, res.status_code());
    }

    #[tokio::test]
    async fn csrf_guard_can_be_disabled() {
        let server = build_server_with("./fixtures/data", &["--disable-csrf-guard"]).await;

        let res = server
            .post("/shuffle")
            .add_header("origin", "null")
            .add_header("host", "nas.local")
            .await;
        assert_eq!(303, res.status_code());

        let res = server
            .post("/shuffle")
            .add_header("sec-fetch-site", "cross-site")
            .await;
        assert_eq!(303, res.status_code());
    }

    #[tokio::test]
    async fn csrf_safe_method_is_never_checked() {
        let server = build_server().await;
        let res = server
            .get("/")
            .add_header("sec-fetch-site", "cross-site")
            .await;
        assert_eq!(200, res.status_code());
    }

    /// A TLS-terminating proxy forwards a portless `Host` against an `https://`
    /// `Origin`; the authorities still match.
    #[tokio::test]
    async fn csrf_tls_terminating_proxy_origin_matches_forwarded_host() {
        let server = build_server().await;
        let res = server
            .post("/shuffle")
            .add_header("origin", "https://app.example.com")
            .add_header("host", "app.example.com")
            .await;
        assert_eq!(303, res.status_code());
    }

    /// comics is a single origin, so its own forms report `same-origin`.
    #[tokio::test]
    async fn csrf_same_site_post_is_forbidden() {
        let server = build_server().await;
        let res = server
            .post("/shuffle")
            .add_header("sec-fetch-site", "same-site")
            .await;
        assert_eq!(403, res.status_code());
    }

    /// Only reached without `Sec-Fetch-Site`, i.e. over plain HTTP, where the
    /// browser puts the same port in both headers.
    #[tokio::test]
    async fn csrf_origin_fallback_compares_the_port_too() {
        let server = build_server().await;

        let res = server
            .post("/shuffle")
            .add_header("origin", "http://nas.local:8080")
            .add_header("host", "nas.local:8080")
            .await;
        assert_eq!(303, res.status_code());

        let res = server
            .post("/shuffle")
            .add_header("origin", "http://nas.local:8080")
            .add_header("host", "nas.local")
            .await;
        assert_eq!(403, res.status_code());
    }

    /// A non-browser client carries no ambient cookie, so it is no CSRF vector.
    #[tokio::test]
    async fn csrf_client_sending_neither_header_is_allowed() {
        let server = build_server().await;
        let res = server.post("/shuffle").await;
        assert_eq!(303, res.status_code());
    }

    /// RFC 7231 calls `TRACE` safe, but only `GET`/`HEAD`/`OPTIONS` are exempt.
    #[tokio::test]
    async fn csrf_cross_site_trace_is_forbidden() {
        let server = build_server().await;
        let res = server
            .method(Method::TRACE, "/shuffle")
            .add_header("sec-fetch-site", "cross-site")
            .await;
        assert_eq!(403, res.status_code());
    }

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    fn opts_with_hash(hash: &str) -> Opts {
        Opts::parse_from([
            "comics",
            "--data-dir",
            "./fixtures/data",
            "--auth-username",
            "user",
            "--auth-password-hash",
            hash,
        ])
    }

    #[test]
    fn a_usable_password_hash_starts_the_server() {
        let hash = argon2_hash("password").unwrap();
        assert!(ensure_password_hash_is_usable(&opts_with_hash(&hash)).is_ok());

        let public = Opts::parse_from(["comics", "--data-dir", "./fixtures/data"]);
        assert!(ensure_password_hash_is_usable(&public).is_ok());
    }

    /// The empty string is what an unset shell variable produces.
    #[test]
    fn a_malformed_password_hash_stops_startup() {
        let cases = [
            "",
            "not-a-hash",
            "password",
            // Parses, but has no digest.
            "$argon2id$v=19$m=19456$nope",
            // Another algorithm's hash.
            "$pbkdf2-sha256$i=1000$c2FsdHNhbHQ$xEbJPmXjr2fBIf1RhJ1Kd0uGrjhOTOAgWnMYGVBLj4Y",
        ];
        for hash in cases {
            let err = ensure_password_hash_is_usable(&opts_with_hash(hash))
                .expect_err(&format!("{hash:?} was accepted"))
                .to_string();
            assert!(err.contains("hash-password"), "{err}");
        }
    }

    #[test]
    fn a_bcrypt_hash_names_the_migration() {
        let hashes = [
            "$2a$11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu",
            "$2b$11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu",
            "$2x$11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu",
            "$2y$11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu",
        ];
        for hash in hashes {
            let err = ensure_password_hash_is_usable(&opts_with_hash(hash))
                .expect_err("a bcrypt hash was accepted")
                .to_string();
            assert!(err.contains("bcrypt"), "{err}");
            assert!(err.contains("Argon2id"), "{err}");
            assert!(err.contains("hash-password"), "{err}");
            assert!(err.contains("password itself is unchanged"), "{err}");
        }
    }

    #[test]
    fn hash_password_accepts_a_password_at_the_limit() {
        assert!(ensure_password_fits(&"x".repeat(MAX_PASSWORD_BYTES)).is_ok());

        let cjk = "密".repeat(100);
        assert_eq!(300, cjk.len());
        assert!(ensure_password_fits(&cjk).is_ok());
        assert!(argon2_hash(&cjk).unwrap().starts_with("$argon2id$"));
    }

    /// `Argon2::default()` is upstream's; pin it so a crate upgrade cannot
    /// silently move the cost parameters.
    #[test]
    fn hash_password_records_the_owasp_parameters() {
        let hash = argon2_hash("a-password-long-enough").unwrap();
        let parsed = PasswordHash::new(&hash).unwrap();

        assert_eq!("argon2id", parsed.algorithm.as_str());
        assert_eq!(Some(argon2::Version::V0x13 as u32), parsed.version);
        for (name, want) in [("m", 19456), ("t", 2), ("p", 1)] {
            assert_eq!(Some(want), parsed.params.get_decimal(name), "{name} cost");
        }
        assert_eq!(16, parsed.salt.unwrap().len());
    }

    /// The message names the size: the passphrase was typed blind.
    #[test]
    fn hash_password_refuses_an_over_long_password() {
        let err = ensure_password_fits(&"x".repeat(MAX_PASSWORD_BYTES + 1))
            .expect_err("a password past the ceiling was accepted")
            .to_string();
        assert!(
            err.contains(&format!("{} bytes", MAX_PASSWORD_BYTES + 1)),
            "{err}"
        );

        assert!(argon2_hash(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn hash_password_refuses_an_empty_password() {
        assert!(ensure_password_fits("").is_err());
        assert!(argon2_hash("").is_err());
    }

    #[test]
    fn a_short_password_is_warned_about_but_still_hashed() {
        let short = "x".repeat(MIN_PASSWORD_CHARS - 1);
        let warning = password_strength_warning(&short).expect("a warning");
        assert!(
            warning.contains(&format!("{} characters", MIN_PASSWORD_CHARS - 1)),
            "{warning}"
        );
        assert!(
            warning.contains(&MIN_PASSWORD_CHARS.to_string()),
            "{warning}"
        );
        assert!(warning.contains("not a refusal"), "{warning}");
        assert!(argon2_hash(&short).unwrap().starts_with("$argon2id$"));
    }

    /// `$(comics hash-password)` captures stdout, so it must hold the hash alone.
    #[test]
    fn the_warning_never_reaches_stdout() {
        let short = "x".repeat(MIN_PASSWORD_CHARS - 1);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit_password_hash(&short, &mut out, &mut err).expect("hashing a short password");

        let out = String::from_utf8(out).expect("utf-8 stdout");
        let err = String::from_utf8(err).expect("utf-8 stderr");

        assert_eq!(
            1,
            out.lines().count(),
            "stdout carried more than the hash: {out}"
        );
        assert!(out.starts_with("$argon2id$"), "{out}");
        assert!(
            !out.contains("warning"),
            "the warning reached stdout: {out}"
        );
        assert!(PasswordHash::new(out.trim()).is_ok(), "{out}");

        assert!(err.contains("warning:"), "{err}");
    }

    #[test]
    fn a_long_enough_password_emits_only_the_hash() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit_password_hash(&"x".repeat(MIN_PASSWORD_CHARS), &mut out, &mut err)
            .expect("hashing an adequate password");

        assert!(String::from_utf8(out).unwrap().starts_with("$argon2id$"));
        assert!(err.is_empty(), "{:?}", String::from_utf8(err));
    }

    #[test]
    fn a_refused_password_writes_nothing() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(emit_password_hash("", &mut out, &mut err).is_err());
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn a_long_enough_password_draws_no_warning() {
        assert!(password_strength_warning(&"x".repeat(MIN_PASSWORD_CHARS)).is_none());
        assert!(password_strength_warning(&"x".repeat(MIN_PASSWORD_CHARS + 40)).is_none());
    }

    #[test]
    fn the_strength_floor_counts_characters_not_bytes() {
        let fifteen = "密".repeat(MIN_PASSWORD_CHARS);
        assert_eq!(45, fifteen.len());
        assert!(password_strength_warning(&fifteen).is_none());

        let five = "密".repeat(5);
        assert_eq!(15, five.len(), "fifteen bytes, and far too short");
        assert!(password_strength_warning(&five).is_some());
    }

    const SESSION_COOKIE: &str = "comics_session";

    /// A server with credentials `user`/`password`; `save_cookies` makes the
    /// client keep cookies like a browser.
    async fn build_auth_server(save_cookies: bool) -> TestServer {
        build_auth_server_with(save_cookies, &[]).await
    }

    /// Like [`build_auth_server`], with `extra_args` appended to the CLI.
    async fn build_auth_server_with(save_cookies: bool, extra_args: &[&str]) -> TestServer {
        use std::{thread, time};

        let (tx, _) = oneshot::channel::<()>();
        let hash = argon2_hash("password").unwrap();
        let mut args = vec![
            "comics",
            "--data-dir",
            "./fixtures/data",
            "--auth-username",
            "user",
            "--auth-password-hash",
            &hash,
        ];
        args.extend_from_slice(extra_args);
        let mut opts = Opts::parse_from(args);
        opts.secret
            .get_or_insert_with(|| TEST_SECRET.parse().unwrap());
        let (router, state) = init_route(&opts);
        spawn_initial_scan(state, tx);

        let mut server =
            TestServer::new(router.into_make_service_with_connect_info::<std::net::SocketAddr>());
        if save_cookies {
            server.save_cookies();
        }
        for _ in 0..10 {
            let res = server.get("/healthz").await;
            if res.status_code() == 200 {
                break;
            }
            thread::sleep(time::Duration::from_millis(100));
        }
        server
    }

    #[tokio::test]
    async fn auth_unauthenticated_get_redirects_to_login() {
        let server = build_auth_server(false).await;
        let res = server.get("/").await;
        assert_eq!(303, res.status_code());
        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login"));
        assert!(location.contains("next="));
    }

    #[tokio::test]
    async fn auth_unauthenticated_post_is_unauthorized() {
        let server = build_auth_server(false).await;
        let res = server.post("/rescan").await;
        assert_eq!(401, res.status_code());
    }

    #[tokio::test]
    async fn auth_login_page_is_public() {
        let server = build_auth_server(false).await;
        let res = server.get("/login").await;
        assert_eq!(200, res.status_code());
        assert!(res.text().contains("action=\"/login\""));
    }

    #[tokio::test]
    async fn auth_login_success_sets_cookie_and_grants_access() {
        let server = build_auth_server(true).await;
        let res = server
            .post("/login")
            .form(&[
                ("username", "user"),
                ("password", "password"),
                ("next", "/"),
            ])
            .await;
        assert_eq!(303, res.status_code());
        assert_eq!(
            "/",
            res.headers().get("location").unwrap().to_str().unwrap()
        );
        assert!(res.maybe_cookie(SESSION_COOKIE).is_some());

        let res = server.get("/").await;
        assert_eq!(200, res.status_code());
        assert!(res.text().contains("2 book(s)"));
    }

    /// Raw `Set-Cookie` values: `maybe_cookie` drops the attributes.
    fn set_cookie_headers(res: &axum_test::TestResponse) -> Vec<String> {
        res.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    async fn login_response(server: &TestServer) -> axum_test::TestResponse {
        server
            .post("/login")
            .form(&[("username", "user"), ("password", "password")])
            .await
    }

    #[test]
    fn cookie_secure_defaults_to_off() {
        assert!(!resolve_cookie_secure(None));
        assert!(!resolve_cookie_secure(Some(false)));
    }

    #[test]
    fn cookie_secure_override_wins() {
        assert!(resolve_cookie_secure(Some(true)));
    }

    #[tokio::test]
    async fn auth_login_cookie_has_secure_when_enabled() {
        let server = build_auth_server_with(true, &["--cookie-secure"]).await;
        let res = login_response(&server).await;
        let headers = set_cookie_headers(&res);
        assert!(
            headers.iter().any(|h| h.contains("Secure")),
            "expected a Secure attribute in {headers:?}"
        );
    }

    /// A browser drops a `Secure` cookie over plain HTTP.
    #[tokio::test]
    async fn auth_login_cookie_has_no_secure_by_default() {
        let server = build_auth_server(true).await;
        let res = login_response(&server).await;
        let headers = set_cookie_headers(&res);
        assert!(!headers.is_empty());
        assert!(
            !headers.iter().any(|h| h.contains("Secure")),
            "unexpected Secure attribute in {headers:?}"
        );
    }

    #[tokio::test]
    async fn auth_login_wrong_password_is_unauthorized() {
        let server = build_auth_server(false).await;
        let res = server
            .post("/login")
            .form(&[("username", "user"), ("password", "nope")])
            .await;
        assert_eq!(401, res.status_code());
        assert!(res.maybe_cookie(SESSION_COOKIE).is_none());
        assert!(res.text().contains("帳號或密碼錯誤"));
    }

    #[tokio::test]
    async fn auth_login_sets_host_prefixed_cookie_when_secure() {
        let server = build_auth_server_with(true, &["--cookie-secure"]).await;
        let res = login_response(&server).await;
        let headers = set_cookie_headers(&res);
        let session = headers
            .iter()
            .find(|h| h.starts_with("__Host-comics_session="))
            .unwrap_or_else(|| panic!("no __Host- cookie in {headers:?}"));
        assert!(session.contains("Secure"), "{session}");
        assert!(session.contains("Path=/"), "{session}");
        assert!(!session.contains("Domain="), "{session}");
    }

    #[tokio::test]
    async fn hsts_absent_by_default() {
        let server = build_server().await;
        let res = server.get("/healthz").await;
        assert!(!res.headers().contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn hsts_present_when_configured() {
        let server = build_auth_server_with(false, &["--hsts-max-age", "63072000"]).await;
        for path in ["/healthz", "/login", "/assets/app.css"] {
            let res = server.get(path).await;
            assert_eq!(
                "max-age=63072000",
                res.headers()["strict-transport-security"],
                "GET {path}"
            );
        }
    }

    #[tokio::test]
    async fn security_headers_present_on_every_response() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        for path in [
            "/".to_string(),
            format!("/book/{book}"),
            "/healthz".to_string(),
            "/assets/app.css".to_string(),
            "/assets/theme.js".to_string(),
            "/favicon.svg".to_string(),
        ] {
            let res = server.get(&path).await;
            assert_eq!(200, res.status_code(), "GET {path}");
            assert_security_headers(res.headers(), &path);
        }

        // Including the anonymous redirect, issued before any handler.
        let server = build_auth_server(false).await;
        let res = server.get("/login").await;
        assert_eq!(200, res.status_code());
        assert_security_headers(res.headers(), "/login");
        let res = server.get("/").await;
        assert_eq!(303, res.status_code());
        assert_security_headers(res.headers(), "/ (anonymous redirect)");
    }

    fn assert_security_headers(headers: &http::HeaderMap, what: &str) {
        for name in [
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "cross-origin-resource-policy",
            "cross-origin-opener-policy",
            "permissions-policy",
        ] {
            assert!(headers.contains_key(name), "{what} is missing {name}");
        }
        assert_eq!("nosniff", headers["x-content-type-options"], "{what}");
        assert_eq!("DENY", headers["x-frame-options"], "{what}");
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(!csp.contains("unsafe-inline"), "{what} -> {csp}");
    }

    /// The CSP forbids inline scripts, so the browser would drop them.
    #[tokio::test]
    async fn rendered_pages_carry_no_inline_scripts() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let pages = [
            server.get("/").await.text(),
            server.get(&format!("/book/{book}")).await.text(),
            // `/login` only renders when auth is on.
            build_auth_server(false).await.get("/login").await.text(),
        ];

        for html in pages {
            assert!(html.contains("<script"), "no script rendered");
            for tag in html.split("<script").skip(1) {
                let open = &tag[..tag.find('>').expect("an unclosed <script")];
                assert!(open.contains("src="), "inline script: <script{open}>");
            }
            assert!(!html.contains("onclick="));
        }
    }

    /// `.pg` is hidden until `is-current` lands on it; without app.js the
    /// server has to set it on the first page.
    #[tokio::test]
    async fn the_first_page_is_visible_without_javascript() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let html = server.get(&format!("/book/{book}")).await.text();

        let figures: Vec<&str> = html
            .split("<figure")
            .skip(1)
            .map(|tag| &tag[..tag.find('>').expect("an unclosed <figure")])
            .collect();

        assert!(figures.len() > 1, "the fixture book needs several pages");
        assert!(figures[0].contains("is-current"), "{}", figures[0]);
        for tag in &figures[1..] {
            assert!(!tag.contains("is-current"), "{tag}");
        }
    }

    /// Without a script, `:target` picks the page, so each carries links to its
    /// neighbours, and none past either end.
    #[tokio::test]
    async fn anchor_paging_links_every_page_to_its_neighbours() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let html = server.get(&format!("/book/{book}")).await.text();

        let figures: Vec<&str> = html
            .split("<figure")
            .skip(1)
            .map(|f| f.split("</figure>").next().expect("an unclosed <figure>"))
            .collect();
        let total = figures.len();
        assert!(total > 2, "the fixture book needs several pages");

        for (i, fragment) in figures.iter().enumerate() {
            let n = i + 1;
            assert!(fragment.contains(&format!("id=\"p{n}\"")), "{fragment}");

            if n < total {
                let next = format!("href=\"#p{}\"", n + 1);
                assert!(fragment.contains(&next), "page {n} has no next: {fragment}");
            } else {
                assert!(!fragment.contains("rel=\"next\""), "last page: {fragment}");
            }

            if n > 1 {
                let prev = format!("href=\"#p{}\"", n - 1);
                assert!(fragment.contains(&prev), "page {n} has no prev: {fragment}");
            } else {
                assert!(!fragment.contains("rel=\"prev\""), "first page: {fragment}");
            }
        }
    }

    /// The topbar switch would lose the page without a script, so each page
    /// carries its own.
    #[tokio::test]
    async fn switching_mode_without_javascript_keeps_the_page() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        for (query, target) in [("?mode=paged", "scroll"), ("?mode=scroll", "paged")] {
            let html = server.get(&format!("/book/{book}{query}")).await.text();

            let pages: Vec<&str> = html
                .split("<figure")
                .skip(1)
                .map(|f| f.split("</figure>").next().expect("an unclosed <figure>"))
                .collect();
            assert!(pages.len() > 2, "the fixture book needs several pages");

            for (i, page) in pages.iter().enumerate() {
                let n = i + 1;
                let link = format!("href=\"?mode={target}#p{n}\"");
                assert!(page.contains(&link), "page {n} in {query}: {page}");
            }
        }
    }

    /// Checked on every template with a theme toggle, not just the reader.
    #[tokio::test]
    async fn script_only_controls_are_hidden_without_javascript() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let pages = [
            ("/", server.get("/").await.text()),
            ("/book", server.get(&format!("/book/{book}")).await.text()),
            (
                "/login",
                build_auth_server(false).await.get("/login").await.text(),
            ),
        ];

        for (what, html) in pages {
            let toggle = html
                .split("id=\"theme\"")
                .next()
                .and_then(|before| before.rfind('<').map(|at| &before[at..]))
                .expect("the theme toggle");
            assert!(toggle.contains("js-only"), "{what}: {toggle}");
        }

        // The topbar keeps its total; only the live page number is hidden.
        let reader = server.get(&format!("/book/{book}")).await.text();
        let titleblock = reader
            .split("class=\"s\"")
            .nth(1)
            .expect("the topbar counter")
            .split("</div>")
            .next()
            .expect("an unclosed counter");
        let live = titleblock
            .split("<span")
            .nth(1)
            .expect("the script-driven half");
        assert!(live.contains("js-only"), "{titleblock}");
        assert!(live.contains("id=\"cur\""), "{titleblock}");
        assert!(titleblock.contains("ページ"), "the total went missing");

        assert!(comics::assets::APP_CSS.contains("html:not(.js) .js-only"));
    }

    /// An unrecognised mode renders the default rather than a 400.
    #[tokio::test]
    async fn the_reader_mode_is_server_rendered() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        for (query, expected) in [
            ("", "paged"),
            ("?mode=paged", "paged"),
            ("?mode=scroll", "scroll"),
            ("?mode=nonsense", "paged"),
        ] {
            let res = server.get(&format!("/book/{book}{query}")).await;
            assert_eq!(200, res.status_code(), "GET /book/…{query}");

            let html = res.text();
            let attribute = format!("data-mode=\"{expected}\"");
            assert!(
                html.contains(&attribute),
                "{query} did not render {expected}"
            );

            let control = html
                .split("class=\"seg\"")
                .nth(1)
                .expect("the segmented control")
                .split("</div>")
                .next()
                .expect("an unclosed control");
            assert!(!control.contains("<button"), "an inert button: {control}");

            let selected = control
                .split("<a ")
                .skip(1)
                .find(|half| half.contains("class=\"on\""))
                .unwrap_or_else(|| panic!("nothing selected for {query}"));
            let marker = format!("data-m=\"{expected}\"");
            assert!(selected.contains(&marker), "{query}: {selected}");
        }
    }

    /// Each thumbnail anchors to its page, and each page states its own number,
    /// since the rail's counter is script-written.
    #[tokio::test]
    async fn the_rail_works_without_javascript() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let html = server.get(&format!("/book/{book}")).await.text();
        let total = html.split("<figure").skip(1).count();
        assert!(total > 2, "the fixture book needs several pages");

        let rail = html
            .split("class=\"thumbs\"")
            .nth(1)
            .expect("the thumbnail rail")
            .split("</div>")
            .next()
            .expect("an unclosed rail");

        for n in 1..=total {
            let href = format!("href=\"#p{n}\"");
            assert!(rail.contains(&href), "no thumbnail for page {n}: {rail}");
        }
        assert!(!rail.contains("<button"), "an inert button: {rail}");

        for (i, fragment) in html.split("<figure").skip(1).enumerate() {
            let page = fragment.split("</figure>").next().expect("an unclosed one");
            let counter = format!("{} / {total}", i + 1);
            assert!(page.contains(&counter), "page {} lacks its number", i + 1);
        }
    }

    /// Without theme.js there is no `data-theme`; the media-query copy of the
    /// dark palette must match the attribute one.
    #[test]
    fn dark_theme_has_a_no_js_fallback() {
        /// The declarations between the braces that follow `selector`.
        fn block<'a>(css: &'a str, selector: &str) -> &'a str {
            let at = css
                .find(selector)
                .unwrap_or_else(|| panic!("no `{selector}` block"));
            let open = at + css[at..].find('{').expect("an unopened block");
            let close = open + css[open..].find('}').expect("an unclosed block");
            &css[open + 1..close]
        }

        /// The `--custom-property: value` pairs, sorted so order cannot matter.
        fn tokens(block: &str) -> Vec<(&str, &str)> {
            let mut out: Vec<(&str, &str)> = block
                .lines()
                .filter_map(|line| line.trim().strip_suffix(';'))
                .filter_map(|decl| decl.split_once(':'))
                .map(|(name, value)| (name.trim(), value.trim()))
                .filter(|(name, _)| name.starts_with("--"))
                .collect();
            out.sort_unstable();
            out
        }

        let css = comics::assets::APP_CSS;
        let explicit = tokens(block(css, "html[data-theme=\"dark\"] {"));
        let system = tokens(block(css, "html:not([data-theme]) {"));

        assert!(!explicit.is_empty(), "the dark palette went missing");
        assert_eq!(explicit, system, "the dark palettes have drifted");
    }

    /// Without the `js` class before first paint, `:target` fights app.js.
    #[tokio::test]
    async fn the_scripted_path_is_marked_before_first_paint() {
        let server = build_server().await;

        let js = server.get("/assets/theme.js").await.text();
        assert!(js.contains("classList.add(\"js\")"), "{js}");
        assert!(comics::assets::APP_CSS.contains("html:not(.js)"));
    }

    /// It must run before the first paint.
    #[tokio::test]
    async fn theme_script_is_served_and_not_deferred() {
        let server = build_server().await;

        let res = server.get("/assets/theme.js").await;
        assert_eq!(200, res.status_code());
        assert_eq!("text/javascript", res.headers()["content-type"]);
        assert_eq!(
            "public, max-age=31536000, immutable",
            res.headers()["cache-control"]
        );
        assert!(res.text().contains("data-theme"));

        let html = server.get("/").await.text();
        let marker = "/assets/theme.js";
        let at = html.find(marker).expect("the theme script");
        let tag_start = html[..at].rfind("<script").expect("a <script> tag");
        let tag = &html[tag_start..at + html[at..].find('>').expect("an unclosed tag")];
        assert!(!tag.contains("defer"), "{tag}");
        assert!(!tag.contains("async"), "{tag}");
    }

    #[tokio::test]
    async fn authenticated_html_is_not_cacheable() {
        let server = build_auth_server(true).await;
        login_response(&server).await;
        let book = DATA_IDS[0];

        for path in ["/".to_string(), format!("/book/{book}")] {
            let res = server.get(&path).await;
            assert_eq!(200, res.status_code(), "GET {path}");
            assert_eq!("no-store", res.headers()["cache-control"], "GET {path}");
            assert_eq!("no-cache", res.headers()["pragma"], "GET {path}");
        }
    }

    #[tokio::test]
    async fn login_page_is_not_cacheable() {
        let server = build_auth_server(false).await;
        let res = server.get("/login").await;
        assert_eq!(200, res.status_code());
        assert_eq!("no-store", res.headers()["cache-control"]);
    }

    /// Browser-cacheable, but never by a shared cache.
    #[tokio::test]
    async fn page_and_thumb_images_are_privately_cacheable() {
        let server = build_auth_server(true).await;
        login_response(&server).await;

        let html = server.get("/").await.text();
        let marker = "/thumb/md/";
        let start = html.find(marker).expect("a cover thumbnail") + marker.len();
        let id: String = html[start..].chars().take_while(|&c| c != '"').collect();

        for path in [format!("/data/{id}"), format!("/thumb/md/{id}")] {
            let res = server.get(&path).await;
            assert_eq!(200, res.status_code(), "GET {path}");
            let cache_control = res.headers()["cache-control"].to_str().unwrap().to_string();
            assert!(
                cache_control.starts_with("private"),
                "GET {path} -> {cache_control}"
            );
            assert!(
                cache_control.contains("max-age="),
                "GET {path} -> {cache_control}"
            );
        }
    }

    #[tokio::test]
    async fn static_assets_stay_publicly_cacheable() {
        let server = build_auth_server(false).await;
        let res = server.get("/assets/app.css").await;
        assert_eq!(200, res.status_code());
        assert_eq!(
            "public, max-age=31536000, immutable",
            res.headers()["cache-control"]
        );
    }

    /// Deliberate: a server-side store is what makes logout enforceable.
    #[tokio::test]
    async fn sessions_do_not_survive_a_router_rebuild() {
        const SECRET: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\
                              fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let first = build_auth_server_with(true, &["--secret", SECRET]).await;
        let res = login_response(&first).await;
        assert_eq!(303, res.status_code());
        let cookie = res.maybe_cookie(SESSION_COOKIE).expect("a session cookie");

        let second = build_auth_server_with(false, &["--secret", SECRET]).await;
        let res = second.get("/").add_cookie(cookie).await;
        assert_eq!(303, res.status_code(), "a stale session was accepted");
        assert!(
            res.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/login")
        );
    }

    #[tokio::test]
    async fn secret_keeps_urls_stable_across_router_rebuild() {
        const SECRET: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\
                              fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let first = build_auth_server_with(true, &["--secret", SECRET]).await;
        login_response(&first).await;
        let first_page = first.get("/").await.text();

        let second = build_auth_server_with(true, &["--secret", SECRET]).await;
        login_response(&second).await;
        let second_page = second.get("/").await.text();

        // Not TEST_SECRET/DATA_IDS: the flag must be what makes them agree.
        let ids = |page: &str| -> Vec<String> {
            page.match_indices("/book/")
                .map(|(at, marker)| {
                    let rest = &page[at + marker.len()..];
                    rest[..rest.find('"').expect("a closing quote")].to_string()
                })
                .collect()
        };
        let before = ids(&first_page);
        assert_eq!(2, before.len(), "expected the two fixture books");
        assert_eq!(before, ids(&second_page));
    }

    #[tokio::test]
    async fn session_cookie_value_is_a_bare_identifier() {
        let server = build_auth_server(true).await;
        let res = login_response(&server).await;
        let cookie = res.maybe_cookie(SESSION_COOKIE).expect("a session cookie");

        // The signed value is `<signature><id>`.
        let value = cookie.value();
        assert!(
            !value.contains('.'),
            "value still carries a separator: {value}"
        );
        let id = &value[value.len() - 32..];
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
        assert!(value.len() > 32, "{value}");
    }

    #[tokio::test]
    async fn auth_successful_logins_do_not_count_against_the_limit() {
        let server = build_auth_server(false).await;
        for attempt in 1..=(LOGIN_MAX_ATTEMPTS + 3) {
            let res = login_response(&server).await;
            assert_eq!(303, res.status_code(), "attempt {attempt}");
        }
    }

    /// The throttle runs before the credential check, so even the correct
    /// password gets a 429.
    #[tokio::test]
    async fn auth_login_is_rate_limited_after_five_attempts() {
        let server = build_auth_server(false).await;
        for attempt in 1..=LOGIN_MAX_ATTEMPTS {
            let res = server
                .post("/login")
                .form(&[("username", "user"), ("password", "nope")])
                .await;
            assert_eq!(401, res.status_code(), "attempt {attempt}");
        }

        let res = server
            .post("/login")
            .form(&[("username", "user"), ("password", "nope")])
            .await;
        assert_eq!(429, res.status_code());

        let res = server
            .post("/login")
            .form(&[("username", "user"), ("password", "password")])
            .await;
        assert_eq!(429, res.status_code());
        assert!(res.maybe_cookie(SESSION_COOKIE).is_none());
    }

    /// Fail one login as the client `X-Forwarded-For` names.
    async fn failed_login_from(server: &TestServer, forwarded_for: &str) -> http::StatusCode {
        server
            .post("/login")
            .add_header("x-forwarded-for", forwarded_for)
            .form(&[("username", "user"), ("password", "nope")])
            .await
            .status_code()
    }

    /// Guards the `Opts` → `AppState` → handler wiring no unit test sees.
    #[tokio::test]
    async fn auth_trusted_proxy_gives_each_forwarded_client_its_own_budget() {
        let server = build_auth_server_with(false, &["--trusted-proxies", "127.0.0.1"]).await;
        for attempt in 1..=LOGIN_MAX_ATTEMPTS {
            let status = failed_login_from(&server, "203.0.113.1").await;
            assert_eq!(401, status, "attempt {attempt}");
        }
        assert_eq!(429, failed_login_from(&server, "203.0.113.1").await);

        assert_eq!(401, failed_login_from(&server, "203.0.113.2").await);
    }

    #[tokio::test]
    async fn auth_untrusted_forwarded_clients_share_one_budget() {
        let server = build_auth_server(false).await;
        for attempt in 1..=LOGIN_MAX_ATTEMPTS {
            let status = failed_login_from(&server, &format!("203.0.113.{attempt}")).await;
            assert_eq!(401, status, "attempt {attempt}");
        }
        assert_eq!(429, failed_login_from(&server, "203.0.113.99").await);
    }

    /// Four addresses spend their budgets; a fifth, fresh one is still refused.
    /// Slow by necessity: each attempt runs a real Argon2 verification.
    #[tokio::test]
    async fn auth_login_is_throttled_across_all_client_addresses() {
        let server = build_auth_server_with(false, &["--trusted-proxies", "127.0.0.1"]).await;
        for client in 1..=(LOGIN_GLOBAL_MAX_ATTEMPTS / LOGIN_MAX_ATTEMPTS) {
            for attempt in 1..=LOGIN_MAX_ATTEMPTS {
                let status = failed_login_from(&server, &format!("203.0.113.{client}")).await;
                assert_eq!(401, status, "client {client}, attempt {attempt}");
            }
        }
        assert_eq!(
            429,
            failed_login_from(&server, "203.0.113.99").await,
            "a fresh address got through after the global budget was spent"
        );
    }

    #[tokio::test]
    async fn auth_login_redirects_safely() {
        let server = build_auth_server(true).await;
        let res = server
            .post("/login")
            .form(&[
                ("username", "user"),
                ("password", "password"),
                ("next", "https://evil.example"),
            ])
            .await;
        assert_eq!(303, res.status_code());
        assert_eq!(
            "/",
            res.headers().get("location").unwrap().to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn session_cookie_is_same_site_strict() {
        let server = build_auth_server(false).await;
        let res = login_response(&server).await;
        let issued = set_cookie_headers(&res)
            .into_iter()
            .find(|h| h.starts_with(&format!("{SESSION_COOKIE}=")))
            .expect("a session cookie");
        assert!(issued.contains("SameSite=Strict"), "{issued}");
    }

    /// `no_store_html` does not reach these: they are public, and redirects.
    #[tokio::test]
    async fn responses_carrying_a_session_cookie_are_not_cacheable() {
        let server = build_auth_server(false).await;

        let res = login_response(&server).await;
        assert_eq!(303, res.status_code());
        assert_eq!("no-store", res.headers()["cache-control"]);
        assert_eq!("no-cache", res.headers()["pragma"]);

        let cookie = res.maybe_cookie(SESSION_COOKIE).expect("a session cookie");
        let res = server.post("/logout").add_cookie(cookie).await;
        assert_eq!(303, res.status_code());
        assert_eq!("no-store", res.headers()["cache-control"]);
        assert_eq!("no-cache", res.headers()["pragma"]);
    }

    /// A browser resolves `/\evil.example` to `//evil.example`.
    #[tokio::test]
    async fn auth_login_rejects_backslash_redirect_targets() {
        let server = build_auth_server(false).await;
        let res = server
            .post("/login")
            .form(&[
                ("username", "user"),
                ("password", "password"),
                ("next", r"/\evil.example"),
            ])
            .await;
        assert_eq!(303, res.status_code());
        assert_eq!("/", res.headers()["location"]);
    }

    /// `Redirect::to` panics on a value `HeaderValue` refuses, and `next`
    /// arrives percent-decoded; this must answer, not drop the connection.
    #[tokio::test]
    async fn login_survives_a_control_character_in_next() {
        let server = build_server().await;
        let res = server.get("/login?next=%2F%0Ax").await;
        assert_eq!(303, res.status_code());
        assert_eq!("/", res.headers()["location"]);
    }

    /// Replayed by hand, not via the jar (which honours the removal cookie): a
    /// copied cookie must die with the server-side session.
    #[tokio::test]
    async fn auth_logout_invalidates_the_session_server_side() {
        let server = build_auth_server(false).await;
        let res = login_response(&server).await;
        assert_eq!(303, res.status_code());
        let cookie = res.maybe_cookie(SESSION_COOKIE).expect("a session cookie");

        assert_eq!(
            200,
            server
                .get("/")
                .add_cookie(cookie.clone())
                .await
                .status_code(),
            "the fresh session should work"
        );

        let res = server.post("/logout").add_cookie(cookie.clone()).await;
        assert_eq!(303, res.status_code());

        let res = server.get("/").add_cookie(cookie).await;
        assert_eq!(
            303,
            res.status_code(),
            "a destroyed session was still accepted"
        );
        assert!(
            res.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/login")
        );
    }

    /// Logout ends *every* session, so signing out anywhere kills a stolen cookie.
    #[tokio::test]
    async fn auth_logout_ends_sessions_on_other_devices() {
        let server = build_auth_server(false).await;
        let phone = login_response(&server)
            .await
            .maybe_cookie(SESSION_COOKIE)
            .expect("a session cookie");
        let desktop = login_response(&server)
            .await
            .maybe_cookie(SESSION_COOKIE)
            .expect("a second session cookie");
        assert_ne!(
            phone.value(),
            desktop.value(),
            "the two logins should be distinct sessions"
        );

        assert_eq!(
            303,
            server.post("/logout").add_cookie(phone).await.status_code()
        );

        assert_eq!(
            303,
            server.get("/").add_cookie(desktop).await.status_code(),
            "the other device's session outlived the logout"
        );
    }

    /// `/logout` is public and the CSRF guard passes header-less clients, so
    /// store membership must be what authorises the clear.
    #[tokio::test]
    async fn auth_anonymous_logout_ends_nothing() {
        let server = build_auth_server(false).await;
        let cookie = login_response(&server)
            .await
            .maybe_cookie(SESSION_COOKIE)
            .expect("a session cookie");

        assert_eq!(303, server.post("/logout").await.status_code());

        assert_eq!(
            200,
            server.get("/").add_cookie(cookie).await.status_code(),
            "an anonymous logout ended a live session"
        );
    }

    #[tokio::test]
    async fn auth_logout_clears_session() {
        let server = build_auth_server(true).await;
        server
            .post("/login")
            .form(&[("username", "user"), ("password", "password")])
            .await;
        assert_eq!(200, server.get("/").await.status_code());

        let res = server.post("/logout").await;
        assert_eq!(303, res.status_code());
        assert_eq!(
            "/login",
            res.headers().get("location").unwrap().to_str().unwrap()
        );

        assert_eq!(
            "\"cache\", \"cookies\", \"storage\"",
            res.headers()["clear-site-data"]
        );
        // Must mirror the issued cookie, or the browser treats it as another.
        let removal = set_cookie_headers(&res)
            .into_iter()
            .find(|h| h.starts_with(&format!("{SESSION_COOKIE}=")))
            .expect("a removal cookie");
        assert!(removal.contains("HttpOnly"), "{removal}");
        assert!(removal.contains("SameSite=Strict"), "{removal}");
        assert!(removal.contains("Path=/"), "{removal}");

        assert_eq!(303, server.get("/").await.status_code());
    }

    #[tokio::test]
    async fn auth_public_routes_need_no_login() {
        let server = build_auth_server(false).await;
        assert_eq!(200, server.get("/healthz").await.status_code());
        assert_eq!(200, server.get("/assets/app.css").await.status_code());
    }

    /// Guards against a route slipping out from under the middleware, e.g. by
    /// being declared after `route_layer`.
    #[tokio::test]
    async fn auth_every_protected_route_rejects_anonymous() {
        let server = build_auth_server(false).await;
        let book = DATA_IDS[0];

        for path in [
            "/".to_string(),
            format!("/book/{book}"),
            // A bogus id still redirects: auth runs before the handler.
            format!("/data/{book}"),
            format!("/thumb/md/{book}"),
        ] {
            let res = server.get(&path).await;
            assert_eq!(303, res.status_code(), "GET {path}");
            let location = res.headers().get("location").unwrap().to_str().unwrap();
            assert!(location.starts_with("/login"), "GET {path} -> {location}");
        }

        for path in [
            "/rescan".to_string(),
            "/shuffle".to_string(),
            format!("/shuffle/{book}"),
        ] {
            let res = server.post(&path).await;
            assert_eq!(401, res.status_code(), "POST {path}");
        }
    }

    #[tokio::test]
    async fn auth_every_protected_route_reachable_when_logged_in() {
        let server = build_auth_server(true).await;
        server
            .post("/login")
            .form(&[("username", "user"), ("password", "password")])
            .await;
        let book = DATA_IDS[0];

        assert_eq!(200, server.get("/").await.status_code());
        assert_eq!(
            200,
            server.get(&format!("/book/{book}")).await.status_code()
        );
        assert_eq!(303, server.post("/rescan").await.status_code());
        assert_eq!(303, server.post("/shuffle").await.status_code());
        assert_eq!(
            303,
            server.post(&format!("/shuffle/{book}")).await.status_code()
        );
        // 404, not a redirect, proves auth passed.
        assert_eq!(404, server.get("/data/deadbeef").await.status_code());
        assert_eq!(404, server.get("/thumb/md/deadbeef").await.status_code());
    }

    #[tokio::test]
    async fn book_not_found() {
        let server = build_server().await;
        let res = server.get("/book/nonexistent123").await;
        assert_eq!(404, res.status_code());
    }

    #[tokio::test]
    async fn page_not_found() {
        let server = build_server().await;
        let res = server.get("/data/nonexistent123").await;
        assert_eq!(404, res.status_code());
    }
}
