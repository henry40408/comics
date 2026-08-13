use std::{io, io::Write as _, net::SocketAddr, path::PathBuf, sync::Arc, thread};

use anyhow::{anyhow, bail};
use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _,
    password_hash::{SaltString, rand_core::OsRng},
};
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
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::{
    EnvFilter, Layer as _, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

use comics::{
    APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, AppState, AuthConfig, DEFAULT_ABSOLUTE_TTL,
    DEFAULT_IDLE_TTL, FAVICON_PNG, FAVICON_SVG, MAX_CONCURRENT_VERIFICATIONS, MAX_PASSWORD_BYTES,
    MIN_PASSWORD_CHARS, RateLimiter, Secret, SessionAuditSalt, SessionStore, THEME_JS,
    TrustedProxies, VERSION, auth_middleware_fn, csrf_origin_guard, healthz_route, index_route,
    login_route, login_submit_route, logout_route, no_store_html, rescan_books_route, scan_books,
    security_headers_layer, show_book_route, show_page_route, show_thumb_route, shuffle_book_route,
    shuffle_route,
};

// The release image links musl, whose default allocator is markedly slower than
// glibc's under the concurrent, allocation-heavy work this server does (rayon
// scans, on-demand image decoding for thumbnails). mimalloc restores throughput.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Assets are fingerprinted in the URL (`?v=<hash>`), so they can be cached
// forever; the URL changes whenever the content changes.
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
    /// Defaults to off: comics never terminates TLS itself, so it cannot detect
    /// HTTPS behind a reverse proxy, and a browser silently discards a `Secure`
    /// cookie delivered over plain HTTP — defaulting it on would lock plain-HTTP
    /// LAN deployments out of the login form with no visible error.
    #[arg(
        long,
        env = "COMICS_COOKIE_SECURE",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    cookie_secure: Option<bool>,
    /// The one secret comics is configured with: at least 64 hex characters
    /// (32 bytes). Generate one with `openssl rand -hex 32`. Both the session
    /// cookie signing key and the salt for hashed book/page IDs are derived from
    /// it. Sessions live in memory and end at every restart regardless of this
    /// value; what it buys is stable book and page URLs across restarts, and a
    /// signature that stays valid so a stale cookie is distinguishable from a
    /// forged one. When unset a random secret is generated at startup, which
    /// reshuffles every URL on restart. Rotating it changes every URL.
    #[arg(long, env = "COMICS_SECRET")]
    secret: Option<Secret>,
    /// Send `Strict-Transport-Security` with this `max-age` (seconds). Off by
    /// default: HSTS belongs on the TLS-terminating reverse proxy, and a browser
    /// that has cached the header will refuse plain HTTP to this host for the
    /// whole max-age — which would make an HTTP-only LAN deployment unreachable
    /// with no easy way back. Only enable when comics is always reached over
    /// HTTPS. Suggested value: 63072000 (2 years).
    #[arg(long, env = "COMICS_HSTS_MAX_AGE")]
    hsts_max_age: Option<u64>,
    /// Reverse proxies whose `X-Forwarded-For` may set the login rate-limit key:
    /// a comma-separated list of IP addresses and CIDR prefixes (e.g.
    /// `172.16.0.0/12,10.0.0.2`). Empty by default, which ignores the header and
    /// keys on the TCP peer — the header is forgeable by anyone who can reach
    /// the port, so only an explicit list can make it meaningful. Set it to the
    /// address the proxy connects from, not to the client range. Leaving it
    /// unset behind a proxy is safe but blunt: every client shares the proxy's
    /// single bucket.
    #[arg(long, env = "COMICS_TRUSTED_PROXIES")]
    trusted_proxies: Option<TrustedProxies>,
    /// Turn off the CSRF origin guard entirely. Off by default, and there is no
    /// good reason to set it on a deployment reachable from anywhere untrusted.
    ///
    /// It exists for one shape the guard cannot serve: a plain-HTTP LAN host
    /// (`http://nas.local`). Fetch-metadata headers are only sent to
    /// potentially-trustworthy origins — HTTPS or `localhost` — so no
    /// `Sec-Fetch-Site` ever arrives, the guard falls back to `Origin`, and a
    /// browser that reports an opaque `Origin: null` then locks the operator out
    /// of the login form with no way back. Serving over HTTPS fixes the same
    /// problem without giving anything up; prefer that when it is available.
    ///
    /// What is left when this is set: the session cookie's `SameSite=Strict`,
    /// which is what actually keeps a cross-site POST from carrying credentials.
    /// This guard is defence in depth on top of it, not the only lock.
    #[arg(
        long,
        env = "COMICS_DISABLE_CSRF_GUARD",
        num_args = 0..=1,
        default_missing_value = "true",
        default_value = "false"
    )]
    disable_csrf_guard: bool,
    /// Bind host & port. Defaults to loopback so a bare-metal run is not
    /// exposed on all interfaces without opting in; the container image sets
    /// `COMICS_BIND=0.0.0.0:8080` so a reverse proxy can reach it.
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

/// Login attempts allowed per client IP within [`LOGIN_WINDOW_SECS`]. Not
/// exposed as an option: a single-account service has one legitimate user, for
/// whom five tries a minute is ample.
const LOGIN_MAX_ATTEMPTS: u32 = 5;
const LOGIN_WINDOW_SECS: u64 = 60;

/// Login attempts allowed across *every* client IP within [`LOGIN_WINDOW_SECS`].
///
/// The account-scoped counter the OWASP Authentication Cheat Sheet asks for, and
/// what bounds an attacker spraying from addresses they hold in bulk. Four times
/// the per-IP allowance, so it takes at least four distinct addresses failing
/// within the same minute to reach — well outside one reader's use, and the
/// [`RateLimiter`] docs explain what happens when an attack reaches it anyway.
const LOGIN_GLOBAL_MAX_ATTEMPTS: u32 = 20;

/// Whether the session cookie carries `Secure`. comics never terminates TLS, so
/// there is no runtime signal to infer from and no declared public URL — the
/// explicit flag is the only input.
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
        // Fixed rather than scaled to the core count: what this bounds is
        // memory, not parallelism, and the machine's core count says nothing
        // about how much of it there is to spare.
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
        // Page images and thumbnails are content, so they live behind the auth
        // layer too. Cookie verification is cheap, so guarding every image
        // request (unlike a per-request password hash) is no longer a concern.
        .route("/data/{id}", get(show_page_route))
        .route("/thumb/{size}/{id}", get(show_thumb_route))
        // Inside the auth layer, so it only sees responses for protected routes:
        // authenticated HTML must not be left in a cache that survives logout.
        .route_layer(middleware::from_fn(no_store_html))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware_fn,
        ))
        // Login/logout sit outside the auth layer so they stay reachable while
        // logged out.
        .route("/login", get(login_route).post(login_submit_route))
        .route("/logout", post(logout_route))
        .route("/healthz", get(healthz_route))
        .route("/assets/app.css", get(|| async { (CSS_HEADERS, APP_CSS) }))
        .route("/assets/app.js", get(|| async { (JS_HEADERS, APP_JS) }))
        // Separate from app.js because it is loaded synchronously in <head>;
        // see the module comment in vendor/assets/theme.js.
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
            // Per-request logs are noisy for an image-heavy app (every page and
            // thumbnail hits /data), so emit them at DEBUG; enable with RUST_LOG
            // (e.g. `RUST_LOG=comics=info,tower_http=debug`). Failures still
            // surface via the default on_failure (ERROR).
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        );

    // Global outer layer so the check also covers the public `/login` and
    // `/logout` POSTs, which sit outside the auth layer; inert for safe
    // methods, so every asset/image/`/healthz` GET passes untouched. Skipped
    // entirely rather than made permissive when disabled, so the disabled build
    // has no classification logic left to get wrong.
    let router = if opts.disable_csrf_guard {
        warn!(
            "CSRF origin guard disabled by --disable-csrf-guard; every \
             state-changing request is accepted whatever its origin. The \
             session cookie's SameSite=Strict is the only cross-site defence \
             left. Serving over HTTPS is the way to undo this."
        );
        router
    } else {
        router.layer(middleware::from_fn(csrf_origin_guard))
    };

    let router = router
        // Global outer layer so the policy also covers `/login`, `/healthz` and
        // the assets. Everything but HSTS is unconditional; HSTS stays inert
        // unless a max-age is configured.
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

/// Prefixes of the bcrypt hashes comics issued before it moved to Argon2.
///
/// Matched only to say so plainly. Every such hash stopped working at the
/// switch, and the parse error alone would be `salt invalid: too short` — true,
/// unactionable, and the sort of message that sends an operator hunting through
/// their reverse proxy for a fault that is one command away.
const BCRYPT_PREFIXES: [&str; 4] = ["$2a$", "$2b$", "$2x$", "$2y$"];

/// Reject a `COMICS_AUTH_PASSWORD_HASH` that is not an Argon2 hash.
///
/// The login handler treats an unparseable hash as a wrong password — so without
/// this the server starts, logs that authentication is enabled, and then refuses
/// every correct password with the same generic error a typo produces. Failing
/// closed is the right direction; failing closed *silently* is not, because the
/// one thing the operator cannot see is that the hash, rather than their typing,
/// is at fault. That goes double after the bcrypt-to-Argon2 switch, where every
/// previously working configuration becomes exactly this case.
///
/// Checked at startup for the same reason as [`ensure_no_legacy_env_vars`]: a
/// configuration mistake should stop the server rather than change what it
/// quietly does. Deliberately not checked before the `hash-password` subcommand,
/// which is what an operator runs *to fix* a bad hash.
///
/// A parse alone is **not** enough, and neither is a trial verification.
///
/// The PHC grammar is looser than it looks: `PasswordHash::new` happily accepts
/// `$argon2id$v=19$m=19456$nope`, a salt with no digest after it, because that
/// shape is legal as *input* to a hasher. Such a hash can never verify anything.
///
/// Nor can a trial verification catch it, which is the subtle part:
/// `PasswordVerifier` reports a missing digest as `Error::Password` — the very
/// same answer as a merely wrong password — so a verification that fails proves
/// nothing about the hash. The digest has to be checked for directly, and only
/// then is `Error::Password` the reassuring answer it looks like: *this hash
/// works; that password was wrong*.
///
/// What the verification does still catch is a well-formed hash the login route
/// could not use anyway — another algorithm's, or one whose parameters do not
/// reconstruct — each of which parses cleanly and then fails every comparison.
/// It costs one Argon2id verification, some 15 ms and 19 MiB, once, at startup.
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
        Ok(()) | Err(argon2::password_hash::Error::Password) => Ok(()),
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
        // The two settings contradict each other: HSTS declares the site
        // HTTPS-only while the cookie is still sent without `Secure`.
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
    // `into_make_service_with_connect_info` is what puts the TCP peer address in
    // the request extensions; without it the login rate limiter would degrade to
    // a single global bucket.
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
                    // Sender dropped after successful scan; wait for real shutdown signal
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

/// Refuse a password past [`comics::MAX_PASSWORD_BYTES`].
///
/// A backstop rather than a real constraint — Argon2 truncates nothing, so
/// unlike bcrypt's 72 bytes this limit exists only to keep the verifier from
/// being handed something absurd. Kept in step with the identical check in
/// `verify_credentials`, so a password that hashes here always verifies there.
///
/// Split out of [`hash_password`] so it can be tested: that one reads from a tty
/// and no test can drive it, which would leave this covered by nothing.
fn ensure_password_fits(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        // The one length that is a mistake rather than a choice. Everything
        // shorter than advisable is left to `password_strength_warning`; nobody
        // sets an empty password deliberately, and a hash of one would lock the
        // reader out of noticing.
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

/// What to say about a password that is shorter than OWASP advises, if anything.
///
/// Advice, not enforcement — see [`comics::MIN_PASSWORD_CHARS`] for why a
/// single-account self-hosted service leaves this to its operator. Returned
/// rather than printed so it can be tested; [`hash_password`] reads from a tty
/// and no test can drive it.
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

/// Hash a password with Argon2id at [`Argon2::default`]'s parameters, which are
/// `m=19456, t=2, p=1` — one of the configurations the OWASP Password Storage
/// Cheat Sheet lists as sufficient. They are recorded in the PHC string that
/// comes out, so raising them later leaves existing hashes verifiable.
fn argon2_hash(password: &str) -> anyhow::Result<String> {
    ensure_password_fits(password)?;
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow!("failed to hash the password: {err}"))?
        .to_string())
}

/// Hash `password` and write the result: the hash to `out`, any advice to `err`.
///
/// The two sinks are parameters rather than `println!`/`eprintln!` so that the
/// split can be *tested*. It is the load-bearing part of this command —
/// `COMICS_AUTH_PASSWORD_HASH=$(comics hash-password)` captures stdout, so a
/// warning that leaked into it would be silently baked into the configured hash
/// — and it is the sort of thing a later edit undoes without noticing. Note that
/// the tracing subscriber also writes to stdout, which is why the warning is not
/// a `warn!`.
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

fn init_tracing(format: LogFormat) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error,comics=info"));
    let span_events = env_filter.max_level_hint().map_or(FmtSpan::CLOSE, |l| {
        if l >= Level::DEBUG {
            FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        }
    });
    let use_ansi = std::env::var_os("NO_COLOR").is_none();
    let layer = tracing_subscriber::fmt::layer()
        .with_span_events(span_events)
        .with_ansi(use_ansi);
    let layer = match format {
        LogFormat::Full => layer.with_filter(env_filter).boxed(),
        LogFormat::Compact => layer.compact().with_filter(env_filter).boxed(),
        LogFormat::Pretty => layer.pretty().with_filter(env_filter).boxed(),
        LogFormat::Json => layer.json().with_filter(env_filter).boxed(),
    };
    tracing_subscriber::registry().with(layer).init();
}

/// Configuration environment variables that no longer exist, paired with the
/// name that replaced them. Most were renamed to carry the `COMICS_` prefix;
/// `COMICS_SEED` and `COMICS_SESSION_KEY` were folded into the single
/// `COMICS_SECRET` both are now derived from. `NO_COLOR` (an ecosystem-wide
/// convention) and `GIT_VERSION` (a build-time variable) were intentionally
/// left unprefixed and are deliberately absent from this list.
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

/// Fail fast when a retired environment variable name is still set, so a stale
/// deployment configuration surfaces immediately instead of being silently
/// ignored (the old names are no longer wired to any option).
///
/// This matters most for the two folded into `COMICS_SECRET`: ignoring a
/// leftover `COMICS_SESSION_KEY` would quietly generate a random secret
/// instead, logging everyone out on every restart while the operator's
/// configuration still looks correct.
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
            // Ignore write errors (e.g., broken pipe when output is piped to `head`)
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
    use tokio::sync::oneshot;

    /// Fixed secret so the derived ID seed — and therefore the URLs below — are
    /// stable across runs. Any 64 hex characters will do.
    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Book IDs under `TEST_SECRET`. Recompute them whenever the secret or the
    /// derivation changes: `comics --secret <TEST_SECRET> --data-dir
    /// fixtures/data` and read the `/book/…` hrefs off the index page.
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
        // Only when the caller did not pass `--secret` itself.
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

    // The scan timestamp is localised client-side, but never through a
    // customized built-in: WebKit does not implement `<time is="…">` (WebKit
    // bug 182671), so that form is dead on Safari and app.js is one IIFE where
    // a throw would cost the reader too. Opt in per element, so the sibling
    // `<time>` holding an ISO duration is left alone.
    #[tokio::test]
    async fn index_opts_timestamps_into_client_side_localisation() {
        let server = build_server().await;
        let t = server.get("/").await.text();

        assert!(!t.contains("is=\"x-time\""));
        assert_eq!(1, t.matches("data-localtime").count());
    }

    // A duration's time components sit behind the `T` designator, so a bare
    // `P0.003S` parses as nothing at all — in ISO 8601 and in HTML's own
    // duration-string grammar alike. The localised timestamp above carries
    // `data-localtime`, so `<time datetime=` matches only the duration.
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
        // Discover a real page id from the first book's reader page rather than
        // hard-coding a hash that changes whenever the fixtures change.
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

        // A book with a single page in a temp data dir we are free to mutate.
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

        // Discover the page id the scan assigned (cover of the only book).
        let html = server.get("/").await.text();
        let marker = "/thumb/md/";
        let start = html.find(marker).expect("a cover link") + marker.len();
        let id: String = html[start..].chars().take_while(|&c| c != '"').collect();
        assert!(!id.is_empty());

        // Serves while the file exists, then 404s once it is removed post-scan.
        assert_eq!(200, server.get(&format!("/data/{id}")).await.status_code());
        fs::remove_file(&page).unwrap();
        assert_eq!(404, server.get(&format!("/data/{id}")).await.status_code());
    }

    #[tokio::test]
    async fn thumbnail_serves_jpeg() {
        let server = build_server().await;

        // The cover link on the index uses the medium thumbnail endpoint.
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

        // The second request for the same thumbnail is served from the disk cache.
        let cached = server.get(&format!("/thumb/md/{id}")).await;
        assert_eq!(200, cached.status_code());
        assert!(cached.as_bytes().starts_with(b"\xFF\xD8\xFF"));

        // Unknown size and unknown id both 404.
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

        // A "page" that is not a valid image.
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

        // Undecodable source falls back to the original bytes.
        let res = server.get(&format!("/thumb/sm/{id}")).await;
        assert_eq!(200, res.status_code());
        assert_eq!(res.as_bytes(), &b"this is not an image"[..]);

        // Once the original is gone, the fallback 404s.
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

    /// The stateless CSRF origin guard rejects any state-changing POST a browser
    /// reports as cross-site, including the public `/login` and `/logout` that
    /// sit outside the auth layer. The guard is the outermost layer, so it fires
    /// before auth and before the handler.
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

    /// A same-origin POST — the normal browser form submit — is untouched by the
    /// guard and reaches the handler, whether flagged via `Sec-Fetch-Site` or a
    /// matching `Origin`/`Host`.
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

    /// The plain-HTTP LAN lockout the escape hatch exists for: no
    /// `Sec-Fetch-Site` (the origin is not potentially trustworthy, so the
    /// browser sends none) plus an opaque `Origin: null` is rejected by default.
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

    /// With the guard disabled the same request reaches the handler. The layer
    /// is not installed at all, so this also covers the `cross-site` label.
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

    /// A GET is a safe method and never checked, even when reported cross-site.
    #[tokio::test]
    async fn csrf_safe_method_is_never_checked() {
        let server = build_server().await;
        let res = server
            .get("/")
            .add_header("sec-fetch-site", "cross-site")
            .await;
        assert_eq!(200, res.status_code());
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

    /// A real hash — and no credentials at all — must both start the server.
    #[test]
    fn a_usable_password_hash_starts_the_server() {
        let hash = argon2_hash("password").unwrap();
        assert!(ensure_password_hash_is_usable(&opts_with_hash(&hash)).is_ok());

        let public = Opts::parse_from(["comics", "--data-dir", "./fixtures/data"]);
        assert!(ensure_password_hash_is_usable(&public).is_ok());
    }

    /// Without this the server would start, report authentication as enabled,
    /// and then reject the correct password with the same message a typo gets —
    /// leaving the hash the one thing the operator cannot see is at fault. The
    /// empty string is the case that arrives by way of an unset shell variable.
    #[test]
    fn a_malformed_password_hash_stops_startup() {
        let cases = [
            "",
            "not-a-hash",
            "password",
            // Parses, but is a salt with no digest after it — legal as *input*
            // to a hasher, and unable to match any password.
            "$argon2id$v=19$m=19456$nope",
            // Another algorithm's hash: well-formed, and useless to this route.
            "$pbkdf2-sha256$i=1000$c2FsdHNhbHQ$xEbJPmXjr2fBIf1RhJ1Kd0uGrjhOTOAgWnMYGVBLj4Y",
        ];
        for hash in cases {
            let err = ensure_password_hash_is_usable(&opts_with_hash(hash))
                .expect_err(&format!("{hash:?} was accepted"))
                .to_string();
            assert!(err.contains("hash-password"), "{err}");
        }
    }

    /// Every configuration that worked before the move to Argon2 lands here, so
    /// the message has to say what happened and what to do — not the parser's
    /// "salt invalid: too short", which is true and useless. Covers each bcrypt
    /// version prefix, since which one an operator holds depends only on when
    /// they generated it.
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
            // The reassurance that matters: they do not need a new password.
            assert!(err.contains("password itself is unchanged"), "{err}");
        }
    }

    /// The lengths that must go through. The Chinese passphrase is the one worth
    /// spelling out: at three bytes a character it was capped at 24 under
    /// bcrypt's 72-byte ceiling, and a hundred of them is now unremarkable.
    #[test]
    fn hash_password_accepts_a_password_at_the_limit() {
        assert!(ensure_password_fits(&"x".repeat(MAX_PASSWORD_BYTES)).is_ok());

        let cjk = "密".repeat(100);
        assert_eq!(300, cjk.len());
        assert!(ensure_password_fits(&cjk).is_ok());
        // And it really does hash, rather than merely passing the length check.
        assert!(argon2_hash(&cjk).unwrap().starts_with("$argon2id$"));
    }

    /// Past the ceiling the message must name the size that was submitted — the
    /// operator cannot count the bytes of a passphrase they just typed blind.
    #[test]
    fn hash_password_refuses_an_over_long_password() {
        let err = ensure_password_fits(&"x".repeat(MAX_PASSWORD_BYTES + 1))
            .expect_err("a password past the ceiling was accepted")
            .to_string();
        assert!(
            err.contains(&format!("{} bytes", MAX_PASSWORD_BYTES + 1)),
            "{err}"
        );

        // `argon2_hash` applies the same check, so the subcommand cannot bypass it.
        assert!(argon2_hash(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    /// The one length that is a mistake rather than a choice. Hashing it would
    /// produce a perfectly valid hash of nothing, which is the sort of thing an
    /// operator discovers much later.
    #[test]
    fn hash_password_refuses_an_empty_password() {
        assert!(ensure_password_fits("").is_err());
        assert!(argon2_hash("").is_err());
    }

    /// Short passwords are warned about, not refused: a single-account service's
    /// one user is also its operator, and a hard floor would only send them to
    /// generate the hash somewhere else. The warning has to name the length —
    /// they typed it blind — and say it is advice.
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
        // Advice, so the hash still comes out.
        assert!(argon2_hash(&short).unwrap().starts_with("$argon2id$"));
    }

    /// The stream split, which is the part a later edit could quietly undo.
    /// `COMICS_AUTH_PASSWORD_HASH=$(comics hash-password)` captures stdout, so a
    /// warning that leaked into it would be baked into the configured hash and
    /// break every login with no clue as to why.
    #[test]
    fn the_warning_never_reaches_stdout() {
        let short = "x".repeat(MIN_PASSWORD_CHARS - 1);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit_password_hash(&short, &mut out, &mut err).expect("hashing a short password");

        let out = String::from_utf8(out).expect("utf-8 stdout");
        let err = String::from_utf8(err).expect("utf-8 stderr");

        // stdout is the hash and nothing else — one line, parseable as it stands.
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

    /// Nothing on stderr when there is nothing to say — a warning on every run
    /// is one nobody reads.
    #[test]
    fn a_long_enough_password_emits_only_the_hash() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit_password_hash(&"x".repeat(MIN_PASSWORD_CHARS), &mut out, &mut err)
            .expect("hashing an adequate password");

        assert!(String::from_utf8(out).unwrap().starts_with("$argon2id$"));
        assert!(err.is_empty(), "{:?}", String::from_utf8(err));
    }

    /// A refused password writes nothing at all — not a partial line, and above
    /// all not a hash.
    #[test]
    fn a_refused_password_writes_nothing() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(emit_password_hash("", &mut out, &mut err).is_err());
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    /// At or above the advice, nothing is said at all.
    #[test]
    fn a_long_enough_password_draws_no_warning() {
        assert!(password_strength_warning(&"x".repeat(MIN_PASSWORD_CHARS)).is_none());
        assert!(password_strength_warning(&"x".repeat(MIN_PASSWORD_CHARS + 40)).is_none());
    }

    /// Counted in characters, not bytes — the asymmetry with the byte ceiling is
    /// deliberate. Fifteen Chinese characters are 45 bytes; measuring the floor
    /// in bytes would have let five of them through, a third of what an ASCII
    /// passphrase is asked for.
    #[test]
    fn the_strength_floor_counts_characters_not_bytes() {
        let fifteen = "密".repeat(MIN_PASSWORD_CHARS);
        assert_eq!(45, fifteen.len());
        assert!(password_strength_warning(&fifteen).is_none());

        let five = "密".repeat(5);
        assert_eq!(15, five.len(), "fifteen bytes, and far too short");
        assert!(password_strength_warning(&five).is_some());
    }

    // Authentication: form login backed by a signed session cookie.
    const SESSION_COOKIE: &str = "comics_session";

    /// Build a server with credentials configured. When `save_cookies` is set,
    /// the test client persists cookies across requests like a browser would.
    async fn build_auth_server(save_cookies: bool) -> TestServer {
        build_auth_server_with(save_cookies, &[]).await
    }

    /// Like [`build_auth_server`], with `extra_args` appended to the CLI so a
    /// test can flip a single option (e.g. `--cookie-secure`).
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
        // Only when the caller did not pass `--secret` itself.
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

    /// Collect the raw `Set-Cookie` header values. `maybe_cookie` parses the
    /// cookie and drops its attributes, so attribute assertions have to read the
    /// header verbatim.
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

    /// The default must stay attribute-free so plain-HTTP LAN deployments keep
    /// working — a browser silently drops a `Secure` cookie sent over HTTP.
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

    /// HSTS is a global outer layer, so it must be present even on the routes
    /// that sit outside the auth layer.
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

    /// The constant part of the policy is a global outer layer, so it must reach
    /// the public routes and the assets as well as the protected pages — an
    /// asset served without `nosniff` is exactly the one worth sniffing.
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

        // The login form, and the redirect an anonymous visitor is bounced with
        // before ever reaching a handler — the layer is outermost, so both.
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

    /// The CSP is only worth the header bytes if the pages it guards actually
    /// obey it. Every `<script>` comics renders must be an external `src`, or
    /// the browser will drop the inline one and the page breaks — which is the
    /// failure this asserts against, since nothing else in the suite runs a
    /// script.
    #[tokio::test]
    async fn rendered_pages_carry_no_inline_scripts() {
        let server = build_server().await;
        let book = DATA_IDS[0];

        let pages = [
            server.get("/").await.text(),
            server.get(&format!("/book/{book}")).await.text(),
            // `/login` only renders as a page when auth is on; otherwise it
            // redirects to the library.
            build_auth_server(false).await.get("/login").await.text(),
        ];

        for html in pages {
            assert!(html.contains("<script"), "no script rendered");
            for tag in html.split("<script").skip(1) {
                let open = &tag[..tag.find('>').expect("an unclosed <script")];
                assert!(open.contains("src="), "inline script: <script{open}>");
            }
            // A CSP without `unsafe-inline` drops event-handler attributes too.
            assert!(!html.contains("onclick="));
        }
    }

    /// `.pg` is `display: none` until `is-current` lands on it, and app.js is
    /// what normally puts it there — so a reader without JavaScript would get a
    /// blank stage. Exactly the first page carries the class server-side, which
    /// is the same one app.js sets when it repaints from page 1 on load.
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

    /// Without a script there is no way for a shared control to know which page
    /// it sits on, so every page carries its own neighbours and `:target` picks
    /// the one to show. The ends must not offer a link past the book.
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

    /// A control only a script can operate must not be on screen without one.
    /// Checked on every page that renders a theme toggle rather than just the
    /// reader: the toggle is in three templates, and covering one of them is
    /// how the topbar's counter was missed the first time.
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

        // The topbar states the total, which is true without a script; only the
        // live half — the current page — is dropped.
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

    /// The segmented control is a pair of links, so the mode has to survive a
    /// round trip through the URL rather than living only in app.js. A value
    /// nobody recognises renders the default instead of failing the request —
    /// it is a display preference, and a reader beats a 400.
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

    /// The rail is the only one-step route to a distant page, and as `<button>`
    /// it did nothing without a script. Each thumbnail anchors to its page, and
    /// each page states its own number — the rail's counter is written by
    /// app.js, so without it that counter would read 1 on every page.
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

    /// theme.js sets `data-theme`, so a viewer without JavaScript never gets the
    /// attribute the dark palette hangs off. The media-query copy covers them,
    /// and it is a copy — this fails when the two lists drift apart.
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

    /// The no-JS paging keys off `html:not(.js)`, and the class has to be there
    /// before the first paint — theme.js is the only script that early. Drop it
    /// and `:target` would fight app.js over which page is showing.
    #[tokio::test]
    async fn the_scripted_path_is_marked_before_first_paint() {
        let server = build_server().await;

        let js = server.get("/assets/theme.js").await.text();
        assert!(js.contains("classList.add(\"js\")"), "{js}");
        assert!(comics::assets::APP_CSS.contains("html:not(.js)"));
    }

    /// Loaded synchronously in `<head>`, so it must not be deferred — the point
    /// is that it runs before the first paint.
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

    /// Authenticated images stay browser-cacheable (page turns would otherwise
    /// re-read the disk every time) but must not be kept by a shared cache.
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

    /// The middleware must not reach the assets: they carry no user data and
    /// their fingerprinted URLs are what make the long cache safe.
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

    /// Sessions do **not** survive a rebuild of the router, and that is the
    /// deliberate trade the session store makes.
    ///
    /// This test previously asserted the opposite: a fixed `COMICS_SECRET` made
    /// a cookie issued by one server acceptable to the next, because the cookie
    /// described itself and the server kept no record of it. That is exactly what
    /// made logout unenforceable — nothing existed to delete — so ending a
    /// session and surviving a restart were the same property, and only one of
    /// them could be had. Being able to revoke won.
    ///
    /// What the secret still buys is asserted below: stable URLs, and a
    /// signature that stays valid across the rebuild, so a stale cookie is
    /// distinguishable from a forged one.
    #[tokio::test]
    async fn sessions_do_not_survive_a_router_rebuild() {
        // Deliberately not TEST_SECRET: the flag, not the helper default, has to
        // be what makes the two routers agree.
        const SECRET: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\
                              fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let first = build_auth_server_with(true, &["--secret", SECRET]).await;
        let res = login_response(&first).await;
        assert_eq!(303, res.status_code());
        let cookie = res.maybe_cookie(SESSION_COOKIE).expect("a session cookie");

        // The same cookie against a fresh process: the store never heard of it.
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

    /// The shared secret still keeps book and page URLs stable across a restart.
    /// That, and signature continuity, is what it is for now that it no longer
    /// decides whether a session lives.
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

        // Not DATA_IDS: those are derived from TEST_SECRET, and this test uses
        // its own so the flag rather than the helper default is what makes the
        // two agree. Comparing the two sets is the property either way.
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

    /// The cookie carries the session identifier and nothing else — no expiry,
    /// no username, nothing an attacker could decode or an operator could be
    /// tempted to trust. Everything else lives in the store.
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

    /// A successful login must not consume the anti-brute-force budget: the
    /// control targets password guessing, and locking out someone who signs in
    /// on several devices would be pure cost.
    #[tokio::test]
    async fn auth_successful_logins_do_not_count_against_the_limit() {
        let server = build_auth_server(false).await;
        for attempt in 1..=(LOGIN_MAX_ATTEMPTS + 3) {
            let res = login_response(&server).await;
            assert_eq!(303, res.status_code(), "attempt {attempt}");
        }
    }

    /// The sixth *failed* attempt inside the window is refused, and the refusal
    /// happens before the credential check — so even the correct password gets a
    /// 429.
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

    /// Fail a login `n` times as the client `X-Forwarded-For` names, returning
    /// the status of the last attempt.
    async fn failed_login_from(server: &TestServer, forwarded_for: &str) -> http::StatusCode {
        server
            .post("/login")
            .add_header("x-forwarded-for", forwarded_for)
            .form(&[("username", "user"), ("password", "nope")])
            .await
            .status_code()
    }

    /// End-to-end proof that `--trusted-proxies` reaches the limiter: the test
    /// server's peer is loopback, so naming it as the proxy makes
    /// `X-Forwarded-For` authoritative and each forwarded client gets its own
    /// budget. Guards the `Opts` → `AppState` → handler wiring, which no unit
    /// test on `rate_limit_key` can see.
    #[tokio::test]
    async fn auth_trusted_proxy_gives_each_forwarded_client_its_own_budget() {
        let server = build_auth_server_with(false, &["--trusted-proxies", "127.0.0.1"]).await;
        for attempt in 1..=LOGIN_MAX_ATTEMPTS {
            let status = failed_login_from(&server, "203.0.113.1").await;
            assert_eq!(401, status, "attempt {attempt}");
        }
        assert_eq!(429, failed_login_from(&server, "203.0.113.1").await);

        // A different forwarded client is untouched by the first one's lockout.
        assert_eq!(401, failed_login_from(&server, "203.0.113.2").await);
    }

    /// The default. With no proxy configured the header is ignored outright, so
    /// two forwarded clients share the peer's single bucket — safe, and blunt.
    #[tokio::test]
    async fn auth_untrusted_forwarded_clients_share_one_budget() {
        let server = build_auth_server(false).await;
        for attempt in 1..=LOGIN_MAX_ATTEMPTS {
            let status = failed_login_from(&server, &format!("203.0.113.{attempt}")).await;
            assert_eq!(401, status, "attempt {attempt}");
        }
        assert_eq!(429, failed_login_from(&server, "203.0.113.99").await);
    }

    /// The account-scoped ceiling, on the real router: four addresses spend their
    /// five apiece, and a fifth — whose own per-IP budget is untouched — is
    /// refused anyway. Per-IP alone waved that fifth address straight through,
    /// which is the gap the global window closes.
    ///
    /// Slower than its neighbours because every one of those twenty attempts
    /// costs a real `BCRYPT_COST` verification; the throttle is reserved before
    /// the credential check, so they cannot be made cheap without also making
    /// the test stop exercising the path it is about.
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
        // An off-site `next` is ignored in favour of the home page.
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

    /// `SameSite=Strict` is the cheat sheet's stated preference and comics can
    /// afford it: nothing third-party ever navigates into an authenticated URL.
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

    /// Both responses that carry a session identifier are redirects, and neither
    /// is reached by `no_store_html` — `/login` and `/logout` sit outside the
    /// auth layer, and a redirect is not `text/html`. The cheat sheet asks for
    /// `no-store` on exactly these.
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

    /// End-to-end for the backslash open redirect: the endpoint must send the
    /// visitor home, not to `//evil.example`, which is where a browser resolves
    /// `Location: /\evil.example`.
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

    /// `next` reaches the handler percent-decoded, and `Redirect::to` panics on
    /// a value `HeaderValue` refuses — so this must answer, not drop the
    /// connection. Reachable without credentials: `GET /login` redirects before
    /// authenticating whenever auth is disabled.
    #[tokio::test]
    async fn login_survives_a_control_character_in_next() {
        let server = build_server().await;
        let res = server.get("/login?next=%2F%0Ax").await;
        assert_eq!(303, res.status_code());
        assert_eq!("/", res.headers()["location"]);
    }

    /// The change this branch exists for: after logout the *same* cookie is
    /// refused, because the session it names is gone from the server.
    ///
    /// The cookie is replayed by hand rather than through the client jar,
    /// precisely because the jar would honour the removal cookie and prove
    /// nothing — a browser that ignores it, or an attacker holding a copy taken
    /// earlier, is exactly the case that used to keep working for a further
    /// seven days.
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

    /// Logout ends *every* session, not just the one that submitted it, so a
    /// reader who suspects a stolen cookie can invalidate it by signing out
    /// anywhere. Without this the only remedy was restarting the server.
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

    /// `/logout` sits outside the auth middleware and the CSRF guard passes
    /// header-less clients, so an anonymous `POST` must not be able to sign
    /// everyone out.
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
        // The removal cookie must mirror the issued one, or the browser will not
        // consider them the same cookie.
        let removal = set_cookie_headers(&res)
            .into_iter()
            .find(|h| h.starts_with(&format!("{SESSION_COOKIE}=")))
            .expect("a removal cookie");
        assert!(removal.contains("HttpOnly"), "{removal}");
        assert!(removal.contains("SameSite=Strict"), "{removal}");
        assert!(removal.contains("Path=/"), "{removal}");

        // Session is gone, so the protected page bounces to login again.
        assert_eq!(303, server.get("/").await.status_code());
    }

    #[tokio::test]
    async fn auth_public_routes_need_no_login() {
        let server = build_auth_server(false).await;
        assert_eq!(200, server.get("/healthz").await.status_code());
        assert_eq!(200, server.get("/assets/app.css").await.status_code());
    }

    /// Every route behind the auth layer must refuse anonymous access: read
    /// routes bounce to the login form, write routes are rejected with 401. This
    /// guards against a route silently slipping out from under the middleware
    /// (e.g. by being declared after `route_layer`).
    #[tokio::test]
    async fn auth_every_protected_route_rejects_anonymous() {
        let server = build_auth_server(false).await;
        let book = DATA_IDS[0];

        for path in [
            "/".to_string(),
            format!("/book/{book}"),
            // Page images and thumbnails are content too, so they sit behind the
            // login as well. The middleware runs before the handler, so a bogus
            // id still redirects rather than 404ing.
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

    /// The flip side: with a valid session every protected route is reachable
    /// (no redirect to login, no 401).
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
        // Write routes succeed and redirect (303), rather than being blocked.
        assert_eq!(303, server.post("/rescan").await.status_code());
        assert_eq!(303, server.post("/shuffle").await.status_code());
        assert_eq!(
            303,
            server.post(&format!("/shuffle/{book}")).await.status_code()
        );
        // Image routes let the request through to the handler: an unknown id
        // 404s (rather than redirecting to login), proving auth passed.
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
