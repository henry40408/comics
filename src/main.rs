use std::{
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use clap::{Parser, Subcommand, ValueEnum};
use cookie::Key;
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
    APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, AppState, AuthConfig, BCRYPT_COST, FAVICON_PNG,
    FAVICON_SVG, VERSION, auth_middleware_fn, csrf_origin_guard, healthz_route, index_route,
    login_route, login_submit_route, logout_route, rescan_books_route, scan_books, show_book_route,
    show_page_route, show_thumb_route, shuffle_book_route, shuffle_route,
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
    /// Seed to generate hashed IDs
    #[arg(long, env = "COMICS_SEED")]
    seed: Option<u64>,
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

#[allow(
    clippy::unnecessary_wraps,
    reason = "init entry point; keeps a fallible signature for future fallible setup steps"
)]
fn init_route(opts: &Opts) -> anyhow::Result<(Router, Arc<AppState>)> {
    let data_dir = &opts.data_dir;

    let seed = opts.seed.unwrap_or_else(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        warn!(%seed, "no seed provided, use seconds since UNIX epoch as seed");
        seed
    });
    let state = Arc::new(AppState {
        auth_config: match (opts.auth_username.clone(), opts.auth_password_hash.clone()) {
            (Some(u), Some(p)) => AuthConfig::Some {
                username: u,
                password_hash: p,
            },
            _ => AuthConfig::None,
        },
        key: Key::generate(),
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
    });

    let router = Router::new()
        .route("/book/{id}", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/shuffle/{id}", post(shuffle_book_route))
        .route("/shuffle", post(shuffle_route))
        .route("/", get(index_route))
        // Page images and thumbnails are content, so they live behind the auth
        // layer too. Cookie verification is cheap, so guarding every image
        // request (unlike per-request bcrypt) is no longer a concern.
        .route("/data/{id}", get(show_page_route))
        .route("/thumb/{size}/{id}", get(show_thumb_route))
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
        )
        // First-line CSRF defence: a stateless cross-site check on every
        // unsafe-method request. Applied as a global outer layer so it also
        // covers the public `/login` and `/logout` POSTs, which sit outside the
        // auth layer. It is inert for safe methods, so every asset/image/
        // `/healthz` GET passes untouched.
        .layer(middleware::from_fn(csrf_origin_guard))
        .with_state(state.clone());

    Ok((router, state))
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

async fn run_server(addr: SocketAddr, opts: &Opts) -> anyhow::Result<()> {
    let (tx, rx) = oneshot::channel::<()>();
    let (app, state) = init_route(opts)?;
    if opts.auth_username.is_none() || opts.auth_password_hash.is_none() {
        warn!("no authorization enabled, server is publicly accessible");
    }
    let version = VERSION;
    let listener = TcpListener::bind(&addr).await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    info!(addr = %local_addr, %version, "server started");
    spawn_initial_scan(state, tx);
    axum::serve(listener, app)
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

fn hash_password() -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirmation: ")?;
    if password != confirmation {
        bail!("Password mismatch");
    }
    let hashed = bcrypt::hash(password, BCRYPT_COST)?;
    println!("{hashed}");
    Ok(())
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
                &scan.books.len(),
                &scan.pages_map.len(),
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
    use crate::{Opts, init_route, spawn_initial_scan};
    use axum_test::TestServer;
    use clap::Parser as _;
    use comics::{BCRYPT_COST, VERSION};
    use tokio::sync::oneshot;

    const DATA_IDS: [&str; 2] = [
        // Pepper and Carrot 01 - Potion of Flight
        "cc95bc12d8d64a8a",
        // Pepper and Carrot 02 - Rainbow Potions
        "cdada1cf3b5d0696",
    ];

    async fn build_server() -> TestServer {
        build_server_at("./fixtures/data").await
    }

    async fn build_server_at(data_dir: &str) -> TestServer {
        use std::{thread, time};

        let (tx, _) = oneshot::channel::<()>();
        let mut opts = Opts::parse_from(["comics", "--data-dir", data_dir]);
        opts.seed = Some(1);
        let (router, state) = init_route(&opts).unwrap();
        spawn_initial_scan(state, tx);

        let server = TestServer::new(router.into_make_service());
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

        // Verify redirect is to a different book
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

    // Authentication: form login backed by a signed session cookie.
    const SESSION_COOKIE: &str = "comics_session";

    /// Build a server with credentials configured. When `save_cookies` is set,
    /// the test client persists cookies across requests like a browser would.
    async fn build_auth_server(save_cookies: bool) -> TestServer {
        use std::{thread, time};

        let (tx, _) = oneshot::channel::<()>();
        let mut opts = Opts::parse_from([
            "comics",
            "--data-dir",
            "./fixtures/data",
            "--auth-username",
            "user",
            "--auth-password-hash",
            &bcrypt::hash("password", BCRYPT_COST).unwrap(),
        ]);
        opts.seed = Some(1);
        let (router, state) = init_route(&opts).unwrap();
        spawn_initial_scan(state, tx);

        let mut server = TestServer::new(router.into_make_service());
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

    // Error handling tests
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
