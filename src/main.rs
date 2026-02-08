use std::{
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use axum::{Router, middleware, routing::{get, post}};
use clap::{Parser, Subcommand, ValueEnum};
use http::header;
use parking_lot::Mutex;
use tokio::{
    net::TcpListener,
    sync::oneshot::{self, Sender},
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::{
    EnvFilter, Layer as _, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

use comics::{
    AuthConfig, AppState, BCRYPT_COST, VERSION,
    auth_middleware_fn, healthz_route, index_route, rescan_books_route,
    scan_books, show_book_route, show_page_route, shuffle_book_route, shuffle_route,
};

const WATER_CSS: &str = include_str!("../vendor/assets/water.css");

type SingleHeader = [(header::HeaderName, &'static str); 1];
const CSS_HEADER: SingleHeader = [(header::CONTENT_TYPE, "text/css")];

#[derive(Parser, Debug)]
#[command(author, version=VERSION, about, long_about=None)]
struct Opts {
    /// Username for basic authentication
    #[arg(long, env = "AUTH_USERNAME")]
    auth_username: Option<String>,
    /// Hashed password for basic authentication
    #[arg(long, env = "AUTH_PASSWORD_HASH")]
    auth_password_hash: Option<String>,
    /// Bind host & port
    #[arg(long, short = 'b', env = "BIND", default_value = "127.0.0.1:3000")]
    bind: String,
    /// Debug mode
    #[arg(long, short = 'd', env = "DEBUG")]
    debug: bool,
    /// Data directory
    #[arg(long, env = "DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,
    /// Log format
    #[arg(long, env = "LOG_FORMAT", default_value = "full")]
    log_format: LogFormat,
    /// No color <https://no-color.org/>
    #[arg(long, env = "NO_COLOR")]
    no_color: bool,
    /// Seed to generate hashed IDs
    #[arg(long, env = "SEED")]
    seed: Option<u64>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Debug, ValueEnum)]
enum LogFormat {
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

fn init_route(opts: &Opts, tx: Sender<()>) -> anyhow::Result<Router> {
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
        data_dir: data_dir.clone(),
        scan: Arc::new(Mutex::new(None)),
        seed,
    });

    let router = Router::new()
        .route("/book/{id}", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/shuffle/{id}", post(shuffle_book_route))
        .route("/shuffle", post(shuffle_route))
        .route("/", get(index_route))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware_fn,
        ))
        // to prevent timing attack, bcrypt is too slow
        // protected by randomly-generated string as page ID instead
        .route("/data/{id}", get(show_page_route))
        .route("/healthz", get(healthz_route))
        .route(
            "/assets/water.css",
            get(|| async { (CSS_HEADER, WATER_CSS) }),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state.clone());

    thread::spawn({
        let state = state.clone();
        move || {
            let new_scan = match scan_books(state.seed, &state.data_dir) {
                Ok(s) => s,
                Err(err) => {
                    error!(?err, "initial scan failed");
                    let _ = tx.send(());
                    return;
                }
            };

            let total_books = &new_scan.books.len();
            let total_pages = &new_scan.pages_map.len();
            let duration = new_scan
                .scan_duration
                .to_std()
                .map(|d| format!("{d:?}"))
                .unwrap_or(String::new());
            info!(total_books, total_pages, %duration, "initial scan finished");

            *state.scan.lock() = Some(new_scan);
        }
    });

    Ok(router)
}

async fn run_server(addr: SocketAddr, opts: &Opts) -> anyhow::Result<()> {
    let (tx, rx) = oneshot::channel::<()>();
    let app = init_route(opts, tx)?;
    if opts.auth_username.is_none() || opts.auth_password_hash.is_none() {
        warn!("no authorization enabled, server is publicly accessible");
    }
    let version = VERSION;
    let listener = TcpListener::bind(&addr).await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    info!(addr = %local_addr, %version, "server started");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if (rx.await).is_err() {
                std::future::pending::<()>().await;
            }
            warn!("fatal error occurred, shutdown the server");
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

fn init_tracing(opts: &Opts) {
    let default_directive = if opts.debug {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_directive.into())
        .from_env_lossy();
    let span_events = env_filter.max_level_hint().map_or_else(
        || FmtSpan::CLOSE,
        |l| {
            if l >= Level::DEBUG {
                FmtSpan::CLOSE
            } else {
                FmtSpan::NONE
            }
        },
    );
    let layer = tracing_subscriber::fmt::layer().with_span_events(span_events);
    let layer = match opts.log_format {
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

    init_tracing(&opts);

    match &opts.command {
        Some(Commands::HashPassword { .. }) => hash_password()?,
        Some(Commands::List { .. }) => {
            let seed = 0u64; // dummy salt
            let scan = scan_books(seed, &opts.data_dir)?;
            let mut stdout = std::io::stdout().lock();
            for book in &scan.books {
                _ = writeln!(stdout, "{} ({}P)", book.title, book.pages.len());
            }
            _ = writeln!(
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
    use crate::{Opts, init_route};
    use axum_test::TestServer;
    use base64::Engine;
    use clap::Parser as _;
    use comics::{BCRYPT_COST, VERSION};
    use tokio::sync::oneshot;

    const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    const DATA_IDS: [&str; 2] = [
        // Netherworld Nomads Journey to the Jade Jungle
        "8e81107a0fb24286",
        // Quantum Quest Legacy of the Luminous League
        "1500ed4c58b05a85",
    ];

    async fn build_server() -> TestServer {
        use std::{thread, time};

        let (tx, _) = oneshot::channel::<()>();
        let mut opts = Opts::parse_from(["comics", "--data-dir", "./fixtures/data"]);
        opts.seed = Some(1);
        let router = init_route(&opts, tx).unwrap();

        let server = TestServer::new(router.into_make_service()).unwrap();
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
        assert!(t.contains("Netherworld Nomads Journey to the Jade Jungle"));
        assert!(t.contains("Quantum Quest Legacy of the Luminous League"));
    }

    #[tokio::test]
    async fn get_book() {
        let book_id = DATA_IDS.first().unwrap();
        let path = format!("/book/{book_id}");
        let server = build_server().await;
        let res = server.get(&path).await;
        assert_eq!(200, res.status_code());

        let t = res.text();
        assert!(t.contains("Netherworld Nomads Journey to the Jade Jungle"));
    }

    #[tokio::test]
    async fn get_page() {
        let page_id = "df007a2c411dcb94"; // Netherworld Nomads Journey to the Jade Jungle, page 1
        let path = format!("/data/{page_id}");
        let server = build_server().await;
        let res = server.get(&path).await;
        assert_eq!(200, res.status_code());

        let content = res.as_bytes();
        assert!(content.starts_with(b"\xFF\xD8\xFF")); // JPEG magic bytes
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
        let book_id = DATA_IDS.last().unwrap();
        let expected = format!("/book/{book_id}");
        assert_eq!(expected, location);
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

    #[tokio::test]
    async fn auth() {
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
        let router = init_route(&opts, tx).unwrap();

        let server = TestServer::new(router.into_make_service()).unwrap();
        for _ in 0..10 {
            let res = server.get("/healthz").await;
            if res.status_code() == 200 {
                break;
            }
            thread::sleep(time::Duration::from_millis(100));
        }

        let credentials = BASE64_ENGINE.encode("user:password");
        let res = server
            .get("/")
            .authorization(format!("Basic {credentials}"))
            .await;
        assert_eq!(200, res.status_code());
    }

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    // Authentication edge cases
    async fn build_auth_server() -> TestServer {
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
        let router = init_route(&opts, tx).unwrap();

        let server = TestServer::new(router.into_make_service()).unwrap();
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
    async fn auth_invalid_base64() {
        let server = build_auth_server().await;
        let res = server
            .get("/")
            .authorization("Basic not-valid-base64!!!")
            .await;
        assert_eq!(500, res.status_code());
    }

    #[tokio::test]
    async fn auth_malformed_credentials() {
        let server = build_auth_server().await;
        // Missing colon separator
        let credentials = BASE64_ENGINE.encode("userpassword");
        let res = server
            .get("/")
            .authorization(format!("Basic {credentials}"))
            .await;
        assert_eq!(401, res.status_code());
    }

    #[tokio::test]
    async fn auth_wrong_method() {
        let server = build_auth_server().await;
        let credentials = BASE64_ENGINE.encode("user:password");
        let res = server
            .get("/")
            .authorization(format!("Bearer {credentials}"))
            .await;
        assert_eq!(401, res.status_code());
    }

    #[tokio::test]
    async fn auth_wrong_password() {
        let server = build_auth_server().await;
        let credentials = BASE64_ENGINE.encode("user:wrongpassword");
        let res = server
            .get("/")
            .authorization(format!("Basic {credentials}"))
            .await;
        assert_eq!(401, res.status_code());
    }

    #[tokio::test]
    async fn auth_wrong_username() {
        let server = build_auth_server().await;
        let credentials = BASE64_ENGINE.encode("wronguser:password");
        let res = server
            .get("/")
            .authorization(format!("Basic {credentials}"))
            .await;
        assert_eq!(401, res.status_code());
    }

    #[tokio::test]
    async fn auth_no_credentials() {
        let server = build_auth_server().await;
        let res = server.get("/").await;
        assert_eq!(401, res.status_code());
        assert!(res.headers().get("www-authenticate").is_some());
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
