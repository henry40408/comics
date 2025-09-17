use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    net::SocketAddr,
    path::{self, PathBuf},
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use askama::Template;
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use base64::{Engine as _, engine::GeneralPurpose};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use http::{StatusCode, header};
use imsz::ImInfo;
use parking_lot::Mutex;
use rand::seq::IndexedMutRandom as _;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::oneshot::{self, Sender},
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, Span, debug, error, field, info, trace_span, warn};
use tracing_subscriber::{
    EnvFilter, Layer as _, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};
use xxhash_rust::xxh3::Xxh3;

const BCRYPT_COST: u32 = 11u32;
const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;
const VERSION: &str = env!("APP_VERSION");
const WATER_CSS: &str = include_str!("../vendor/assets/water.css");

type SingleHeader = [(header::HeaderName, &'static str); 1];
const CSS_HEADER: SingleHeader = [(header::CONTENT_TYPE, "text/css")];
const WWW_AUTHENTICATE_HEADER: SingleHeader = [(header::WWW_AUTHENTICATE, "Basic realm=comics")];

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

#[derive(Clone, Debug)]
struct Dimension {
    height: u64,
    width: u64,
}

impl From<&ImInfo> for Dimension {
    fn from(value: &ImInfo) -> Self {
        Self {
            height: value.height,
            width: value.width,
        }
    }
}

#[derive(Clone, Debug)]
struct Page {
    filename: String,
    id: String,
    path: String,
    dimension: Dimension,
}

fn hash_string<S: AsRef<str>>(seed: u64, s: S) -> String {
    let mut hasher = Xxh3::with_seed(seed);
    hasher.update(s.as_ref().as_bytes());
    format!("{:x}", hasher.digest())
}

impl Page {
    fn new(seed: u64, path: &path::Path) -> anyhow::Result<Self> {
        if !path.is_file() {
            bail!("Not a file: {}", path.display());
        }
        let filename = path
            .file_name()
            .and_then(|s| s.to_str().map(|s| s.to_string()))
            .with_context(|| format!("Invalid path: {}", path.display()))?;
        let path_str = path.to_string_lossy().to_string();
        let dimension = Dimension::from(&imsz::imsz(path)?);
        Ok(Page {
            filename,
            id: hash_string(seed, &path_str),
            path: path_str,
            dimension,
        })
    }
}

#[derive(Debug)]
struct Book {
    cover: Page,
    id: String,
    title: String,
    pages: Vec<Page>,
}

impl Book {
    fn new(span: &Span, seed: u64, path: &path::Path) -> anyhow::Result<Self> {
        let span = trace_span!(parent: span, "scan book", ?path).entered();
        if !path.is_dir() {
            bail!("Not a directory: {}", path.display());
        }
        let pages = scan_pages(&span, seed, path)?;
        let cover = pages
            .first()
            .with_context(|| format!("Empty directory: {}", path.display()))?;
        let title = path
            .file_name()
            .and_then(|s| s.to_str().map(|s| s.to_string()))
            .with_context(|| format!("Invalid path: {}", path.display()))?;
        Ok(Book {
            cover: cover.clone(),
            id: hash_string(seed, &title),
            title,
            pages,
        })
    }
}

fn scan_pages(span: &Span, seed: u64, book_path: &path::Path) -> anyhow::Result<Vec<Page>> {
    let s = trace_span!(parent: span, "scan pages", ?book_path, pages = field::Empty).entered();
    let entries: Vec<_> = fs::read_dir(book_path)?.collect();
    let mut pages: Vec<Page> = entries
        .into_par_iter()
        .filter_map(|entry| {
            if let Err(ref err) = entry {
                error!(%err, "skip file");
            }
            entry.ok()
        })
        .filter_map(|entry| {
            let path = entry.path();
            let page = Page::new(seed, &path);
            if let Err(ref err) = page {
                error!(%err, ?path, "failed to create page");
            }
            page.ok()
        })
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    s.record("pages", pages.len());
    Ok(pages)
}

fn scan_books(seed: u64, data_path: &path::Path) -> anyhow::Result<BookScan> {
    let span = trace_span!("scan books").entered();
    let scanned_at = Utc::now();
    let entries: Vec<_> = fs::read_dir(data_path)?.collect();
    let mut books: Vec<Book> = entries
        .into_par_iter()
        .filter_map(|entry| {
            if let Err(ref err) = entry {
                error!(%err, "skip directory");
            }
            entry.ok()
        })
        .filter_map(|entry| {
            let path = entry.path();
            let book = Book::new(&span, seed, path.as_path());
            if let Err(err) = &book {
                error!(%err, "failed to create book");
            };
            book.ok()
        })
        .collect();
    books.sort_by(|a, b| a.title.cmp(&b.title));
    let mut pages_map = HashMap::new();
    for book in books.iter() {
        for page in book.pages.iter() {
            pages_map.insert(page.id.clone(), page.clone());
        }
    }
    Ok(BookScan {
        books,
        pages_map,
        scan_duration: Utc::now().signed_duration_since(scanned_at),
        scanned_at,
    })
}

#[derive(Clone)]
enum AuthConfig {
    None,
    Some {
        username: String,
        password_hash: String,
    },
}

#[derive(Clone)]
struct AppState {
    auth_confg: AuthConfig,
    data_dir: PathBuf,
    scan: Arc<Mutex<Option<BookScan>>>,
    seed: u64,
}

#[derive(Debug)]
struct BookScan {
    books: Vec<Book>,
    pages_map: HashMap<String, Page>,
    scan_duration: Duration,
    scanned_at: DateTime<Utc>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    books: &'a Vec<Book>,
    scan_duration: f64,
    scanned_at: String,
    version: &'static str,
}

#[derive(Template)]
#[template(path = "book.html")]
struct BookTemplate<'a> {
    book: &'a Book,
    version: &'static str,
}

enum AuthState {
    Public,
    Request,
    Success,
    Failed,
}

fn authenticate(state: &Arc<AppState>, request: &Request) -> anyhow::Result<AuthState> {
    let (expected_username, expected_password) = match &state.auth_confg {
        AuthConfig::None => return Ok(AuthState::Public),
        AuthConfig::Some {
            username,
            password_hash,
        } => (username, password_hash),
    };
    let header_value = match request.headers().get(header::AUTHORIZATION) {
        None => return Ok(AuthState::Request),
        Some(v) => v,
    };
    let header_str = header_value.to_str()?;
    let parts: Vec<&str> = header_str.split_ascii_whitespace().collect();
    let digest = match (parts.first().map(|s| s.to_ascii_lowercase()), parts.get(1)) {
        (Some(scheme), Some(digest)) if scheme == "basic" => digest,
        _ => return Ok(AuthState::Failed),
    };
    let decoded = BASE64_ENGINE.decode(digest)?;
    let decoded_str = String::from_utf8(decoded)?;
    let actual: Vec<String> = decoded_str.split(':').map(|s| s.to_string()).collect();
    let (username, password) = match (actual.first(), actual.get(1)) {
        (Some(u), Some(p)) if **u == *expected_username => (u, p),
        _ => return Ok(AuthState::Failed),
    };
    match (
        **username == *expected_username,
        bcrypt::verify(&**password, expected_password),
    ) {
        (true, Ok(true)) => Ok(AuthState::Success),
        (true, Ok(false)) | (false, _) => Ok(AuthState::Failed),
        (true, Err(err)) => {
            error!(?err, "failed to verify password");
            bail!("Bcrypt error: {err}")
        }
    }
}

async fn auth_middleware_fn(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    match authenticate(&state, &request) {
        Ok(AuthState::Public | AuthState::Success) => next.run(request).await,
        Ok(AuthState::Failed) => StatusCode::UNAUTHORIZED.into_response(),
        Ok(AuthState::Request) => {
            (StatusCode::UNAUTHORIZED, WWW_AUTHENTICATE_HEADER, "").into_response()
        }
        Err(err) => {
            error!(%err, "failed to authenticate");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn index_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let locked = state.scan.lock();
    let scan = match locked.as_ref() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
        Some(scan) => scan,
    };
    let t = IndexTemplate {
        books: &scan.books,
        scan_duration: scan.scan_duration.num_milliseconds() as f64,
        scanned_at: scan.scanned_at.to_rfc2822(),
        version: VERSION,
    };
    let rendered = match t.render() {
        Ok(html) => html,
        Err(err) => {
            error!(%err, "faile to render index");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };
    (StatusCode::OK, Html(rendered))
}

async fn show_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let locked = state.scan.lock();
    let scan = match locked.as_ref() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
        Some(scan) => scan,
    };
    let book = match scan.books.iter().find(|b| b.id == id) {
        None => return (StatusCode::NOT_FOUND, Html("not found".to_string())),
        Some(book) => book,
    };
    let template = BookTemplate {
        book,
        version: VERSION,
    };
    let rendered = match template.render() {
        Ok(html) => html,
        Err(err) => {
            error!(%err, "failed to render book");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };
    (StatusCode::OK, Html(rendered))
}

async fn rescan_books_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut locked = state.scan.lock();
    let scan_result = scan_books(state.seed, state.data_dir.as_path());
    if let Err(err) = scan_result {
        error!(%err, "failed to re-scan books");
        return Redirect::to("/");
    }
    let new_scan = scan_result.unwrap();
    let books = new_scan.books.len();
    let pages = new_scan.pages_map.len();
    let ms = new_scan.scan_duration.num_milliseconds();
    info!(books, pages, ms, "finished re-scan");
    *locked = Some(new_scan);
    Redirect::to("/")
}

async fn shuffle_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut locked = state.scan.lock();
    let scan = match locked.as_mut() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
        Some(scan) => scan,
    };
    let mut rng = rand::rng();
    let book = match scan.books.choose_mut(&mut rng) {
        None => return Redirect::to("/").into_response(),
        Some(book) => book,
    };
    let id = &book.id;
    Redirect::to(&format!("/book/{id}")).into_response()
}

async fn shuffle_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut locked = state.scan.lock();
    let scan = match locked.as_mut() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
        Some(scan) => scan,
    };
    let mut rng = rand::rng();
    let mut filtered_books: Vec<&Book> = scan.books.iter().filter(|b| b.id != id).collect();
    let random_book = match filtered_books.choose_mut(&mut rng) {
        None => return Redirect::to("/").into_response(),
        Some(book) => book,
    };
    Redirect::to(&format!("/book/{}", random_book.id)).into_response()
}

async fn show_page_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let locked = state.scan.lock();
    let scan = match locked.as_ref() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
        Some(scan) => scan,
    };
    let page = match scan.pages_map.get(&*id) {
        None => return (StatusCode::NOT_FOUND, Vec::new()).into_response(),
        Some(page) => page,
    };
    let content = match fs::read(&*page.path) {
        Ok(content) => content,
        Err(err) => {
            error!(%err, "failed to read page");
            return (StatusCode::NOT_FOUND, Vec::new()).into_response();
        }
    };
    (StatusCode::OK, content).into_response()
}

#[derive(Deserialize, Serialize)]
struct Healthz {
    scanned_at: i64,
}

async fn healthz_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let locked = state.scan.lock();
    let scan = match locked.as_ref() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(())).into_response(),
        Some(scan) => scan,
    };
    Json(Healthz {
        scanned_at: scan.scanned_at.timestamp_millis(),
    })
    .into_response()
}

fn init_route(opts: &Opts, tx: Sender<()>) -> anyhow::Result<Router> {
    let data_dir = &opts.data_dir;

    let seed = opts.seed.unwrap_or_else(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        warn!(%seed, "no seed provided, use seconds since UNIX epoch as seed");
        seed
    });
    let state = Arc::new(AppState {
        auth_confg: match (opts.auth_username.clone(), opts.auth_password_hash.clone()) {
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
    use crate::{BASE64_ENGINE, BCRYPT_COST, Opts, init_route};
    use axum_test::TestServer;
    use base64::Engine;
    use clap::Parser as _;
    use tokio::sync::oneshot;

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
}
