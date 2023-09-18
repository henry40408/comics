#![deny(clippy::pedantic, clippy::perf)]

use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, Request},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::GeneralPurpose, Engine};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use hyper::StatusCode;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tower_http::trace::{self, TraceLayer};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::EnvFilter;

const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;
const PAGE_ID_LEN: usize = 10;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const WATER_CSS: &str = include_str!("../assets/water.css");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None, arg_required_else_help(true))]
struct Cli {
    /// Debug mode
    #[arg(long, short = 'd')]
    debug: bool,

    /// Data directory
    #[arg(long)]
    data_dir: Option<OsString>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Hash password
    #[command()]
    HashPassword {},
    /// List books
    #[command(alias = "ls")]
    List {},
    /// Serve books
    #[command(alias = "s")]
    Serve {
        /// Bind host & port
        #[arg(long, short = 'b', default_value = "127.0.0.1:8080")]
        bind: String,
    },
}

#[derive(Debug, Error)]
enum MyError {
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("directory is empty: {0}")]
    EmptyDirectory(PathBuf),
    #[error("invalid path: {0}")]
    InvalidPath(PathBuf),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("not a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("not a file: {0}")]
    NotFile(PathBuf),
    #[error("not an image: {0}")]
    NotImage(PathBuf),
    #[error("password mismatched")]
    PasswordMismatched,
    #[error("server error: {0}")]
    ServerError(#[from] hyper::Error),
    #[error("failed to strip prefix")]
    StripPrefixError(#[from] path::StripPrefixError),
}

type MyResult<T> = Result<T, MyError>;

#[derive(Clone, Debug)]
struct Page {
    filename: String,
    id: String,
    path: String,
}

fn generate_random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

impl Page {
    fn new<P: AsRef<Path>>(path: P) -> MyResult<Self> {
        let path_ref = path.as_ref();
        if !path_ref.is_file() {
            return Err(MyError::NotFile(path_ref.to_path_buf()));
        }

        let path = path_ref
            .to_str()
            .map(ToString::to_string)
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;

        let is_image = infer::get_from_path(path_ref)
            .ok()
            .is_some_and(|i| i.is_some_and(|i| i.matcher_type() == infer::MatcherType::Image));
        if !is_image {
            return Err(MyError::NotImage(path_ref.to_path_buf()));
        }

        let filename = path_ref
            .file_name()
            .and_then(|s| s.to_str().map(ToString::to_string))
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;
        Ok(Page {
            filename,
            id: generate_random_string(PAGE_ID_LEN),
            path,
        })
    }
}

#[derive(Clone, Debug)]
struct Book {
    cover: Page,
    name: String,
    pages: Vec<Page>,
}

impl Book {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self, MyError> {
        let path_ref = path.as_ref();
        if !path_ref.is_dir() {
            return Err(MyError::NotDirectory(path_ref.to_path_buf()));
        }

        let pages = scan_pages(path_ref)?;
        let cover = pages
            .first()
            .map(Clone::clone)
            .ok_or(MyError::EmptyDirectory(path_ref.to_path_buf()))?;

        let filename = path_ref
            .file_name()
            .and_then(|s| s.to_str().map(ToString::to_string))
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;

        Ok(Book {
            cover,
            name: filename,
            pages,
        })
    }
}

fn scan_pages<P: AsRef<Path>>(path: P) -> MyResult<Vec<Page>> {
    let mut pages: Vec<Page> = fs::read_dir(&path)?
        .filter_map(|entry| {
            if entry.is_err() {
                debug!("skip because {:?}", entry);
            }
            Result::ok(entry)
        })
        .filter_map(|entry| {
            let page = Page::new(entry.path().as_path());
            if let Err(ref e) = page {
                debug!("{}", e);
            }
            Result::ok(page)
        })
        .map(|page| {
            debug!("found a page {}", page.path);
            page
        })
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pages)
}

fn scan_books<P: AsRef<Path>>(path: P) -> MyResult<BookScan> {
    let scanned_at = Utc::now();
    let mut books: Vec<Book> = fs::read_dir(&path)?
        .filter_map(|entry| {
            if entry.is_err() {
                debug!("skip because {:?}", entry);
            }
            Result::ok(entry)
        })
        .filter_map(|entry| {
            debug!("found a directory: {}", entry.path().to_string_lossy());
            let book = Book::new(entry.path().as_path());
            if let Err(ref e) = book {
                debug!("{}", e);
            }
            Result::ok(book)
        })
        .map(|book| {
            debug!("found a book {} ({}P)", &book.name, &book.pages.len());
            book
        })
        .collect();
    books.sort_by(|a, b| a.name.cmp(&b.name));

    let mut pages_map = HashMap::new();
    for (i, book) in books.iter().enumerate() {
        for (j, page) in book.pages.iter().enumerate() {
            pages_map.insert(page.id.clone(), (i, j));
        }
    }

    Ok(BookScan {
        books,
        data_dir: path.as_ref().to_path_buf(),
        pages_map,
        scan_duration: Utc::now().signed_duration_since(scanned_at),
        scanned_at,
    })
}

#[derive(Clone)]
struct AppState {
    scan: Arc<Mutex<BookScan>>,
}

#[derive(Clone)]
struct BookScan {
    books: Vec<Book>,
    data_dir: PathBuf,
    pages_map: HashMap<String, (usize, usize)>,
    scan_duration: Duration,
    scanned_at: chrono::DateTime<Utc>,
}

impl BookScan {
    fn pages_count(&self) -> usize {
        self.books.iter().fold(0, |acc, b| acc + b.pages.len())
    }
}

#[derive(Clone, Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    books: Vec<Book>,
    books_count: usize,
    scan_duration: i64,
    scanned_at: String,
    version: String,
}

#[derive(Deserialize)]
struct BookQuery {
    name: String,
}

#[derive(Clone, Template)]
#[template(path = "book.html")]
struct BookTemplate {
    book: Book,
    version: String,
}

fn get_authorization() -> Option<(String, String)> {
    let username = std::env::var("AUTH_USERNAME").ok();
    let password_hash = std::env::var("AUTH_PASSWORD_HASH").ok();
    if let Some(username) = username {
        if let Some(password_hash) = password_hash {
            return Some((username, password_hash));
        }
    }
    None
}

enum AuthState {
    Public,
    Request,
    Success,
    Failed,
}

fn authorize<B>(request: &Request<B>) -> AuthState {
    if let Some(expected) = get_authorization() {
        debug!("authorization is enabled");
        if let Some(header_value) = request.headers().get("Authorization") {
            debug!("found authorization");
            if let Some((username, password)) = header_value
                .to_str()
                .ok()
                .and_then(|value| {
                    let splitted = value.split_ascii_whitespace().collect::<Vec<&str>>();
                    if let Some(scheme) = splitted.first() {
                        if "basic" == scheme.to_ascii_lowercase() {
                            if let Some(digest) = splitted.get(1) {
                                return Some((*digest).to_string());
                            }
                        }
                    }
                    None
                })
                .and_then(|digest| {
                    let decoded = BASE64_ENGINE.decode(digest).ok();
                    if let Some(decoded) = decoded {
                        if let Ok(decoded) = String::from_utf8(decoded) {
                            let splitted = decoded.split(':').collect::<Vec<&str>>();
                            if let Some(username) = splitted.first() {
                                if let Some(password) = splitted.get(1) {
                                    return Some((
                                        (*username).to_string(),
                                        (*password).to_string(),
                                    ));
                                }
                            }
                        }
                    }
                    None
                })
            {
                let matched = bcrypt::verify(password, &expected.1).unwrap_or(false);
                if expected.0 == username && matched {
                    debug!("authorized");
                    return AuthState::Success;
                }
                debug!("unauthorized");
                return AuthState::Failed;
            }
        }
        debug!("request authorzation");
        return AuthState::Request;
    }

    debug!("authentication is disabled");
    AuthState::Public
}

async fn auth_middleware_fn<B>(request: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let authorized = authorize(&request);
    let response = next.run(request).await;
    match authorized {
        AuthState::Public | AuthState::Success => Ok(response),
        AuthState::Failed => Err(StatusCode::UNAUTHORIZED),
        AuthState::Request => {
            let mut response = Response::default();
            response.headers_mut().insert(
                "WWW-Authenticate",
                HeaderValue::from_static("Basic realm=comics"),
            );
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            Ok(response)
        }
    }
}

#[allow(clippy::unused_async)]
async fn index_route(State(state): State<AppState>) -> impl IntoResponse {
    match state.scan.lock() {
        Err(e) => {
            error!("failed to render books {:?}", e);
            Html(String::new())
        }
        Ok(scan) => {
            let books_count = scan.books.len();
            let books = scan.books.clone();
            let t = IndexTemplate {
                books,
                books_count,
                scan_duration: scan.scan_duration.num_milliseconds(),
                scanned_at: scan.scanned_at.to_rfc2822(),
                version: VERSION.to_string(),
            };
            Html(match t.render() {
                Ok(t) => t,
                Err(e) => {
                    error!("failed to render template {:?}", e);
                    String::new()
                }
            })
        }
    }
}

#[allow(clippy::unused_async)]
async fn show_book_route(
    State(state): State<AppState>,
    query: Query<BookQuery>,
) -> impl IntoResponse {
    match state.scan.lock() {
        Err(e) => {
            error!("failed to render book {:?}", e);
            Html(String::new())
        }
        Ok(scan) => {
            let query = query.0;
            let book = match scan.books.iter().find(|b| b.name == query.name) {
                None => return Html("not found".to_string()),
                Some(b) => b,
            };
            let t = BookTemplate {
                book: book.clone(),
                version: VERSION.to_string(),
            };
            match t.render() {
                Ok(t) => Html(t),
                Err(e) => {
                    error!("failed to render template {:?}", e);
                    Html(String::new())
                }
            }
        }
    }
}

#[allow(clippy::unused_async)]
async fn rescan_books_route(State(state): State<AppState>) -> impl IntoResponse {
    match state.scan.lock() {
        Err(e) => {
            error!("failed to re-scan books {:?}", e);
            Redirect::to("/")
        }
        Ok(mut scan) => {
            let data_dir = &scan.data_dir;
            match scan_books(data_dir) {
                Err(e) => {
                    error!("failed to re-scan books {:?}", e);
                }
                Ok(new_scan) => {
                    info!(
                        "re-scan in {}ms, {} books found",
                        scan.scan_duration.num_milliseconds(),
                        scan.books.len()
                    );
                    *scan = new_scan;
                }
            }
            Redirect::to("/")
        }
    }
}

#[derive(Deserialize)]
struct DataQuery {
    id: String,
}

#[allow(clippy::unused_async)]
async fn show_page_route(
    State(state): State<AppState>,
    query: Query<DataQuery>,
) -> impl IntoResponse {
    state
        .scan
        .lock()
        .ok()
        .and_then(|scan| {
            scan.pages_map.get(&query.id).and_then(|(b_idx, p_idx)| {
                scan.books
                    .get(*b_idx)
                    .and_then(|b| b.pages.get(*p_idx))
                    .and_then(|p| fs::read(&p.path).ok())
                    .map(|buf| (StatusCode::OK, buf))
            })
        })
        .unwrap_or((StatusCode::NOT_FOUND, Vec::new()))
}

async fn run_server<P: AsRef<Path>>(addr: SocketAddr, data_dir: P) -> MyResult<()> {
    let scan = scan_books(&data_dir)?;
    info!(
        "finished initial scan in {} ms, {} book(s), {} page(s) found",
        scan.scan_duration.num_milliseconds(),
        &scan.books.len(),
        scan.pages_count()
    );
    let state = AppState {
        scan: Arc::new(Mutex::new(scan)),
    };
    let app = Router::new()
        .route("/book", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/", get(index_route))
        .route_layer(middleware::from_fn(auth_middleware_fn))
        // to prevent timing attack, bcrypt is too slow
        // protected by randomly-generated string as page ID instead
        .route("/data", get(show_page_route))
        .route("/healthz", get(|| async { "" }))
        .route(
            "/assets/water.css",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, "text/css".parse().unwrap());
                (headers, WATER_CSS)
            }),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);
    if get_authorization().is_none() {
        warn!("no authrization enabled, server is publicly accessible");
    }
    info!("running on {:?}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn hash_password() -> MyResult<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirmation: ")?;
    if password != confirmation {
        return Err(MyError::PasswordMismatched);
    }
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    println!("{hashed}");
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(if cli.debug {
                    Level::DEBUG.into()
                } else {
                    Level::INFO.into()
                })
                .from_env_lossy(),
        )
        .with_target(false)
        .compact()
        .init();

    let data_dir = cli.data_dir.unwrap_or(OsString::from("./data"));
    match &cli.command {
        Some(Commands::HashPassword { .. }) => {
            if let Err(e) = hash_password() {
                error!("failed to hash password: {}", e);
            }
        }
        Some(Commands::List { .. }) => {
            let scan = match scan_books(&data_dir) {
                Err(e) => {
                    error!("failed to scan directory: {}", e);
                    return;
                }
                Ok(b) => b,
            };
            for book in &scan.books {
                println!("{} ({}P)", book.name, book.pages.len());
            }
            println!(
                "{} book(s), {} page(s), scanned in {}ms",
                &scan.books.len(),
                &scan.pages_count(),
                scan.scan_duration.num_milliseconds()
            );
        }
        Some(Commands::Serve { bind }) => {
            let bind: SocketAddr = match bind.parse() {
                Err(e) => {
                    error!("invalid host:port pair: {:?}", e);
                    return;
                }
                Ok(b) => b,
            };
            if let Err(e) = run_server(bind, data_dir).await {
                error!("failed to start the server: {:?}", e);
            };
        }
        None => {}
    };
}
