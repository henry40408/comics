#![deny(clippy::pedantic, clippy::perf)]

use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, Request},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use base64::{engine::GeneralPurpose, Engine};
use clap::{Parser, Subcommand};
use hyper::StatusCode;
use serde::Deserialize;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tower_http::{
    services::ServeDir,
    trace::{self, TraceLayer},
};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::EnvFilter;

const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;
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

fn strip_dot_prefix<P: AsRef<Path>>(prefix: P, path: P) -> MyResult<PathBuf> {
    path.as_ref()
        .strip_prefix(prefix)
        .map(PathBuf::from)
        .map_err(MyError::StripPrefixError)
}

#[derive(Clone, Debug)]
struct Page {
    filename: String,
    path: String,
    relative_path: String,
}

impl Page {
    fn new<P: AsRef<Path>>(prefix: P, path: P) -> MyResult<Self> {
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

        let prefix_ref = prefix.as_ref();
        let relative_path = strip_dot_prefix(prefix_ref, path_ref)
            .map(|p| p.to_str().map(ToString::to_string))?
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;

        let filename = path_ref
            .file_name()
            .and_then(|s| s.to_str().map(ToString::to_string))
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;
        Ok(Page {
            filename,
            path,
            relative_path,
        })
    }
}

#[derive(Clone, Debug)]
struct Book {
    cover: Page,
    filename: String,
    pages: Vec<Page>,
}

impl Book {
    fn new<P: AsRef<Path>>(prefix: P, path: P) -> Result<Self, MyError> {
        let path_ref = path.as_ref();
        if !path_ref.is_dir() {
            return Err(MyError::NotDirectory(path_ref.to_path_buf()));
        }

        let pages = list_pages(prefix.as_ref(), path_ref)?;
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
            filename,
            pages,
        })
    }
}

fn list_pages<P: AsRef<Path>>(prefix: P, path: P) -> MyResult<Vec<Page>> {
    let mut pages: Vec<Page> = fs::read_dir(&path)?
        .filter_map(|entry| {
            if entry.is_err() {
                debug!("skip because {:?}", entry);
            }
            Result::ok(entry)
        })
        .filter_map(|entry| {
            let page = Page::new(prefix.as_ref(), entry.path().as_path());
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

fn list_books<P: AsRef<Path>>(prefix: P, path: P) -> MyResult<Vec<Book>> {
    let mut books: Vec<Book> = fs::read_dir(&path)?
        .filter_map(|entry| {
            if entry.is_err() {
                debug!("skip because {:?}", entry);
            }
            Result::ok(entry)
        })
        .filter_map(|entry| {
            debug!("found a directory: {}", entry.path().to_string_lossy());
            let book = Book::new(prefix.as_ref(), entry.path().as_path());
            if let Err(ref e) = book {
                debug!("{}", e);
            }
            Result::ok(book)
        })
        .map(|book| {
            debug!("found a book {} ({}P)", &book.filename, &book.pages.len());
            book
        })
        .collect();
    books.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(books)
}

#[derive(Clone)]
struct AppState {
    scan: Arc<Mutex<BookScan>>,
}

#[derive(Clone)]
struct BookScan {
    books: Vec<Book>,
    scan_duration: Duration,
}

#[derive(Clone, Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    books: Vec<Book>,
    books_count: usize,
    scan_duration: u128,
    version: String,
}

#[derive(Deserialize)]
struct BookQuery {
    filename: String,
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
                scan_duration: scan.scan_duration.as_millis(),
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
            let book = match scan.books.iter().find(|b| b.filename == query.filename) {
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

async fn run_server<P: AsRef<Path>>(addr: SocketAddr, data_dir: P) -> MyResult<()> {
    let start = Instant::now();
    let books = list_books(&data_dir, &data_dir)?;
    let scan_duration = start.elapsed();
    info!(
        "finished initial scan in {} ms, {} book(s) found",
        scan_duration.as_millis(),
        books.len()
    );
    let state = AppState {
        scan: Arc::new(Mutex::new(BookScan {
            books,
            scan_duration,
        })),
    };
    let app = Router::new()
        .nest_service("/data", ServeDir::new(&data_dir))
        .route("/book", get(show_book_route))
        .route("/", get(index_route))
        .route_layer(middleware::from_fn(auth_middleware_fn))
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
            let books = match list_books(&data_dir, &data_dir) {
                Err(e) => {
                    error!("failed to scan directory: {}", e);
                    return;
                }
                Ok(b) => b,
            };
            for book in &books {
                println!("{} ({}P)", book.filename, book.pages.len());
            }
            println!("{} book(s)", books.len());
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
