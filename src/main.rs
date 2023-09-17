#![deny(clippy::pedantic, clippy::perf)]

use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap},
    response::Html,
    routing::get,
    Router,
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{self, Path, PathBuf},
};
use thiserror::Error;
use tower_http::{
    services::ServeDir,
    trace::{self, TraceLayer},
};
use tracing::{debug, error, info, Level};
use tracing_subscriber::EnvFilter;

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
    books: Vec<Book>,
}

#[derive(Clone, Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    books: Vec<Book>,
    books_count: usize,
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

async fn run_server<P: AsRef<Path>>(addr: SocketAddr, data_dir: P) -> MyResult<()> {
    let books = list_books(&data_dir, &data_dir)?;
    let state = AppState { books };
    let app = Router::new()
        .route("/healthz", get(|| async { "" }))
        .route(
            "/assets/water.css",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, "text/css".parse().unwrap());
                (headers, WATER_CSS)
            }),
        )
        .nest_service("/data", ServeDir::new(&data_dir))
        .route(
            "/book",
            get(
                |State(state): State<AppState>, query: Query<BookQuery>| async {
                    let books = state.books;
                    let query = query.0;
                    let book = match books.iter().find(|b| b.filename == query.filename) {
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
                },
            ),
        )
        .route(
            "/",
            get(|State(state): State<AppState>| async {
                let books_count = state.books.len();
                let books = state.books;
                let t = IndexTemplate {
                    books,
                    books_count,
                    version: VERSION.to_string(),
                };
                Html(match t.render() {
                    Ok(t) => t,
                    Err(e) => {
                        error!("failed to render template {:?}", e);
                        String::new()
                    }
                })
            }),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);
    info!("running on {:?}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn hash_password() -> MyResult<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Password (again): ")?;
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
