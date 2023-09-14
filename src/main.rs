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
    path::{Path, PathBuf},
};
use tower_http::{
    services::ServeDir,
    trace::{self, TraceLayer},
};
use tracing::{debug, error, info, Level};
use tracing_subscriber::EnvFilter;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const WATER_CSS: &'static str = include_str!("../assets/water.css");

#[derive(Parser, Debug)]
#[command(author, version, about,long_about=None)]
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

#[derive(Clone, Debug)]
struct Page {
    name: String,
    path: String,
}

impl Page {
    fn is_valid(&self) -> bool {
        return !self.path.is_empty() && !self.name.is_empty();
    }
}

#[derive(Clone, Debug)]
struct Book {
    cover: Page,
    name: String,
    pages: Vec<Page>,
    path: String,
}

impl Book {
    fn is_valid(&self) -> bool {
        !self.path.is_empty() && !self.path.is_empty() && !self.pages.is_empty()
    }
}

fn list_pages<P: AsRef<Path>>(prefix: P, path: P) -> std::io::Result<Vec<Page>> {
    debug!("scan {}", &path.as_ref().to_string_lossy());
    let mut pages: Vec<Page> = fs::read_dir(&path)?
        .into_iter()
        .filter_map(|e| {
            if e.is_err() {
                debug!("skip a file {:?}", e)
            }
            Result::ok(e)
        })
        .filter(|e| match e.path().is_file() {
            true => {
                debug!("found a file {}", e.path().to_string_lossy());
                true
            }
            false => {
                debug!("skip a non-file {}", e.path().to_string_lossy());
                false
            }
        })
        .filter(|e| match infer::get_from_path(e.path()) {
            Ok(Some(inferred)) => {
                debug!("found an image {}", e.path().to_string_lossy());
                inferred.matcher_type() == infer::MatcherType::Image
            }
            _ => {
                debug!("skip a non-image {}", e.path().to_string_lossy());
                false
            }
        })
        .filter_map(
            |entry| match strip_dot_prefix(prefix.as_ref().to_path_buf(), entry.path()) {
                Some(p) => Some(Page {
                    name: entry.file_name().to_string_lossy().to_string(),
                    path: format!("/data/{}", p.to_string_lossy().to_string()),
                }),
                None => None,
            },
        )
        .filter(Page::is_valid)
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pages)
}

fn strip_dot_prefix<P: AsRef<Path>>(prefix: P, path: P) -> Option<PathBuf> {
    path.as_ref().strip_prefix(prefix).ok().map(PathBuf::from)
}

fn list_books<'a, P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Book>> {
    let mut books: Vec<Book> = fs::read_dir(&path)?
        .into_iter()
        .filter_map(|e| {
            if e.is_err() {
                debug!("skip {:?}", e);
            }
            Result::ok(e)
        })
        .filter(|e| match e.path().is_dir() {
            true => {
                debug!("find a directory {}", e.path().to_string_lossy());
                true
            }
            false => {
                debug!("skip a non-directory {}", e.path().to_string_lossy());
                false
            }
        })
        .filter_map(|entry| {
            let data_dir = &path.as_ref().to_path_buf();
            let book_path = &entry.path();

            let pages = list_pages(data_dir, book_path).unwrap_or(vec![]);
            if pages.is_empty() {
                return None;
            }

            match strip_dot_prefix(data_dir, book_path) {
                Some(p) => Some(Book {
                    cover: pages.first().unwrap().clone(),
                    name: entry.file_name().to_string_lossy().to_string(),
                    pages,
                    path: p.to_string_lossy().to_string(),
                }),
                None => None,
            }
        })
        .map(|b| {
            debug!("found a book {} ({}P)", &b.name, &b.pages.len());
            b
        })
        .filter(Book::is_valid)
        .collect();
    books.sort_by(|a, b| a.path.cmp(&b.path));
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
    name: String,
}

#[derive(Clone, Template)]
#[template(path = "book.html")]
struct BookTemplate {
    book: Book,
}

async fn run_server<P: AsRef<Path>>(addr: SocketAddr, data_dir: P) {
    let books = list_books(&data_dir).expect("failed to scan directory");
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
                    let book = match books.iter().find(|b| b.name == query.name) {
                        None => return Html("not found".to_string()),
                        Some(b) => b,
                    };
                    let t = BookTemplate { book: book.clone() };
                    match t.render() {
                        Ok(t) => Html(t),
                        Err(e) => {
                            error!("failed to render template {:?}", e);
                            Html("".to_string())
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
                        "".to_string()
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
        .await
        .expect("failed to run the server");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(match cli.debug {
                    true => Level::DEBUG.into(),
                    false => Level::INFO.into(),
                })
                .from_env_lossy(),
        )
        .with_target(false)
        .compact()
        .init();

    let data_dir = cli.data_dir.unwrap_or(OsString::from("./data"));
    match &cli.command {
        Some(Commands::List { .. }) => {
            let books = list_books(data_dir)?;
            for book in &books {
                println!("{} ({}P)", book.name, book.pages.len());
            }
            println!("{} book(s)", books.len());
        }
        Some(Commands::Serve { bind }) => {
            let bind: SocketAddr = bind.parse().expect("invalid host:port pair");
            run_server(bind, data_dir).await
        }
        None => {}
    };
    Ok(())
}
