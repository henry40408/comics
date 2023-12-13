use askama::Template;
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::GeneralPurpose, Engine};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{self, PathBuf},
    sync::{Arc, Mutex},
    thread,
};
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::trace::{self, TraceLayer};
use tracing::{debug, error, info, warn, Level};
use uuid::Uuid;

const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const WATER_CSS: &str = include_str!("../assets/water.css");

type SingleHeader = [(header::HeaderName, &'static str); 1];
const CSS_HEADER: SingleHeader = [(header::CONTENT_TYPE, "text/css")];
const WWW_AUTHENTICATE_HEADER: SingleHeader = [(header::WWW_AUTHENTICATE, "Basic realm=comics")];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
pub struct Cli {
    /// Bind host & port
    #[arg(long, short = 'b', env = "BIND", default_value = "127.0.0.1:8080")]
    pub bind: String,

    /// Debug mode
    #[arg(long, short = 'd', env = "DEBUG")]
    pub debug: bool,

    /// Data directory
    #[arg(long, env = "DATA_DIR", default_value = "./data")]
    pub data_dir: OsString,

    /// No color https://no-color.org/
    #[arg(long, env = "NO_COLOR")]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Hash password
    #[command()]
    HashPassword {},
    /// List books
    #[command(alias = "ls")]
    List {},
}

#[derive(Debug, Error)]
pub enum MyError {
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("directory is empty: {0}")]
    EmptyDirectory(PathBuf),
    #[error("image error: {0}")]
    ImageError(#[from] image::ImageError),
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
    #[error("failed to strip prefix")]
    StripPrefixError(#[from] path::StripPrefixError),
}

type MyResult<T> = Result<T, MyError>;

#[derive(Clone, Debug)]
pub struct Page {
    pub filename: String,
    pub id: String,
    pub path: String,
    // (width, height)
    pub dimensions: (u32, u32),
}

impl Page {
    fn new<P: AsRef<path::Path>>(path: P) -> MyResult<Self> {
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
        let dimensions = image::image_dimensions(path_ref)?;
        Ok(Page {
            filename,
            id: Uuid::new_v4().to_string(),
            path,
            dimensions,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Book {
    pub cover: Page,
    pub id: String,
    pub title: String,
    pub pages: Vec<Page>,
}

impl Book {
    fn new<P: AsRef<path::Path>>(path: P) -> Result<Self, MyError> {
        let path_ref = path.as_ref();
        if !path_ref.is_dir() {
            return Err(MyError::NotDirectory(path_ref.to_path_buf()));
        }

        let pages = scan_pages(path_ref)?;
        let cover = pages
            .first()
            .map(Clone::clone)
            .ok_or(MyError::EmptyDirectory(path_ref.to_path_buf()))?;

        let title = path_ref
            .file_name()
            .and_then(|s| s.to_str().map(ToString::to_string))
            .ok_or(MyError::InvalidPath(path_ref.to_path_buf()))?;
        Ok(Book {
            cover,
            id: blake3::hash(title.as_bytes()).to_string(),
            title,
            pages,
        })
    }
}

fn scan_pages<P: AsRef<path::Path>>(path: P) -> MyResult<Vec<Page>> {
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

pub fn scan_books<P: AsRef<path::Path>>(path: P) -> MyResult<BookScan> {
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
            debug!("found a book {} ({}P)", &book.title, &book.pages.len());
            book
        })
        .collect();
    books.sort_by(|a, b| a.title.cmp(&b.title));
    let mut pages_map = HashMap::new();
    for book in books.iter() {
        for page in book.pages.iter() {
            pages_map.insert(page.id.clone(), page.clone());
        }
    }
    let scan = BookScan {
        books,
        pages_map,
        scan_duration: Utc::now().signed_duration_since(scanned_at),
        scanned_at,
    };
    Ok(scan)
}

#[derive(Clone)]
struct AppState {
    data_dir: OsString,
    scan: Arc<Mutex<Option<BookScan>>>,
}

#[derive(Clone, Debug)]
pub struct BookScan {
    pub books: Vec<Book>,
    pub pages_map: HashMap<String, Page>,
    pub scan_duration: Duration,
    pub scanned_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    books: Vec<Book>,
    books_count: usize,
    scan_duration: f64,
    scanned_at: String,
    version: String,
}

#[derive(Clone, Template)]
#[template(path = "book.html")]
struct BookTemplate {
    book: Book,
    version: String,
}

fn get_expected_credentials() -> Option<(String, String)> {
    std::env::var("AUTH_USERNAME")
        .ok()
        .and_then(|u| std::env::var("AUTH_PASSWORD_HASH").ok().map(|p| (u, p)))
}

enum AuthState {
    Public,
    Request,
    Success,
    Failed,
}

fn authenticate(request: &Request) -> AuthState {
    let expected = match get_expected_credentials() {
        None => {
            debug!("authentication is disabled");
            return AuthState::Public;
        }
        Some(e) => e,
    };

    let header_value = request.headers().get("authorization");
    if header_value.is_none() {
        debug!("request authentication");
        return AuthState::Request;
    }

    header_value
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split_ascii_whitespace().collect::<Vec<&str>>())
        .and_then(|splitted| {
            match (
                splitted.first().map(|s| s.to_ascii_lowercase()),
                splitted.get(1).copied(),
            ) {
                (Some(ref scheme), Some(digest)) if scheme == "basic" => Some(digest),
                _ => None,
            }
        })
        .and_then(|digest| BASE64_ENGINE.decode(digest).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .map(|decoded| {
            decoded
                .split(':')
                .map(String::from)
                .collect::<Vec<String>>()
        })
        .map_or(AuthState::Failed, |splitted| {
            match (splitted.first(), splitted.get(1)) {
                (Some(u), Some(p)) if u == &expected.0 => bcrypt::verify(p, &expected.1)
                    .ok()
                    .map_or(AuthState::Failed, |matched| {
                        if matched {
                            debug!("authenticated");
                            AuthState::Success
                        } else {
                            debug!("password mismatched");
                            AuthState::Failed
                        }
                    }),
                _ => {
                    debug!("username mismatched");
                    AuthState::Failed
                }
            }
        })
}

async fn auth_middleware_fn(request: Request, next: Next) -> impl IntoResponse {
    let authenticated = authenticate(&request);
    let response = next.run(request).await;
    match authenticated {
        AuthState::Public | AuthState::Success => response,
        AuthState::Failed => StatusCode::UNAUTHORIZED.into_response(),
        AuthState::Request => {
            (StatusCode::UNAUTHORIZED, WWW_AUTHENTICATE_HEADER, "").into_response()
        }
    }
}

async fn index_route(State(state): State<AppState>) -> impl IntoResponse {
    state
        .scan
        .lock()
        .map_err(|e| {
            debug!("failed to render index {e:?}");
            e
        })
        .ok()
        .map_or(
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())),
            |scan| {
                scan.clone()
                    .map(|scan| IndexTemplate {
                        books: scan.books.clone(),
                        books_count: scan.books.len(),
                        scan_duration: scan.scan_duration.num_milliseconds() as f64,
                        scanned_at: scan.scanned_at.to_rfc2822(),
                        version: VERSION.to_string(),
                    })
                    .and_then(|t| {
                        t.render()
                            .map_err(|e| {
                                debug!("failed to render index {e:?}");
                                e
                            })
                            .ok()
                    })
                    .map_or(
                        (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
                        |rendered| (StatusCode::OK, Html(rendered)),
                    )
            },
        )
}

async fn show_book_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state
        .scan
        .lock()
        .map_err(|e| {
            debug!("failed to render book {e:?}");
            e
        })
        .map_or(
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())),
            |scan| {
                scan.clone().map_or(
                    (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
                    |scan| {
                        scan.books
                            .iter()
                            .find(|b| b.id == id)
                            .map(|book| BookTemplate {
                                book: book.clone(),
                                version: VERSION.to_string(),
                            })
                            .and_then(|t| {
                                t.render()
                                    .map_err(|e| {
                                        debug!("failed to render book {e:?}");
                                        e
                                    })
                                    .ok()
                            })
                            .map_or(
                                (StatusCode::NOT_FOUND, Html("not found".to_string())),
                                |rendered| (StatusCode::OK, Html(rendered)),
                            )
                    },
                )
            },
        )
}

async fn rescan_books_route(State(state): State<AppState>) -> impl IntoResponse {
    state.scan.lock().map_or(Redirect::to("/"), |mut scan| {
        scan_books(&state.data_dir)
            .map(|new_scan| {
                info!(
                    "finished re-scan in {}ms, {} book(s), {} page(s) found",
                    new_scan.scan_duration.num_milliseconds(),
                    new_scan.books.len(),
                    new_scan.pages_map.len()
                );
                *scan = Some(new_scan);
                Redirect::to("/")
            })
            .map_err(|e| {
                debug!("failed to re-scan books {e:?}");
                e
            })
            .ok()
            .unwrap_or(Redirect::to("/"))
    })
}

async fn shuffle_route(State(state): State<AppState>) -> impl IntoResponse {
    state.scan.lock().map_or(Redirect::to("/"), |scan| {
        scan.clone().map_or(Redirect::to("/"), |scan| {
            let mut rng = thread_rng();
            scan.books
                .iter()
                .map(|book| {
                    let name = &book.title;
                    debug!("book taken: {name}");
                    book
                })
                .collect::<Vec<&Book>>()
                .choose(&mut rng)
                .map_or(Redirect::to("/"), |book| {
                    let name = &book.title;
                    debug!("pick {name}");

                    let id = &book.id;
                    Redirect::to(&format!("/book/{id}"))
                })
        })
    })
}

async fn shuffle_book_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.scan.lock().map_or(Redirect::to("/"), |scan| {
        scan.clone().map_or(Redirect::to("/"), |scan| {
            let mut rng = thread_rng();
            scan.books
                .iter()
                .filter(|b| b.id != id)
                .map(|book| {
                    let name = &book.title;
                    debug!("book taken: {name}");
                    book
                })
                .collect::<Vec<&Book>>()
                .choose(&mut rng)
                .map_or(Redirect::to("/"), |book| {
                    let name = &book.title;
                    debug!("pick {name}");

                    let id = &book.id;
                    Redirect::to(&format!("/book/{id}"))
                })
        })
    })
}

async fn show_page_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state
        .scan
        .lock()
        .map_err(|e| {
            debug!("failed to render page {e:?}");
            e
        })
        .ok()
        .and_then(|scan| {
            scan.clone().map(|scan| {
                scan.pages_map
                    .get(&id)
                    .and_then(|page| {
                        fs::read(&page.path)
                            .map_err(|e| {
                                debug!("failed to read page {e:?}");
                                e
                            })
                            .ok()
                            .map(|content| (StatusCode::OK, content))
                    })
                    .unwrap_or((StatusCode::NOT_FOUND, Vec::new()))
            })
        })
        .unwrap_or((StatusCode::NOT_FOUND, Vec::new()))
}

#[derive(Deserialize, Serialize)]
pub struct Healthz {
    pub scanned_at: i64,
}

async fn healthz_route(State(state): State<AppState>) -> impl IntoResponse {
    state.scan.lock().map_or(Json(()).into_response(), |scan| {
        scan.clone().map_or(
            (StatusCode::SERVICE_UNAVAILABLE, Json(())).into_response(),
            |scan| {
                Json(Healthz {
                    scanned_at: scan.scanned_at.timestamp_millis(),
                })
                .into_response()
            },
        )
    })
}

pub fn init_route(cli: &Cli) -> MyResult<Router> {
    let data_dir = &cli.data_dir;

    let state = AppState {
        data_dir: data_dir.clone(),
        scan: Arc::new(Mutex::new(None)),
    };
    let state_clone = state.clone();

    let router = Router::new()
        .route("/book/:id", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/shuffle/:id", post(shuffle_book_route))
        .route("/shuffle", post(shuffle_route))
        .route("/", get(index_route))
        .route_layer(middleware::from_fn(auth_middleware_fn))
        // to prevent timing attack, bcrypt is too slow
        // protected by randomly-generated string as page ID instead
        .route("/data/:id", get(show_page_route))
        .route("/healthz", get(healthz_route))
        .route(
            "/assets/water.css",
            get(|| async { (CSS_HEADER, WATER_CSS) }),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    thread::spawn(move || {
        let data_dir = state_clone.data_dir;
        let new_scan = scan_books(data_dir).expect("initial scan failed");
        info!(
            "finished initial scan in {}ms, {} book(s), {} page(s) found",
            new_scan.scan_duration.num_milliseconds(),
            &new_scan.books.len(),
            new_scan.pages_map.len()
        );
        {
            let mut state = state_clone.scan.lock().unwrap();
            *state = Some(new_scan);
        }
    });

    Ok(router)
}

pub async fn run_server(addr: SocketAddr, cli: &Cli) -> MyResult<()> {
    let app = init_route(cli)?;
    if get_expected_credentials().is_none() {
        warn!("no authrization enabled, server is publicly accessible");
    }
    info!("running on {addr}");
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .await
        .expect("failed to start the server");
    Ok(())
}

pub fn hash_password() -> MyResult<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirmation: ")?;
    if password != confirmation {
        return Err(MyError::PasswordMismatched);
    }
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    println!("{hashed}");
    Ok(())
}
