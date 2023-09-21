// https://github.com/EmbarkStudios/rust-ecosystem/blob/732513edfd9172f4eda358b2d0cefc6cad1585ee/lints.rs
#![deny(unsafe_code)]
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::fallible_impl_from,
    clippy::filter_map_next,
    clippy::flat_map_option,
    clippy::float_cmp_const,
    clippy::fn_params_excessive_bools,
    clippy::from_iter_instead_of_collect,
    clippy::if_let_mutex,
    clippy::implicit_clone,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::invalid_upcast_comparisons,
    clippy::large_digit_groups,
    clippy::large_stack_arrays,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::manual_ok_or,
    clippy::map_err_ignore,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wild_err_arm,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::missing_enforced_import_renames,
    clippy::mut_mut,
    clippy::mutex_integer,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::needless_for_each,
    clippy::option_option,
    clippy::path_buf_push_overwrite,
    clippy::ptr_as_ptr,
    clippy::rc_mutex,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_functions_in_if_condition,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::string_add,
    clippy::string_add_assign,
    clippy::string_lit_as_bytes,
    clippy::string_to_string,
    clippy::todo,
    clippy::trait_duplication_in_bounds,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::useless_transmute,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]

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
use rand::{seq::SliceRandom, thread_rng};
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
use uuid::Uuid;

const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const WATER_CSS: &str = include_str!("../assets/water.css");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
struct Cli {
    /// Bind host & port
    #[arg(long, short = 'b', env = "BIND", default_value = "127.0.0.1:8080")]
    bind: String,

    /// Debug mode
    #[arg(long, short = 'd', env = "DEBUG")]
    debug: bool,

    /// Data directory
    #[arg(long, env = "DATA_DIR")]
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
            id: Uuid::new_v4().to_string(),
            path,
        })
    }
}

#[derive(Clone, Debug)]
struct Book {
    cover: Page,
    name: String,
    pages: Vec<Page>,
    views: u128,
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
            views: 0,
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
    let books: Vec<Book> = fs::read_dir(&path)?
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
    let mut scan = BookScan {
        books,
        data_dir: path.as_ref().to_path_buf(),
        pages_map: HashMap::new(),
        scan_duration: Utc::now().signed_duration_since(scanned_at),
        scanned_at,
    };
    scan.reorder();
    Ok(scan)
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
    fn reorder(&mut self) {
        self.books
            .sort_by(|a, b| (a.views, &a.name).cmp(&(b.views, &b.name)));

        self.pages_map.clear();
        for (i, book) in self.books.iter().enumerate() {
            for (j, page) in book.pages.iter().enumerate() {
                self.pages_map.insert(page.id.clone(), (i, j));
            }
        }
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

#[derive(Deserialize)]
struct ShuffleQuery {
    name: Option<String>,
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

fn authenticate<B>(request: &Request<B>) -> AuthState {
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

async fn auth_middleware_fn<B>(request: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let authenticated = authenticate(&request);
    let response = next.run(request).await;
    match authenticated {
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

async fn index_route(State(state): State<AppState>) -> impl IntoResponse {
    state
        .scan
        .lock()
        .map_err(|e| {
            debug!("failed to render index {e:?}");
            e
        })
        .ok()
        .map(|scan| IndexTemplate {
            books: scan.books.clone(),
            books_count: scan.books.len(),
            scan_duration: scan.scan_duration.num_milliseconds(),
            scanned_at: scan.scanned_at.to_rfc2822(),
            version: VERSION.to_string(),
        })
        .map_or(
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())),
            |t| {
                t.render()
                    .map_err(|e| {
                        debug!("failed to render index {e:?}");
                        e
                    })
                    .ok()
                    .map_or(
                        (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())),
                        |rendered| (StatusCode::OK, Html(rendered)),
                    )
            },
        )
}

async fn show_book_route(
    State(state): State<AppState>,
    query: Query<BookQuery>,
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
            |mut scan| {
                scan.books
                    .iter_mut()
                    .find(|b| b.name == query.0.name)
                    .map(|book| {
                        book.views += 1;
                        BookTemplate {
                            book: book.clone(),
                            version: VERSION.to_string(),
                        }
                    })
                    .and_then(|t| {
                        t.render()
                            .map_err(|e| {
                                debug!("failed to render template {e:?}");
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
}

async fn rescan_books_route(State(state): State<AppState>) -> impl IntoResponse {
    state.scan.lock().map_or(Redirect::to("/"), |mut scan| {
        scan_books(&scan.data_dir)
            .map(|new_scan| {
                info!(
                    "finished re-scan in {}ms, {} book(s), {} page(s) found",
                    new_scan.scan_duration.num_milliseconds(),
                    new_scan.books.len(),
                    new_scan.pages_map.len()
                );
                *scan = new_scan;
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

async fn shuffle_book_route(
    State(state): State<AppState>,
    query: Query<ShuffleQuery>,
) -> impl IntoResponse {
    state.scan.lock().map_or(Redirect::to("/"), |mut scan| {
        scan.reorder();

        let n = (scan.books.len() as f64 * 0.1) as usize;
        let mut rng = thread_rng();
        scan.books
            .iter()
            .take(n.clamp(1, n))
            .map(|book| {
                let name = &book.name;
                let view_count = &book.views;
                debug!("book taken: {name} (view count: {view_count})");
                book
            })
            .filter(|b| Some(&b.name) != query.name.as_ref())
            .collect::<Vec<&Book>>()
            .choose(&mut rng)
            .map_or(Redirect::to("/"), |book| {
                let name = &book.name;
                debug!("pick {name}");

                let encoded = urlencoding::encode(name);
                Redirect::to(&format!("/book?name={encoded}"))
            })
    })
}

#[derive(Deserialize)]
struct DataQuery {
    id: String,
}

async fn show_page_route(
    State(state): State<AppState>,
    query: Query<DataQuery>,
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
            scan.pages_map.get(&query.id).and_then(|(b_idx, p_idx)| {
                scan.books
                    .get(*b_idx)
                    .and_then(|b| b.pages.get(*p_idx))
                    .and_then(|p| {
                        fs::read(&p.path)
                            .map_err(|e| {
                                debug!("failed to read page {e:?}");
                                e
                            })
                            .ok()
                    })
                    .map(|buf| (StatusCode::OK, buf))
            })
        })
        .unwrap_or((StatusCode::NOT_FOUND, Vec::new()))
}

async fn run_server<P: AsRef<Path>>(addr: SocketAddr, data_dir: P) -> MyResult<()> {
    let scan = scan_books(&data_dir)?;
    info!(
        "finished initial scan in {}ms, {} book(s), {} page(s) found",
        scan.scan_duration.num_milliseconds(),
        &scan.books.len(),
        scan.pages_map.len()
    );
    let state = AppState {
        scan: Arc::new(Mutex::new(scan)),
    };
    let app = Router::new()
        .route("/book", get(show_book_route))
        .route("/rescan", post(rescan_books_route))
        .route("/shuffle", post(shuffle_book_route))
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
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
                (headers, WATER_CSS)
            }),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);
    if get_expected_credentials().is_none() {
        warn!("no authrization enabled, server is publicly accessible");
    }
    info!("running on {addr}");
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
    let default_directive = if cli.debug {
        Level::DEBUG.into()
    } else {
        Level::INFO.into()
    };
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_directive)
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();

    let data_dir = cli.data_dir.unwrap_or(OsString::from("./data"));
    match &cli.command {
        Some(Commands::HashPassword { .. }) => {
            if let Err(e) = hash_password() {
                error!("failed to hash password: {e:?}");
            }
        }
        Some(Commands::List { .. }) => {
            let scan = match scan_books(&data_dir) {
                Err(e) => {
                    error!("failed to scan directory: {e:?}");
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
                &scan.pages_map.len(),
                scan.scan_duration.num_milliseconds()
            );
        }
        None => {
            let bind: SocketAddr = match cli.bind.parse() {
                Err(e) => {
                    error!("invalid host:port pair: {e:?}");
                    return;
                }
                Ok(b) => b,
            };
            if let Err(e) = run_server(bind, data_dir).await {
                error!("failed to start the server: {e:?}");
            };
        }
    };
}
