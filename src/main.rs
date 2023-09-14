use axum::{routing::get, Router};
use clap::{Parser, Subcommand};
use std::{ffi::OsString, fs, net::SocketAddr, path::Path};
use tower_http::{
    services::ServeDir,
    trace::{self, TraceLayer},
};
use tracing::{debug, info, Level};
use tracing_subscriber::EnvFilter;

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

#[derive(Debug)]
struct Page {
    path: String,
    name: String,
}

impl Page {
    fn is_valid(&self) -> bool {
        return !self.path.is_empty() && !self.name.is_empty();
    }
}

#[derive(Debug)]
struct Book {
    path: String,
    name: String,
    pages: Vec<Page>,
}

impl Book {
    fn is_valid(&self) -> bool {
        return !self.path.is_empty() && !self.path.is_empty() && !self.pages.is_empty();
    }
}

fn list_pages<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Page>> {
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
        .map(|entry| Page {
            name: entry.file_name().to_string_lossy().to_string(),
            path: entry.path().to_string_lossy().to_string(),
        })
        .filter(Page::is_valid)
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pages)
}

fn list_books<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Book>> {
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
        .map(|entry| Book {
            name: entry.file_name().to_string_lossy().to_string(),
            pages: list_pages(entry.path()).unwrap_or(vec![]),
            path: entry.path().to_string_lossy().to_string(),
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

async fn run_server(addr: SocketAddr) {
    let app = Router::new()
        .route("/healthz", get(|| async { "" }))
        .nest_service("/assets", ServeDir::new("assets"))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        );
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
    match &cli.command {
        Some(Commands::List { .. }) => {
            let data_dir = cli.data_dir.unwrap_or(OsString::from("./data"));
            let books = list_books(data_dir)?;
            for book in &books {
                println!("{} ({}P)", book.name, book.pages.len());
            }
            println!("{} book(s)", books.len());
        }
        Some(Commands::Serve { bind }) => {
            let bind: SocketAddr = bind.parse().expect("invalid host:port pair");
            run_server(bind).await
        }
        None => {}
    };
    Ok(())
}
