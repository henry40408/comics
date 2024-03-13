use std::net::{AddrParseError, SocketAddr};

use clap::Parser;
use comics::{hash_password, run_server, scan_books, Cli, Commands};
use tracing::{error, Level};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

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
    let span_events = env_filter.max_level_hint().map_or(FmtSpan::CLOSE, |l| {
        if l >= Level::DEBUG {
            FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        }
    });
    tracing_subscriber::fmt()
        .with_ansi(!cli.no_color)
        .with_env_filter(env_filter)
        .with_span_events(span_events)
        .with_target(false)
        .compact()
        .init();

    match &cli.command {
        Some(Commands::HashPassword { .. }) => {
            if let Err(e) = hash_password() {
                error!(err = e.to_string(), "failed to hash password");
            }
        }
        Some(Commands::List { .. }) => {
            let scan = match scan_books(&cli.data_dir) {
                Err(e) => {
                    error!(err = e.to_string(), "failed to scan directory");
                    return;
                }
                Ok(b) => b,
            };
            for book in &scan.books {
                println!("{} ({}P)", book.title, book.pages.len());
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
                    let e: AddrParseError = e;
                    error!(
                        bind = cli.bind,
                        err = e.to_string(),
                        "invalid host:port pair"
                    );
                    return;
                }
                Ok(b) => b,
            };
            if let Err(e) = run_server(bind, &cli).await {
                error!(err = e.to_string(), "failed to start the server");
            };
        }
    };
}
