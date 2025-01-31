use std::net::SocketAddr;

use clap::Parser;
use comics::{hash_password, run_server, scan_books, Cli, Commands};
use tracing::{error, Level};
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer as _,
};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(&cli);

    match &cli.command {
        Some(Commands::HashPassword { .. }) => {
            if let Err(err) = hash_password() {
                error!(%err, "failed to hash password");
            }
        }
        Some(Commands::List { .. }) => {
            use std::io::Write as _;
            let seed = 0u64; // dummy salt
            let scan = match scan_books(seed, &cli.data_dir) {
                Err(err) => {
                    error!(%err, "failed to scan directory");
                    return;
                }
                Ok(b) => b,
            };
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
            let bind: SocketAddr = match cli.bind.parse() {
                Err(err) => {
                    let bind = cli.bind;
                    error!(bind, %err, "invalid host:port pair");
                    return;
                }
                Ok(b) => b,
            };
            if let Err(err) = run_server(bind, &cli).await {
                error!(%err, "failed to start the server");
            };
        }
    };
}

fn init_tracing(cli: &Cli) {
    let default_directive = if cli.debug { Level::DEBUG } else { Level::INFO };
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
    let layer = match cli.log_format {
        comics::LogFormat::Full => layer.with_filter(env_filter).boxed(),
        comics::LogFormat::Compact => layer.compact().with_filter(env_filter).boxed(),
        comics::LogFormat::Pretty => layer.pretty().with_filter(env_filter).boxed(),
        comics::LogFormat::Json => layer.json().with_filter(env_filter).boxed(),
    };
    tracing_subscriber::registry().with(layer).init();
}
