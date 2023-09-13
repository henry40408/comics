use std::{ffi::OsString, fs, path::Path};

use clap::{Parser, Subcommand};

const WATER_CSS: &'static str = include_str!("../assets/water.css");

#[derive(Parser, Debug)]
#[command(author, version, about,long_about=None)]
struct Cli {
    /// Data directory
    #[arg(long)]
    data_dir: Option<OsString>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List books
    List {},
}

#[derive(Debug)]
struct Page {
    path: String,
    name: String,
}

#[derive(Debug)]
struct Book {
    path: String,
    name: String,
    pages: Vec<Page>,
}

fn list_pages<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Page>> {
    let mut pages: Vec<Page> = fs::read_dir(&path)?
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .filter(|e| match infer::get_from_path(e.path()) {
            Ok(Some(inferred)) => inferred.matcher_type() == infer::MatcherType::Image,
            _ => false,
        })
        .map(|entry| Page {
            name: entry.file_name().to_string_lossy().to_string(),
            path: entry.path().to_string_lossy().to_string(),
        })
        .filter(|p| !p.path.is_empty())
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pages)
}

fn list_books<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Book>> {
    let mut books: Vec<Book> = fs::read_dir(&path)?
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|entry| Book {
            name: entry.file_name().to_string_lossy().to_string(),
            pages: list_pages(entry.path()).unwrap_or(vec![]),
            path: entry.path().to_string_lossy().to_string(),
        })
        .filter(|b| !b.path.is_empty())
        .collect();
    books.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(books)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::List { .. }) => {
            let data_dir = cli.data_dir.unwrap_or(OsString::from("./data"));
            let books = list_books(data_dir)?;
            for book in &books {
                println!("Book: {}", book.path);
                for page in &book.pages {
                    println!("Page: {}", page.path);
                }
            }
            println!("{} book(s)", books.len());
        }
        None => {}
    };
    Ok(())
}
