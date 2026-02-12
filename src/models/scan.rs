use std::{collections::HashMap, fs, path};

use chrono::{DateTime, Duration, Utc};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use tracing::{Span, error, field, trace_span};

use super::book::{Book, Page};

/// Result of scanning books from the data directory
#[derive(Debug)]
pub struct BookScan {
    pub books: Vec<Book>,
    pub books_map: HashMap<String, usize>,
    pub pages_map: HashMap<String, Page>,
    pub scan_duration: Duration,
    pub scanned_at: DateTime<Utc>,
}

/// Scan pages in a book directory
pub fn scan_pages(span: &Span, seed: u64, book_path: &path::Path) -> anyhow::Result<Vec<Page>> {
    let s = trace_span!(parent: span, "scan pages", ?book_path, pages = field::Empty).entered();
    let entries: Vec<_> = fs::read_dir(book_path)?.collect();
    let mut pages: Vec<Page> = entries
        .into_par_iter()
        .filter_map(|entry| {
            if let Err(ref err) = entry {
                error!(%err, "skip file");
            }
            entry.ok()
        })
        .filter_map(|entry| {
            let path = entry.path();
            let page = Page::new(seed, &path);
            if let Err(ref err) = page {
                error!(%err, ?path, "failed to create page");
            }
            page.ok()
        })
        .collect();
    pages.sort_by(|a, b| a.path.cmp(&b.path));
    s.record("pages", pages.len());
    Ok(pages)
}

/// Scan all books in the data directory
pub fn scan_books(seed: u64, data_path: &path::Path) -> anyhow::Result<BookScan> {
    let span = trace_span!("scan books").entered();
    let scanned_at = Utc::now();
    let entries: Vec<_> = fs::read_dir(data_path)?.collect();
    let mut books: Vec<Book> = entries
        .into_par_iter()
        .filter_map(|entry| {
            if let Err(ref err) = entry {
                error!(%err, "skip directory");
            }
            entry.ok()
        })
        .filter_map(|entry| {
            let path = entry.path();
            let book = Book::new(&span, seed, path.as_path());
            if let Err(err) = &book {
                error!(%err, "failed to create book");
            };
            book.ok()
        })
        .collect();
    books.sort_by(|a, b| a.title.cmp(&b.title));
    let total_pages: usize = books.iter().map(|b| b.pages.len()).sum();
    let mut pages_map = HashMap::with_capacity(total_pages);
    for book in books.iter() {
        for page in book.pages.iter() {
            pages_map.insert(page.id.clone(), page.clone());
        }
    }
    let mut books_map = HashMap::with_capacity(books.len());
    for (idx, book) in books.iter().enumerate() {
        books_map.insert(book.id.clone(), idx);
    }
    Ok(BookScan {
        books,
        books_map,
        pages_map,
        scan_duration: Utc::now().signed_duration_since(scanned_at),
        scanned_at,
    })
}
