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
    /// Maps a page id to its location as `(book index, page index)` into
    /// [`books`]. Storing the location instead of a cloned [`Page`] avoids
    /// duplicating every page's metadata strings — resolve to the owning page
    /// with [`BookScan::page_by_id`].
    pub pages_map: HashMap<String, (usize, usize)>,
    pub scan_duration: Duration,
    pub scanned_at: DateTime<Utc>,
}

impl BookScan {
    /// Resolve a page by its id in O(1) via [`pages_map`](Self::pages_map).
    #[must_use]
    pub fn page_by_id(&self, id: &str) -> Option<&Page> {
        let &(book_idx, page_idx) = self.pages_map.get(id)?;
        self.books.get(book_idx)?.pages.get(page_idx)
    }
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
            }
            book.ok()
        })
        .collect();
    books.sort_by(|a, b| a.title.cmp(&b.title));
    let total_pages: usize = books.iter().map(|b| b.pages.len()).sum();
    let mut pages_map = HashMap::with_capacity(total_pages);
    for (book_idx, book) in books.iter().enumerate() {
        for (page_idx, page) in book.pages.iter().enumerate() {
            pages_map.insert(page.id.clone(), (book_idx, page_idx));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn page_by_id_resolves_to_the_owning_page() {
        let dir = tempdir().unwrap();
        for (book, pages) in [
            ("Alpha", ["01.jpg", "02.jpg"]),
            ("Beta", ["01.png", "02.png"]),
        ] {
            let book_dir = dir.path().join(book);
            fs::create_dir(&book_dir).unwrap();
            for page in pages {
                fs::write(book_dir.join(page), b"x").unwrap();
            }
        }
        let scan = scan_books(1, dir.path()).unwrap();

        // Every page id resolves back to the exact page it was indexed from.
        for book in &scan.books {
            for page in &book.pages {
                let resolved = scan.page_by_id(&page.id).expect("id should resolve");
                assert_eq!(resolved.id, page.id);
                assert_eq!(resolved.path, page.path);
            }
        }
    }

    #[test]
    fn page_by_id_returns_none_for_unknown_id() {
        let dir = tempdir().unwrap();
        let book_dir = dir.path().join("Alpha");
        fs::create_dir(&book_dir).unwrap();
        fs::write(book_dir.join("01.jpg"), b"x").unwrap();
        let scan = scan_books(1, dir.path()).unwrap();

        assert!(scan.page_by_id("deadbeef").is_none());
    }
}
