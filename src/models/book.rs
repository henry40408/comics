use std::path;

use anyhow::{Context, bail};
use tracing::{Span, trace_span};

use super::ids::hash_string;
use super::scan::scan_pages;

/// A single page in a book
#[derive(Clone, Debug)]
pub struct Page {
    pub filename: String,
    pub id: String,
    pub path: String,
}

impl Page {
    /// Build a page from its path. This performs no image I/O — dimensions are
    /// intentionally not read here so the initial scan only lists directories
    /// instead of opening every image (a big win on spinning disks).
    pub fn new(seed: u64, path: &path::Path) -> anyhow::Result<Self> {
        if !path.is_file() {
            bail!("Not a file: {}", path.display());
        }
        let filename = path
            .file_name()
            .and_then(|s| s.to_str().map(|s| s.to_string()))
            .with_context(|| format!("Invalid path: {}", path.display()))?;
        let path_str = path.to_string_lossy().to_string();
        Ok(Page {
            id: hash_string(seed, &path_str),
            filename,
            path: path_str,
        })
    }
}

/// A book containing multiple pages
#[derive(Clone, Debug)]
pub struct Book {
    pub cover: Page,
    pub id: String,
    pub title: String,
    pub pages: Vec<Page>,
}

impl Book {
    pub fn new(span: &Span, seed: u64, path: &path::Path) -> anyhow::Result<Self> {
        let span = trace_span!(parent: span, "scan book", ?path).entered();
        if !path.is_dir() {
            bail!("Not a directory: {}", path.display());
        }
        let pages = scan_pages(&span, seed, path)?;
        let cover = pages
            .first()
            .with_context(|| format!("Empty directory: {}", path.display()))?;
        let title = path
            .file_name()
            .and_then(|s| s.to_str().map(|s| s.to_string()))
            .with_context(|| format!("Invalid path: {}", path.display()))?;
        Ok(Book {
            cover: cover.clone(),
            id: hash_string(seed, &title),
            title,
            pages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tracing::trace_span;

    #[test]
    fn page_new_rejects_a_directory() {
        let dir = tempdir().unwrap();
        assert!(Page::new(0, dir.path()).is_err());
    }

    #[test]
    fn page_new_builds_from_a_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("01.jpg");
        fs::write(&path, b"data").unwrap();
        let page = Page::new(7, &path).unwrap();
        assert_eq!(page.filename, "01.jpg");
        assert!(!page.id.is_empty());
    }

    #[test]
    fn book_new_rejects_a_non_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("loose.txt");
        fs::write(&file, b"x").unwrap();
        assert!(Book::new(&trace_span!("test"), 0, &file).is_err());
    }

    #[test]
    fn book_new_rejects_an_empty_directory() {
        let dir = tempdir().unwrap();
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(Book::new(&trace_span!("test"), 0, &empty).is_err());
    }

    #[test]
    fn book_new_builds_with_sorted_pages() {
        let dir = tempdir().unwrap();
        let book = dir.path().join("My Book");
        fs::create_dir(&book).unwrap();
        fs::write(book.join("02.jpg"), b"x").unwrap();
        fs::write(book.join("01.jpg"), b"x").unwrap();
        let b = Book::new(&trace_span!("test"), 1, &book).unwrap();
        assert_eq!(b.title, "My Book");
        assert_eq!(b.pages.len(), 2);
        assert_eq!(b.cover.filename, "01.jpg");
    }
}
