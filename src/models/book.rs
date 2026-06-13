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
