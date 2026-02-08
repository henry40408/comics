use std::path;

use anyhow::{Context, bail};
use imsz::ImInfo;
use tracing::{Span, trace_span};

use super::ids::hash_string;
use super::scan::scan_pages;

/// Image dimensions
#[derive(Clone, Debug)]
pub struct Dimension {
    pub height: u64,
    pub width: u64,
}

impl From<&ImInfo> for Dimension {
    fn from(value: &ImInfo) -> Self {
        Self {
            height: value.height,
            width: value.width,
        }
    }
}

/// A single page in a book
#[derive(Clone, Debug)]
pub struct Page {
    pub filename: String,
    pub id: String,
    pub path: String,
    pub dimension: Dimension,
}

impl Page {
    pub fn new(seed: u64, path: &path::Path) -> anyhow::Result<Self> {
        if !path.is_file() {
            bail!("Not a file: {}", path.display());
        }
        let filename = path
            .file_name()
            .and_then(|s| s.to_str().map(|s| s.to_string()))
            .with_context(|| format!("Invalid path: {}", path.display()))?;
        let path_str = path.to_string_lossy().to_string();
        let dimension = Dimension::from(&imsz::imsz(path)?);
        Ok(Page {
            filename,
            id: hash_string(seed, &path_str),
            path: path_str,
            dimension,
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
