use std::fmt;

use xxhash_rust::xxh3::Xxh3;

/// Newtype wrapper for book IDs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BookId(pub String);

impl fmt::Display for BookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for BookId {
    fn from(s: String) -> Self {
        BookId(s)
    }
}

impl AsRef<str> for BookId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Newtype wrapper for page IDs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PageId(pub String);

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PageId {
    fn from(s: String) -> Self {
        PageId(s)
    }
}

impl AsRef<str> for PageId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Hash a string with a seed to generate an ID
pub fn hash_string<S: AsRef<str>>(seed: u64, s: S) -> String {
    let mut hasher = Xxh3::with_seed(seed);
    hasher.update(s.as_ref().as_bytes());
    format!("{:x}", hasher.digest())
}
