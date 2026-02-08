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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_id_display() {
        let id = BookId("abc123".to_string());
        assert_eq!(format!("{}", id), "abc123");
    }

    #[test]
    fn book_id_from_string() {
        let id: BookId = String::from("test").into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn book_id_as_ref() {
        let id = BookId("hello".to_string());
        let s: &str = id.as_ref();
        assert_eq!(s, "hello");
    }

    #[test]
    fn page_id_display() {
        let id = PageId("page123".to_string());
        assert_eq!(format!("{}", id), "page123");
    }

    #[test]
    fn page_id_from_string() {
        let id: PageId = String::from("page").into();
        assert_eq!(id.0, "page");
    }

    #[test]
    fn page_id_as_ref() {
        let id = PageId("world".to_string());
        let s: &str = id.as_ref();
        assert_eq!(s, "world");
    }

    #[test]
    fn hash_string_deterministic() {
        let hash1 = hash_string(42, "test");
        let hash2 = hash_string(42, "test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_string_different_seeds() {
        let hash1 = hash_string(1, "test");
        let hash2 = hash_string(2, "test");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_string_different_inputs() {
        let hash1 = hash_string(42, "hello");
        let hash2 = hash_string(42, "world");
        assert_ne!(hash1, hash2);
    }
}
