use std::sync::OnceLock;

use crate::models::hash_string;

/// Stylesheet served at `/assets/app.css`, embedded at compile time.
pub const APP_CSS: &str = include_str!("../vendor/assets/app.css");

/// Script served at `/assets/app.js`, embedded at compile time.
pub const APP_JS: &str = include_str!("../vendor/assets/app.js");

/// Content-derived fingerprint for the bundled assets.
///
/// Appended to asset URLs as a `?v=` query so they can be served with a
/// long-lived immutable `Cache-Control`: the value changes whenever the CSS or
/// JS changes, busting the cache exactly when needed and never otherwise.
pub fn assets_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            let mut combined = String::with_capacity(APP_CSS.len() + APP_JS.len());
            combined.push_str(APP_CSS);
            combined.push_str(APP_JS);
            hash_string(0, &combined)
        })
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_stable_and_hex() {
        assert_eq!(assets_version(), assets_version());
        assert!(!assets_version().is_empty());
        assert!(assets_version().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
