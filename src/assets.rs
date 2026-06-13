use std::sync::OnceLock;

use xxhash_rust::xxh3::Xxh3;

/// Stylesheet served at `/assets/app.css`, embedded at compile time.
pub const APP_CSS: &str = include_str!("../vendor/assets/app.css");

/// Script served at `/assets/app.js`, embedded at compile time.
pub const APP_JS: &str = include_str!("../vendor/assets/app.js");

/// Scalable favicon served at `/favicon.svg` (modern browsers).
pub const FAVICON_SVG: &str = include_str!("../vendor/assets/favicon.svg");

/// Raster favicon served at `/favicon-32.png` (fallback).
pub const FAVICON_PNG: &[u8] = include_bytes!("../vendor/assets/favicon-32.png");

/// Home-screen icon served at `/apple-touch-icon.png` (iOS does not support SVG here).
pub const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("../vendor/assets/apple-touch-icon.png");

/// Content-derived fingerprint for the bundled assets.
///
/// Appended to asset URLs as a `?v=` query so they can be served with a
/// long-lived immutable `Cache-Control`: the value changes whenever any asset
/// changes, busting the cache exactly when needed and never otherwise.
pub fn assets_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            let mut hasher = Xxh3::with_seed(0);
            hasher.update(APP_CSS.as_bytes());
            hasher.update(APP_JS.as_bytes());
            hasher.update(FAVICON_SVG.as_bytes());
            hasher.update(FAVICON_PNG);
            hasher.update(APPLE_TOUCH_ICON_PNG);
            format!("{:x}", hasher.digest())
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
