use std::sync::OnceLock;

use xxhash_rust::xxh3::Xxh3;

pub const APP_CSS: &str = include_str!("../vendor/assets/app.css");

pub const APP_JS: &str = include_str!("../vendor/assets/app.js");

pub const FAVICON_SVG: &str = include_str!("../vendor/assets/favicon.svg");

/// Raster fallback for browsers that will not take the SVG favicon.
pub const FAVICON_PNG: &[u8] = include_bytes!("../vendor/assets/favicon-32.png");

/// Separate from the favicon because iOS does not accept SVG for the home screen.
pub const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("../vendor/assets/apple-touch-icon.png");

/// Appended to asset URLs as `?v=`, so they can be served immutable: the value
/// changes whenever any asset changes, busting the cache exactly then and never
/// otherwise.
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
