use maud::{DOCTYPE, Markup, html};

use crate::VERSION;
use crate::assets::assets_version;

/// The `<head>` every page shares.
///
/// `viewport` is a parameter because only the reader asks for
/// `viewport-fit=cover`.
pub fn head(title: &str, viewport: &str) -> Markup {
    let version = assets_version();
    html! {
        head {
            title { (title) }
            meta charset="UTF-8";
            meta name="viewport" content=(viewport);
            // Sets the theme before paint; not deferred, and not inline (see theme.js).
            script src=(format!("/assets/theme.js?v={version}")) {}
            link rel="preconnect" href="https://fonts.bunny.net";
            link href="https://fonts.bunny.net/css?family=hanken-grotesk:400,500,600|shippori-mincho:500,700" rel="stylesheet";
            link rel="icon" type="image/svg+xml" href=(format!("/favicon.svg?v={version}"));
            link rel="icon" type="image/png" sizes="32x32" href=(format!("/favicon-32.png?v={version}"));
            link rel="apple-touch-icon" href=(format!("/apple-touch-icon.png?v={version}"));
            link href=(format!("/assets/app.css?v={version}")) rel="stylesheet";
            script src=(format!("/assets/app.js?v={version}")) defer {}
        }
    }
}

/// A full document: doctype, `<html>`, the shared head, then `body`.
pub fn document(title: &str, viewport: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            (head(title, viewport))
            (body)
        }
    }
}

/// The title suffix every page carries.
pub fn title_suffix() -> String {
    format!("Comics {VERSION}")
}

/// The theme toggle, shown only with a script (`.js-only`).
///
/// Its `class` is the one thing that differs between pages.
pub fn theme_button(class: &str) -> Markup {
    html! {
        button class=(class) id="theme" type="button" title="Toggle theme" aria-label="Toggle theme" { "◐" }
    }
}
