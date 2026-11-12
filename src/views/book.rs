use maud::{Markup, html};

use super::layout::{document, theme_button, title_suffix};
use crate::models::{Book, Page};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Paged,
    Scroll,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Paged => "paged",
            Self::Scroll => "scroll",
        }
    }
}

pub struct BookView<'a> {
    pub book: &'a Book,
    pub auth_enabled: bool,
    pub mode: Mode,
}

pub fn book_page(view: &BookView<'_>) -> Markup {
    let book = view.book;
    let title = format!(
        "{} ({}P) | {}",
        book.title,
        book.pages.len(),
        title_suffix()
    );
    let body = html! {
        body class="reader" data-mode=(view.mode.as_str()) {
            (topbar(view))
            div class="viewer" id="viewer" {
                div class="zone next" id="next" title="Next" data-testid="reader-next" { span {} }
                div class="zone prev" id="prev" title="Previous" data-testid="reader-prev" { span {} }
                div class="pages" id="pages" {
                    @for (index, page) in book.pages.iter().enumerate() {
                        (figure(view, page, index + 1))
                    }
                }
            }
            (rail(book))
        }
    };
    document(
        &title,
        "width=device-width, initial-scale=1, viewport-fit=cover",
        body,
    )
}

fn topbar(view: &BookView<'_>) -> Markup {
    let book = view.book;
    html! {
        div class="topbar" {
            a class="back" href="/" title="Home" aria-label="Home" { "←" }
            div class="titleblock" {
                div class="t" { (book.title) }
                // The live number is script-written, so it is hidden without a script;
                // `nojs-counter` states the page instead.
                div class="s" {
                    span class="js-only" { b id="cur" data-testid="reader-current" { "1" } " / " }
                    (book.pages.len()) " ページ"
                }
            }
            span class="grow" {}
            // Links, so the mode works without JavaScript; app.js switches in place.
            div class="seg" id="seg" {
                a href="?mode=paged" data-m="paged" class=(on(view.mode == Mode::Paged)) data-testid="reader-mode-paged" { "⇄ 翻頁" }
                a href="?mode=scroll" data-m="scroll" class=(on(view.mode == Mode::Scroll)) data-testid="reader-mode-scroll" { "↕ 捲動" }
            }
            (theme_button("iconbtn js-only"))
            form method="POST" action=(format!("/shuffle/{}", book.id)) {
                button class="tbtn" type="submit" { "Shuffle" }
            }
            @if view.auth_enabled {
                form method="POST" action="/logout" {
                    button class="tbtn" type="submit" data-testid="logout" { "Logout" }
                }
            }
        }
    }
}

fn on(active: bool) -> &'static str {
    if active { "on" } else { "" }
}

/// One page of the book. `number` is 1-based, like the ids and anchors.
fn figure(view: &BookView<'_>, page: &Page, number: usize) -> Markup {
    let total = view.book.pages.len();
    let is_first = number == 1;
    let is_last = number == total;
    // Server-rendered `is-current`, so page 1 shows without JavaScript.
    let class = if is_first { "pg is-current" } else { "pg" };
    html! {
        figure class=(class) id=(format!("p{number}")) data-p=(number) {
            img src=(format!("/data/{}", page.id)) alt=(page.filename) loading="lazy";
            // Script-less paging, per page because the shared tap zones cannot
            // know the current page; `:target` picks the one to show. Right-to-
            // left like the zones: next sits on the left.
            nav class="nojs" {
                @if !is_last {
                    a class="nojs-next" href=(format!("#p{}", number + 1)) rel="next" aria-label="Next page" { "‹" }
                }
                @if !is_first {
                    a class="nojs-prev" href=(format!("#p{}", number - 1)) rel="prev" aria-label="Previous page" { "›" }
                }
                span class="nojs-counter" { (number) " / " (total) }
                // Per page, so switching keeps your place; the only link here that
                // shows in scroll mode.
                @if view.mode == Mode::Paged {
                    a class="nojs-mode" href=(format!("?mode=scroll#p{number}")) { "↕ 捲動" }
                } @else {
                    a class="nojs-mode" href=(format!("?mode=paged#p{number}")) { "⇄ 翻頁" }
                }
            }
        }
    }
}

fn rail(book: &Book) -> Markup {
    html! {
        div class="rail" {
            span class="counter" { b id="cur2" { "1" } " / " (book.pages.len()) }
            div class="progress" { i id="bar" {} }
            div class="thumbs" id="thumbs" {
                @for (index, page) in book.pages.iter().enumerate() {
                    // A link, so the rail works without a script; app.js animates instead.
                    a href=(format!("#p{}", index + 1)) data-p=(index + 1) title=(format!("第{}頁", index + 1)) {
                        img src=(format!("/thumb/sm/{}", page.id)) alt="" loading="lazy";
                    }
                }
            }
        }
    }
}
