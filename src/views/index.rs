use maud::{Markup, html};

use super::layout::{document, theme_button, title_suffix};
use crate::VERSION;
use crate::models::Book;

pub struct IndexView<'a> {
    pub books: &'a [Book],
    pub scan_duration_ms: f64,
    /// Shown when scripting is off.
    pub scanned_at: String,
    /// The `datetime` attribute: RFC 2822 is not a valid HTML date-time value.
    pub scanned_at_iso: String,
    pub auth_enabled: bool,
}

pub fn index_page(view: &IndexView<'_>) -> Markup {
    let count = view.books.len();
    let title = format!("{count} book(s) | {}", title_suffix());
    let body = html! {
        body class="lib" {
            div class="layout" {
                (sidebar())
                main {
                    (header(view))
                    div class="rule" {}
                    (controls(view))
                    div class="grid" {
                        @for (index, book) in view.books.iter().enumerate() {
                            (card(book, index + 1))
                        }
                    }
                }
            }
        }
    };
    document(&title, "width=device-width, initial-scale=1", body)
}

fn sidebar() -> Markup {
    html! {
        aside {
            div class="mark" {}
            div class="spine" { "漫画書架" span class="en" { "／ COMICS" } }
            div class="asidebot" {
                (theme_button("themebtn js-only"))
                div class="ver" { (VERSION) }
            }
        }
    }
}

fn header(view: &IndexView<'_>) -> Markup {
    html! {
        div class="head" {
            h1 { "Library" span class="dot" { "." } }
            div class="stat" {
                div { b { (view.books.len()) } " volume(s)" }
                div {
                    "scanned "
                    time data-localtime datetime=(view.scanned_at_iso) { (view.scanned_at) }
                    " · "
                    time datetime=(format!("PT{}S", view.scan_duration_ms / 1000.0)) {
                        (view.scan_duration_ms) "ms"
                    }
                }
            }
        }
    }
}

fn controls(view: &IndexView<'_>) -> Markup {
    html! {
        div class="controls" {
            form method="POST" action="/rescan" {
                button class="lbtn" type="submit" { "Re-scan" }
            }
            form method="POST" action="/shuffle" {
                button class="lbtn key" type="submit" { "Shuffle" }
            }
            @if view.auth_enabled {
                form method="POST" action="/logout" {
                    button class="lbtn" type="submit" data-testid="logout" { "Logout" }
                }
            }
            span class="note" { "所蔵 " (view.books.len()) " 冊" }
        }
    }
}

fn card(book: &Book, number: usize) -> Markup {
    html! {
        a class="card" href=(format!("/book/{}", book.id)) data-testid="book-card" {
            div class="cover" {
                img src=(format!("/thumb/md/{}", book.cover.id)) alt=(book.title) loading="lazy";
                span class="idx" { (number) }
            }
            div class="info" {
                div class="t" data-testid="book-title" { (book.title) }
                div class="p" { (book.pages.len()) " pages" }
            }
        }
    }
}
