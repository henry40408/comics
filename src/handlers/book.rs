use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse},
};
use http::StatusCode;
use tracing::error;

use crate::models::Book;
use crate::state::AppState;

use super::index::VERSION;

#[derive(Template)]
#[template(path = "book.html")]
struct BookTemplate<'a> {
    book: &'a Book,
    version: &'static str,
}

pub async fn show_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Copy book data while holding lock, release before rendering
    let book = {
        let locked = state.scan.lock();
        let scan = match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
            Some(scan) => scan,
        };
        match scan.books.iter().find(|b| b.id == id) {
            None => return (StatusCode::NOT_FOUND, Html(String::from("not found"))),
            Some(book) => book.clone(),
        }
    };
    let template = BookTemplate {
        book: &book,
        version: VERSION,
    };
    let rendered = match template.render() {
        Ok(html) => html,
        Err(err) => {
            error!(%err, "failed to render book");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };
    (StatusCode::OK, Html(rendered))
}
