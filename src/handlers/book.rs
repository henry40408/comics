use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse},
};
use http::StatusCode;
use tracing::error;

use crate::VERSION;
use crate::assets::assets_version;
use crate::auth::AuthConfig;
use crate::models::Book;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "book.html")]
struct BookTemplate<'a> {
    book: &'a Book,
    version: &'static str,
    assets_version: &'static str,
    auth_enabled: bool,
}

pub async fn show_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Hold read lock through render — template render is pure CPU, no await
    let locked = state.scan.read();
    let Some(scan) = locked.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new()));
    };
    let Some(book) = scan.books_map.get(&id).and_then(|&idx| scan.books.get(idx)) else {
        return (StatusCode::NOT_FOUND, Html(String::from("not found")));
    };
    let template = BookTemplate {
        book,
        version: VERSION,
        assets_version: assets_version(),
        auth_enabled: matches!(state.auth_config, AuthConfig::Some { .. }),
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
