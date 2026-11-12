use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse},
};
use http::StatusCode;
use serde::Deserialize;

use crate::auth::AuthConfig;
use crate::state::AppState;
use crate::views::{BookView, Mode, book_page};

/// Which layout the reader opens in (`?mode=paged|scroll`), so the mode switch
/// works without JavaScript. Anything unrecognised renders `paged` rather than
/// a 400.
#[derive(Deserialize)]
pub struct BookQuery {
    mode: Option<String>,
}

impl BookQuery {
    fn mode(&self) -> Mode {
        match self.mode.as_deref() {
            Some("scroll") => Mode::Scroll,
            _ => Mode::Paged,
        }
    }
}

pub async fn show_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<BookQuery>,
) -> impl IntoResponse {
    // Hold read lock through render — rendering is pure CPU, no await
    let locked = state.scan.read();
    let Some(scan) = locked.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new()));
    };
    let Some(book) = scan.books_map.get(&id).and_then(|&idx| scan.books.get(idx)) else {
        return (StatusCode::NOT_FOUND, Html(String::from("not found")));
    };
    let view = BookView {
        book,
        auth_enabled: matches!(state.auth_config, AuthConfig::Some { .. }),
        mode: query.mode(),
    };
    (StatusCode::OK, Html(book_page(&view).into_string()))
}
