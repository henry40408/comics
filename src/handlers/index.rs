use std::sync::Arc;

use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use http::StatusCode;
use tracing::error;

use crate::models::Book;
use crate::state::AppState;

pub const VERSION: &str = env!("APP_VERSION");

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    books: &'a Vec<Book>,
    scan_duration: f64,
    scanned_at: String,
    version: &'static str,
}

pub async fn index_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Copy needed data while holding lock, release before rendering
    let (books, scan_duration, scanned_at) = {
        let locked = state.scan.lock();
        match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())),
            Some(scan) => (
                scan.books.clone(),
                scan.scan_duration.num_milliseconds() as f64,
                scan.scanned_at.to_rfc2822(),
            ),
        }
    };
    let t = IndexTemplate {
        books: &books,
        scan_duration,
        scanned_at,
        version: VERSION,
    };
    let rendered = match t.render() {
        Ok(html) => html,
        Err(err) => {
            error!(%err, "failed to render index");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };
    (StatusCode::OK, Html(rendered))
}
