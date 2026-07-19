use std::sync::Arc;

use askama::Template;
use axum::{
    extract::State,
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
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    books: &'a Vec<Book>,
    scan_duration: f64,
    scanned_at: String,
    version: &'static str,
    assets_version: &'static str,
    auth_enabled: bool,
}

pub async fn index_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Hold read lock through render — template render is pure CPU, no await
    let locked = state.scan.read();
    let Some(scan) = locked.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new()));
    };
    let t = IndexTemplate {
        books: &scan.books,
        scan_duration: scan.scan_duration.num_milliseconds() as f64,
        scanned_at: scan.scanned_at.to_rfc2822(),
        version: VERSION,
        assets_version: assets_version(),
        auth_enabled: matches!(state.auth_config, AuthConfig::Some { .. }),
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
