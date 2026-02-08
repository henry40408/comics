use std::sync::Arc;

use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tracing::{error, info};

use crate::models::scan_books;
use crate::state::AppState;

pub async fn rescan_books_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let seed = state.seed;
    let data_dir = state.data_dir.clone();

    // Run blocking I/O on dedicated thread pool to avoid blocking async runtime
    let scan_result =
        tokio::task::spawn_blocking(move || scan_books(seed, data_dir.as_path())).await;

    let new_scan = match scan_result {
        Ok(Ok(scan)) => scan,
        Ok(Err(err)) => {
            error!(%err, "failed to re-scan books");
            return Redirect::to("/");
        }
        Err(err) => {
            error!(%err, "scan task panicked");
            return Redirect::to("/");
        }
    };

    let books = new_scan.books.len();
    let pages = new_scan.pages_map.len();
    let ms = new_scan.scan_duration.num_milliseconds();
    info!(books, pages, ms, "finished re-scan");

    *state.scan.lock() = Some(new_scan);
    Redirect::to("/")
}
