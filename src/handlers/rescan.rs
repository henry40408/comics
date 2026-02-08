use std::sync::Arc;

use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tracing::{error, info};

use crate::models::scan_books;
use crate::state::AppState;

pub async fn rescan_books_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut locked = state.scan.lock();
    let scan_result = scan_books(state.seed, state.data_dir.as_path());
    let new_scan = match scan_result {
        Ok(scan) => scan,
        Err(err) => {
            error!(%err, "failed to re-scan books");
            return Redirect::to("/");
        }
    };
    let books = new_scan.books.len();
    let pages = new_scan.pages_map.len();
    let ms = new_scan.scan_duration.num_milliseconds();
    info!(books, pages, ms, "finished re-scan");
    *locked = Some(new_scan);
    Redirect::to("/")
}
