use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use http::StatusCode;
use rand::seq::IndexedRandom as _;

use crate::models::Book;
use crate::state::AppState;

pub async fn shuffle_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let book_id = {
        let locked = state.scan.read();
        let scan = match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
            Some(scan) => scan,
        };
        let mut rng = rand::rng();
        match scan.books.choose(&mut rng) {
            None => return Redirect::to("/").into_response(),
            Some(book) => book.id.clone(),
        }
    };
    Redirect::to(&format!("/book/{book_id}")).into_response()
}

pub async fn shuffle_book_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let book_id = {
        let locked = state.scan.read();
        let scan = match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
            Some(scan) => scan,
        };
        let mut rng = rand::rng();
        let filtered_books: Vec<&Book> = scan.books.iter().filter(|b| b.id != id).collect();
        match filtered_books.choose(&mut rng) {
            None => return Redirect::to("/").into_response(),
            Some(book) => book.id.clone(),
        }
    };
    Redirect::to(&format!("/book/{book_id}")).into_response()
}
