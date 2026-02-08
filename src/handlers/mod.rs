mod book;
mod health;
mod index;
mod page;
mod rescan;
mod shuffle;

pub use book::show_book_route;
pub use health::{healthz_route, Healthz};
pub use index::index_route;
pub use page::show_page_route;
pub use rescan::rescan_books_route;
pub use shuffle::{shuffle_book_route, shuffle_route};
