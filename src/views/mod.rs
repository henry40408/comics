//! Page markup, one module per page. The handlers fetch the data; these only
//! turn it into HTML.

mod book;
mod index;
mod layout;
mod login;

pub use book::{BookView, Mode, book_page};
pub use index::{IndexView, index_page};
pub use login::{LoginView, login_page};
