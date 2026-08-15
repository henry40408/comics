//! Browser E2E support for comics: the server under test, the browser session,
//! and the page objects the Cucumber steps drive.

pub mod browser;
pub mod pages;
pub mod server;
pub mod wait;
pub mod world;

pub use server::Server;
