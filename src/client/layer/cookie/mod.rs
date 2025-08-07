//! Middleware to use Cookie.

mod future;
mod layer;

pub use self::layer::{CookieService, CookieServiceLayer};
