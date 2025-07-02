//! Middleware to use Cookie.

mod future;
mod layer;

pub use self::layer::{CookieManager, CookieManagerLayer};
