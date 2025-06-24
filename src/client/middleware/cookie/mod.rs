//! Middleware to use [\`CookieStore\`].

mod future;
mod layer;

pub use self::layer::{CookieManager, CookieManagerLayer};
