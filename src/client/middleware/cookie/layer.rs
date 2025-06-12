use std::sync::Arc;
use tower::Layer;

use super::CookieManager;
use crate::cookie::CookieStore;

/// Layer to apply [`CookieManager`] middleware.
#[derive(Clone)]
pub struct CookieManagerLayer {
    cookie_store: Option<Arc<dyn CookieStore>>,
}

impl CookieManagerLayer {
    /// Create a new cookie manager layer.
    pub fn new(cookie_store: Option<Arc<dyn CookieStore + 'static>>) -> Self {
        Self { cookie_store }
    }
}

impl<S> Layer<S> for CookieManagerLayer {
    type Service = CookieManager<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieManager {
            inner,
            cookie_store: self.cookie_store.clone(),
        }
    }
}
