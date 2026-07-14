//! HTTP cookie storage and request selection.
//!
//! [`Jar`] stores cookies received through `Set-Cookie` response fields and selects the cookies
//! that apply to later requests. Domain, path, security, and expiration checks follow the
//! [RFC 6265 storage and retrieval model]. [`CookieStore`] can be implemented to provide another
//! storage backend while keeping the same client integration.
//!
//! [RFC 6265 storage and retrieval model]: https://www.rfc-editor.org/rfc/rfc6265.html#section-5

mod helper;
mod jar;
mod value;

use std::sync::Arc;

use http::{Uri, Version};

pub use self::{jar::Jar, value::Cookie};
use crate::header::HeaderValue;

/// Serialized `Cookie` field values selected for an outgoing request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Cookies {
    /// All cookie pairs combined into one field value.
    Compressed(HeaderValue),

    /// Each cookie pair stored as a separate field value.
    Uncompressed(Vec<HeaderValue>),

    /// No cookie applies to the request.
    Empty,
}

/// Thread-safe cookie storage used by [`crate::Client`].
///
/// Implementors receive `Set-Cookie` response fields through [`set_cookies`](Self::set_cookies)
/// and produce `Cookie` request fields through [`cookies`](Self::cookies). Implementations are
/// responsible for applying the [RFC 6265 storage and retrieval model].
///
/// [RFC 6265 storage and retrieval model]: https://www.rfc-editor.org/rfc/rfc6265.html#section-5
pub trait CookieStore: Send + Sync {
    /// Stores `Set-Cookie` field values received from `uri`.
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri);

    /// Serializes the cookies that apply to `uri` for the requested HTTP version.
    ///
    /// HTTP/1.1 combines cookie pairs into one field value using the format from
    /// [RFC 6265 section 5.4]. HTTP/2 and HTTP/3 may split them across field lines to improve
    /// compression, as described by [RFC 9113 section 8.2.3] and [RFC 9114 section 4.2.1].
    ///
    /// [RFC 6265 section 5.4]: https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4
    /// [RFC 9113 section 8.2.3]: https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3
    /// [RFC 9114 section 4.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.1
    fn cookies(&self, uri: &Uri, version: Version) -> Cookies;
}

/// Converts cookie stores into a shared [`CookieStore`].
pub trait IntoCookieStore {
    /// Converts this value into a shared cookie store.
    fn into_shared(self) -> Arc<dyn CookieStore>;
}

impl IntoCookieStore for Arc<dyn CookieStore> {
    #[inline]
    fn into_shared(self) -> Arc<dyn CookieStore> {
        self
    }
}

impl<S: CookieStore + 'static> IntoCookieStore for Arc<S> {
    #[inline]
    fn into_shared(self) -> Arc<dyn CookieStore> {
        self
    }
}

impl<S: CookieStore + 'static> IntoCookieStore for S {
    #[inline]
    fn into_shared(self) -> Arc<dyn CookieStore> {
        Arc::new(self)
    }
}

impl_request_config_value!(Arc<dyn CookieStore>);

/// Converts cookie-like values into an owned [`Cookie`].
///
/// String implementations return `None` when the value cannot be parsed as a `Set-Cookie` value.
pub trait IntoCookie {
    /// Converts this value into an optional owned [`Cookie`].
    fn into_cookie(self) -> Option<Cookie<'static>>;
}

impl IntoCookie for Cookie<'_> {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        Some(self.into_owned())
    }
}

impl IntoCookie for cookie::Cookie<'_> {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        Some(Cookie::from(self.into_owned()))
    }
}

impl IntoCookie for &str {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        cookie::Cookie::parse(self)
            .map(|cookie| Cookie::from(cookie.into_owned()))
            .ok()
    }
}

impl IntoCookie for String {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        cookie::Cookie::parse(self).map(Cookie::from).ok()
    }
}
