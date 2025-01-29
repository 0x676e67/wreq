use crate::{Http1Config, Http2Config, TlsConfig};
use http::{HeaderMap, HeaderName};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// Trait defining the interface for providing an `HttpContext`.
///
/// The `HttpContextProvider` trait is designed to be implemented by types that can provide
/// an `HttpContext` instance. This trait abstracts the creation and configuration of
/// `HttpContext`, allowing different types to offer their own specific configurations.
pub trait HttpContextProvider {
    /// Provides an `HttpContext` instance.
    fn context(self) -> HttpContext;
}

/// HTTP connection context that manages both HTTP and TLS configurations.
///
/// The `HttpContext` provides a complete environment for HTTP connections,
/// including both HTTP-specific settings and the underlying TLS configuration.
/// This unified context ensures consistent behavior across connections.
///
/// # Components
///
/// - **TLS Configuration**: Manages secure connection settings
/// - **HTTP Settings**: Controls HTTP/1 and HTTP/2 behaviors
/// - **Header Management**: Handles default headers and their ordering
#[derive(TypedBuilder, Default, Debug)]
pub struct HttpContext {
    /// TLS configuration for secure connections
    #[builder(setter(into))]
    pub(crate) tls_config: TlsConfig,

    /// HTTP/1 connection settings
    #[builder(default, setter(into))]
    pub(crate) http1_config: Option<Http1Config>,

    /// HTTP/2 connection settings
    #[builder(default, setter(into))]
    pub(crate) http2_config: Option<Http2Config>,

    /// Default headers for all requests
    #[builder(default, setter(into))]
    pub(crate) default_headers: Option<HeaderMap>,

    /// Header ordering for requests
    #[builder(default, setter(strip_option, into))]
    pub(crate) headers_order: Option<Cow<'static, [HeaderName]>>,
}

/// Implement `HttpContextProvider` for `HttpContext`.
impl HttpContextProvider for HttpContext {
    fn context(self) -> HttpContext {
        self
    }
}
