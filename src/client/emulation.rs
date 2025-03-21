use crate::{Http1Config, Http2Config, TlsConfig};
use http::{HeaderMap, HeaderName};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// Trait defining the interface for providing an `EmulationProvider`.
///
/// The `EmulationProviderFactory` trait is designed to be implemented by types that can provide
/// an `EmulationProvider` instance. This trait abstracts the creation and configuration of
/// `EmulationProvider`, allowing different types to offer their own specific configurations.
///
/// # Example
///
/// ```rust
/// use rquest::{EmulationProviderFactory, EmulationProvider};
///
/// struct MyEmulationProvider;
///
/// impl EmulationProviderFactory for MyEmulationProvider {
///     fn emulation(self) -> EmulationProvider {
///         EmulationProvider::default()
///     }
/// }
///
/// let provider = MyEmulationProvider.emulation();
/// ```
pub trait EmulationProviderFactory {
    /// Provides an `EmulationProvider` instance.
    fn emulation(self) -> EmulationProvider;
}

/// HTTP connection context that manages both HTTP and TLS configurations.
///
/// The `EmulationProvider` provides a complete environment for HTTP connections,
/// including both HTTP-specific settings and the underlying TLS configuration.
/// This unified context ensures consistent behavior across connections.
///
/// # Components
///
/// - **TLS Configuration**: Manages secure connection settings.
/// - **HTTP Settings**: Controls HTTP/1 and HTTP/2 behaviors.
/// - **Header Management**: Handles default headers and their ordering.
///
/// # Example
///
/// ```rust
/// use rquest::EmulationProvider;
/// use rquest::TlsConfig;
///
/// let provider = EmulationProvider::builder()
///     .tls_config(TlsConfig::default())
///     .build();
/// ```
#[derive(TypedBuilder, Default, Debug)]
pub struct EmulationProvider {
    /// TLS configuration for secure connections.
    #[builder(setter(into))]
    pub(crate) tls_config: Option<TlsConfig>,

    /// HTTP/1 connection settings.
    #[builder(default, setter(into))]
    pub(crate) http1_config: Option<Http1Config>,

    /// HTTP/2 connection settings.
    #[builder(default, setter(into))]
    pub(crate) http2_config: Option<Http2Config>,

    /// Default headers for all requests.
    #[builder(default, setter(into))]
    pub(crate) default_headers: Option<HeaderMap>,

    /// Header ordering for requests.
    #[builder(default, setter(strip_option, into))]
    pub(crate) headers_order: Option<Cow<'static, [HeaderName]>>,
}

/// Implement `EmulationProviderFactory` for `EmulationProvider`.
///
/// This implementation allows an `EmulationProvider` to be used wherever an
/// `EmulationProviderFactory` is required, providing a default emulation configuration.
impl EmulationProviderFactory for EmulationProvider {
    fn emulation(self) -> EmulationProvider {
        self
    }
}
