use http::HeaderMap;

use crate::{
    OriginalHeaders, core::client::config::TransportOptions, http1::Http1Options,
    http2::Http2Options, tls::TlsOptions,
};

/// Trait defining the interface for providing an `EmulationProvider`.
///
/// The `EmulationProviderFactory` trait is designed to be implemented by types that can provide
/// an `EmulationProvider` instance. This trait abstracts the creation and configuration of
/// `EmulationProvider`, allowing different types to offer their own specific configurations.
pub trait EmulationProviderFactory {
    /// Provides an `EmulationProvider` instance.
    fn emulation(self) -> EmulationProvider;
}

/// Builder for creating an `EmulationProvider`.
#[must_use]
#[derive(Debug)]
pub struct EmulationProviderBuilder {
    provider: EmulationProvider,
}

/// HTTP connection context that manages both HTTP and TLS configurations.
///
/// The `EmulationProvider` provides a complete environment for HTTP connections,
/// including both HTTP-specific settings and the underlying TLS configuration.
/// This unified context ensures consistent behavior across connections.
#[derive(Default, Debug)]
pub struct EmulationProvider {
    transport_options: Option<TransportOptions>,
    default_headers: Option<HeaderMap>,
    original_headers: Option<OriginalHeaders>,
}

impl EmulationProviderBuilder {
    /// Sets the TLS configuration for the `EmulationProvider`.
    pub fn with_tls<C>(mut self, config: C) -> Self
    where
        C: Into<Option<TlsOptions>>,
    {
        self.provider
            .transport_options
            .get_or_insert_with(TransportOptions::default)
            .configure_tls(config);
        self
    }

    /// Sets the HTTP/1 configuration for the `EmulationProvider`.
    pub fn with_config<C>(mut self, config: C) -> Self
    where
        C: Into<Option<Http1Options>>,
    {
        self.provider
            .transport_options
            .get_or_insert_with(TransportOptions::default)
            .configure_http1(config);
        self
    }

    /// Sets the HTTP/2 configuration for the `EmulationProvider`.
    pub fn with_http2<C>(mut self, config: C) -> Self
    where
        C: Into<Option<Http2Options>>,
    {
        self.provider
            .transport_options
            .get_or_insert_with(TransportOptions::default)
            .configure_http2(config);
        self
    }

    /// Sets the default headers for the `EmulationProvider`.
    pub fn with_headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<HeaderMap>>,
    {
        self.provider.default_headers = headers.into();
        self
    }

    /// Sets the original headers for the `EmulationProvider`.
    pub fn with_original_headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<OriginalHeaders>>,
    {
        self.provider.original_headers = headers.into();
        self
    }

    /// Builds the `EmulationProvider` instance.
    pub fn build(self) -> EmulationProvider {
        self.provider
    }
}

impl EmulationProvider {
    /// Creates a new `EmulationProviderBuilder`.
    ///
    /// # Returns
    ///
    /// Returns a new `EmulationProviderBuilder` instance.
    #[inline]
    pub fn builder() -> EmulationProviderBuilder {
        EmulationProviderBuilder {
            provider: EmulationProvider::default(),
        }
    }

    /// Decomposes the `EmulationProvider` into its components.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<TransportOptions>,
        Option<HeaderMap>,
        Option<OriginalHeaders>,
    ) {
        (
            self.transport_options,
            self.default_headers,
            self.original_headers,
        )
    }
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
