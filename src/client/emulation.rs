use http::HeaderMap;

use crate::{
    OriginalHeaders, core::client::options::TransportOptions, http1::Http1Options,
    http2::Http2Options, tls::TlsOptions,
};

/// Factory trait for creating emulation configurations.
///
/// This trait allows different types (enums, structs, etc.) to provide
/// their own emulation configurations. It's particularly useful for:
/// - Predefined browser profiles
/// - Dynamic configuration based on runtime conditions
/// - User-defined custom emulation strategies
pub trait EmulationFactory {
    /// Creates an `Emulation` instance from this factory.
    fn emulation(self) -> Emulation;
}

/// Builder for creating an `Emulation` configuration.
#[must_use]
#[derive(Debug)]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// HTTP emulation configuration for mimicking different HTTP clients.
///
/// This struct combines transport-layer options (HTTP/1, HTTP/2, TLS) with
/// request-level settings (headers, header case preservation) to provide
/// a complete emulation profile for web browsers, mobile applications,
/// API clients, and other HTTP implementations.
#[derive(Default, Debug)]
pub struct Emulation {
    transport: Option<TransportOptions>,
    headers: Option<HeaderMap>,
    original_headers: Option<OriginalHeaders>,
}

impl EmulationBuilder {
    /// Sets the  TLS options configuration for the emulation.
    pub fn with_tls<C>(mut self, config: C) -> Self
    where
        C: Into<Option<TlsOptions>>,
    {
        self.emulation
            .transport
            .get_or_insert_with(TransportOptions::default)
            .configure_tls(config);
        self
    }

    /// Sets the  HTTP/1 options configuration for the emulation.
    pub fn with_http1<C>(mut self, config: C) -> Self
    where
        C: Into<Option<Http1Options>>,
    {
        self.emulation
            .transport
            .get_or_insert_with(TransportOptions::default)
            .configure_http1(config);
        self
    }

    /// Sets the HTTP/2 options configuration for the emulation.
    pub fn with_http2<C>(mut self, config: C) -> Self
    where
        C: Into<Option<Http2Options>>,
    {
        self.emulation
            .transport
            .get_or_insert_with(TransportOptions::default)
            .configure_http2(config);
        self
    }

    /// Sets the default headers for the emulation.
    pub fn with_headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<HeaderMap>>,
    {
        self.emulation.headers = headers.into();
        self
    }

    /// Sets the original headers for the emulation.
    pub fn with_original_headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<OriginalHeaders>>,
    {
        self.emulation.original_headers = headers.into();
        self
    }

    /// Builds the `Emulation` instance.
    pub fn build(self) -> Emulation {
        self.emulation
    }
}

impl Emulation {
    /// Creates a new `EmulationBuilder`.
    #[inline]
    pub fn builder() -> EmulationBuilder {
        EmulationBuilder {
            emulation: Emulation::default(),
        }
    }

    /// Decomposes the emulation into its components.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<TransportOptions>,
        Option<HeaderMap>,
        Option<OriginalHeaders>,
    ) {
        (self.transport, self.headers, self.original_headers)
    }
}

impl EmulationFactory for Emulation {
    fn emulation(self) -> Emulation {
        self
    }
}

impl EmulationFactory for Http1Options {
    fn emulation(self) -> Emulation {
        Emulation::builder().with_http1(self).build()
    }
}

impl EmulationFactory for Http2Options {
    fn emulation(self) -> Emulation {
        Emulation::builder().with_http2(self).build()
    }
}

impl EmulationFactory for TlsOptions {
    fn emulation(self) -> Emulation {
        Emulation::builder().with_tls(self).build()
    }
}
