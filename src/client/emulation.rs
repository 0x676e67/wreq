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
    /// Creates an [`Emulation`] instance from this factory.
    fn emulation(self) -> Emulation;
}

/// Builder for creating an [`Emulation`] configuration.
#[derive(Debug)]
#[must_use]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// HTTP emulation configuration for mimicking different HTTP clients.
///
/// This struct combines transport-layer options (HTTP/1, HTTP/2, TLS) with
/// request-level settings (headers, header case preservation) to provide
/// a complete emulation profile for web browsers, mobile applications,
/// API clients, and other HTTP implementations.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Emulation {
    transport: TransportOptions,
    headers: Option<HeaderMap>,
    original_headers: Option<OriginalHeaders>,
}

// ==== impl EmulationBuilder ====

impl EmulationBuilder {
    /// Sets the  HTTP/1 options configuration for the emulation.
    #[inline]
    pub fn http1_options<C>(mut self, opts: C) -> Self
    where
        C: Into<Option<Http1Options>>,
    {
        if let Some(opts) = opts.into() {
            *self.emulation.http1_options_mut() = Some(opts);
        }
        self
    }

    /// Sets the HTTP/2 options configuration for the emulation.
    #[inline]
    pub fn http2_options<C>(mut self, opts: C) -> Self
    where
        C: Into<Option<Http2Options>>,
    {
        if let Some(opts) = opts.into() {
            *self.emulation.http2_options_mut() = Some(opts);
        }
        self
    }

    /// Sets the  TLS options configuration for the emulation.
    #[inline]
    pub fn tls_options<C>(mut self, opts: C) -> Self
    where
        C: Into<Option<TlsOptions>>,
    {
        if let Some(opts) = opts.into() {
            *self.emulation.tls_options_mut() = Some(opts);
        }
        self
    }

    /// Sets the default headers for the emulation.
    #[inline]
    pub fn headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<HeaderMap>>,
    {
        if let Some(src) = headers.into() {
            let dst = self.emulation.headers.get_or_insert_default();
            crate::util::replace_headers(dst, src);
        }
        self
    }

    /// Sets the original headers for the emulation.
    #[inline]
    pub fn original_headers<H>(mut self, headers: H) -> Self
    where
        H: Into<Option<OriginalHeaders>>,
    {
        if let Some(src) = headers.into() {
            self.emulation
                .original_headers
                .get_or_insert_default()
                .extend(src);
        }
        self
    }

    /// Builds the `Emulation` instance.
    #[inline]
    pub fn build(self) -> Emulation {
        self.emulation
    }
}

// ==== impl Emulation ====

impl Emulation {
    /// Creates a new [`EmulationBuilder`].
    #[inline]
    pub fn builder() -> EmulationBuilder {
        EmulationBuilder {
            emulation: Emulation::default(),
        }
    }

    /// Returns a mutable reference to the TLS options, if set.
    #[inline]
    pub fn tls_options_mut(&mut self) -> &mut Option<TlsOptions> {
        self.transport.tls_options_mut()
    }

    /// Returns a mutable reference to the HTTP/1 options, if set.
    #[inline]
    pub fn http1_options_mut(&mut self) -> &mut Option<Http1Options> {
        self.transport.http1_options_mut()
    }

    /// Returns a mutable reference to the HTTP/2 options, if set.
    #[inline]
    pub fn http2_options_mut(&mut self) -> &mut Option<Http2Options> {
        self.transport.http2_options_mut()
    }

    /// Returns a mutable reference to the emulation headers, if set.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut Option<HeaderMap> {
        &mut self.headers
    }

    /// Returns a mutable reference to the original headers, if set.
    #[inline]
    pub fn original_headers_mut(&mut self) -> &mut Option<OriginalHeaders> {
        &mut self.original_headers
    }

    /// Decomposes the [`Emulation`] into its components.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (TransportOptions, Option<HeaderMap>, Option<OriginalHeaders>) {
        (self.transport, self.headers, self.original_headers)
    }
}

impl EmulationFactory for Emulation {
    #[inline]
    fn emulation(self) -> Emulation {
        self
    }
}

impl EmulationFactory for Http1Options {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().http1_options(self).build()
    }
}

impl EmulationFactory for Http2Options {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().http2_options(self).build()
    }
}

impl EmulationFactory for TlsOptions {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().tls_options(self).build()
    }
}
