use http::HeaderMap;

use crate::{
    core::client::options::TransportOptions, header::OrigHeaderMap, http1::Http1Options,
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
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Emulation {
    headers: HeaderMap,
    orig_headers: OrigHeaderMap,
    transport: TransportOptions,
}

// ==== impl EmulationBuilder ====

impl EmulationBuilder {
    /// Sets the  HTTP/1 options configuration.
    #[inline]
    pub fn http1_options(mut self, opts: Http1Options) -> Self {
        *self.emulation.http1_options_mut() = Some(opts);
        self
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn http2_options(mut self, opts: Http2Options) -> Self {
        *self.emulation.http2_options_mut() = Some(opts);
        self
    }

    /// Sets the  TLS options configuration.
    #[inline]
    pub fn tls_options(mut self, opts: TlsOptions) -> Self {
        *self.emulation.tls_options_mut() = Some(opts);
        self
    }

    /// Sets the default headers.
    #[inline]
    pub fn headers(mut self, src: HeaderMap) -> Self {
        crate::util::replace_headers(&mut self.emulation.headers, src);
        self
    }

    /// Sets the original headers.
    #[inline]
    pub fn orig_headers(mut self, src: OrigHeaderMap) -> Self {
        self.emulation.orig_headers.extend(src);
        self
    }

    /// Builds the [`Emulation`] instance.
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
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Returns a mutable reference to the original headers, if set.
    #[inline]
    pub fn orig_headers_mut(&mut self) -> &mut OrigHeaderMap {
        &mut self.orig_headers
    }

    /// Decomposes the [`Emulation`] into its components.
    #[inline]
    pub(crate) fn into_parts(self) -> (TransportOptions, HeaderMap, OrigHeaderMap) {
        (self.transport, self.headers, self.orig_headers)
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
