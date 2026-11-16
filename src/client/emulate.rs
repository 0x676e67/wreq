use http::HeaderMap;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    config::connect::ConnectConfig, header::OrigHeaderMap, http1::Http1Options, tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Converts predefined or user-defined settings into [`Emulation`].
pub trait IntoEmulation {
    /// Converts `self` into an [`Emulation`] configuration.
    fn into_emulation(self) -> Emulation;
}

/// Collects headers, header order and protocol options for an [`Emulation`].
/// Each protocol setter replaces its previous value.
#[must_use]
#[derive(Debug)]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// HTTP emulation settings: headers, header order and protocol options.
/// Protocol options affect connection reuse; headers do not.
/// Clones share the protocol options.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Emulation(
    pub(super) HeaderMap,
    pub(super) OrigHeaderMap,
    pub(super) ConnectConfig,
);

// ===== impl EmulationBuilder =====

impl EmulationBuilder {
    /// Sets the TLS options for TCP connections.
    #[inline]
    pub fn tls_options(mut self, options: TlsOptions) -> Self {
        self.emulation.2.insert(options);
        self
    }

    /// Sets the HTTP/1 options.
    #[inline]
    pub fn http1_options(mut self, options: Http1Options) -> Self {
        self.emulation.2.insert(options);
        self
    }

    /// Sets the HTTP/2 options.
    #[inline]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_options(mut self, options: Http2Options) -> Self {
        self.emulation.2.insert(options);
        self
    }

    /// Sets the HTTP/3 options.
    #[inline]
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    pub fn http3_options(mut self, options: Http3Options) -> Self {
        self.emulation.2.insert(options);
        self
    }

    /// Sets the QUIC transport and TLS options.
    #[inline]
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    pub fn quic_options(mut self, options: QuicOptions) -> Self {
        self.emulation.2.insert(options);
        self
    }

    /// Adds default headers, replacing existing values for the supplied names.
    #[inline]
    pub fn headers(mut self, src: HeaderMap) -> Self {
        crate::util::replace_headers(&mut self.emulation.0, src);
        self
    }

    /// Adds original header names to the existing map.
    #[inline]
    pub fn orig_headers(mut self, src: OrigHeaderMap) -> Self {
        self.emulation.1.extend(src);
        self
    }

    /// Builds the [`Emulation`] instance.
    #[inline]
    pub fn build(self) -> Emulation {
        self.emulation
    }
}

// ===== impl Emulation =====

impl Emulation {
    /// Creates a new [`EmulationBuilder`].
    #[inline]
    pub fn builder() -> EmulationBuilder {
        EmulationBuilder {
            emulation: Default::default(),
        }
    }
}

impl From<TlsOptions> for Emulation {
    #[inline]
    fn from(options: TlsOptions) -> Self {
        Self::builder().tls_options(options).build()
    }
}

impl From<Http1Options> for Emulation {
    #[inline]
    fn from(options: Http1Options) -> Self {
        Self::builder().http1_options(options).build()
    }
}

#[cfg(feature = "http2")]
#[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
impl From<Http2Options> for Emulation {
    #[inline]
    fn from(options: Http2Options) -> Self {
        Self::builder().http2_options(options).build()
    }
}

#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
impl From<Http3Options> for Emulation {
    #[inline]
    fn from(options: Http3Options) -> Self {
        Self::builder().http3_options(options).build()
    }
}

#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
impl From<QuicOptions> for Emulation {
    #[inline]
    fn from(options: QuicOptions) -> Self {
        Self::builder().quic_options(options).build()
    }
}

impl<T: Into<Emulation>> IntoEmulation for T {
    #[inline]
    fn into_emulation(self) -> Emulation {
        self.into()
    }
}
