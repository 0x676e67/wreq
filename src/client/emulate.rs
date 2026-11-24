//! Emulation profiles combining default headers, header order, and protocol options.

use http::HeaderMap;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{config::ConnectConfig, header::OrigHeaderMap, http1::Http1Options, tls::TlsOptions};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Converts protocol options, an existing [`Emulation`], or a preset profile into [`Emulation`].
pub trait IntoEmulation {
    /// Converts `self` into an [`Emulation`] configuration.
    fn into_emulation(self) -> Emulation;
}

/// Builder for [`Emulation`].
///
/// Later calls replace earlier values of the same option type or header name.
#[must_use]
#[derive(Debug)]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// Emulation profile combining default headers, header order, and protocol options.
///
/// Construct via [`Emulation::builder`] or convert directly from protocol option types.
/// Protocol options partition connection reuse, whereas headers do not.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Emulation(
    pub(super) HeaderMap,
    pub(super) OrigHeaderMap,
    pub(super) ConnectConfig,
);

// ===== impl EmulationBuilder =====

impl EmulationBuilder {
    /// Merges protocol options or another [`Emulation`] into this builder.
    ///
    /// Replaces matching option types and headers, and appends original header names.
    #[inline]
    pub fn config<T: IntoEmulation>(mut self, value: T) -> Self {
        let Emulation(headers, orig_headers, connect_config) = value.into_emulation();
        self.emulation.2.extend(connect_config);
        if !headers.is_empty() {
            crate::util::replace_headers(&mut self.emulation.0, headers);
        }
        if !orig_headers.is_empty() {
            self.emulation.1.extend(orig_headers);
        }
        self
    }

    /// Adds default headers, replacing existing values for the supplied names.
    #[inline]
    pub fn headers(mut self, src: HeaderMap) -> Self {
        crate::util::replace_headers(&mut self.emulation.0, src);
        self
    }

    /// Appends original header casing and ordering entries to the existing map.
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

macro_rules! impl_from_option {
    ($($(#[$meta:meta])* $ty:ty),+ $(,)?) => {
        $(
            $(#[$meta])*
            impl From<$ty> for Emulation {
                #[inline]
                fn from(options: $ty) -> Self {
                    let mut connect_config = ConnectConfig::default();
                    connect_config.insert(options);
                    Self(HeaderMap::new(), OrigHeaderMap::new(), connect_config)
                }
            }
        )+
    };
}

impl_from_option! {
    TlsOptions,
    Http1Options,
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    Http2Options,
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    Http3Options,
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    QuicOptions,
}

impl<T: Into<Emulation>> IntoEmulation for T {
    #[inline]
    fn into_emulation(self) -> Emulation {
        self.into()
    }
}
