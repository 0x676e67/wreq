use http::HeaderMap;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    config::connect::{ConfigSet, ConnectConfig},
    header::OrigHeaderMap,
    http1::Http1Options,
    tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Implements [`ProtocolConfig`] for the given protocol option type.
macro_rules! impl_protocol_config {
    ($type:ty) => {
        impl ProtocolConfig for $type {}
    };
}

/// Converts predefined or user-defined settings into [`Emulation`].
pub trait IntoEmulation {
    /// Converts `self` into an [`Emulation`] configuration.
    fn into_emulation(self) -> Emulation;
}

/// Protocol options an [`Emulation`] carries: [`TlsOptions`], [`Http1Options`],
/// and options for enabled HTTP/2 and HTTP/3 protocols.
/// This trait is sealed.
pub trait ProtocolConfig: ConnectConfig {}

/// Collects headers, header order and protocol options for an [`Emulation`].
/// Building transfers those settings without cloning them.
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
    pub(super) ConfigSet,
);

// ===== impl ProtocolConfig =====

impl_protocol_config!(TlsOptions);
impl_protocol_config!(Http1Options);
#[cfg(feature = "http2")]
impl_protocol_config!(Http2Options);
#[cfg(feature = "http3")]
impl_protocol_config!(Http3Options);
#[cfg(feature = "http3")]
impl_protocol_config!(QuicOptions);

// ===== impl EmulationBuilder =====

impl EmulationBuilder {
    /// Sets one kind of protocol options; a later value of the same type replaces it.
    #[inline]
    pub fn config<T: ProtocolConfig>(mut self, value: T) -> Self {
        self.emulation.2.insert(value);
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

impl<T: ProtocolConfig> From<T> for Emulation {
    #[inline]
    fn from(value: T) -> Self {
        Emulation::builder().config(value).build()
    }
}

impl<T: Into<Emulation>> IntoEmulation for T {
    #[inline]
    fn into_emulation(self) -> Emulation {
        self.into()
    }
}
