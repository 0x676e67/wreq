use http::HeaderMap;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    conn::config::{ConfigSet, ConnectConfig},
    header::OrigHeaderMap,
    http1::Http1Options,
    tls::TlsOptions,
};

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
#[derive(Debug, Clone)]
pub struct Emulation(
    pub(super) HeaderMap,
    pub(super) OrigHeaderMap,
    pub(super) ConfigSet,
);

// ===== impl ProtocolConfig =====

impl_protocol_config!(Http1Options);
#[cfg(feature = "http2")]
impl_protocol_config!(Http2Options);
#[cfg(feature = "http3")]
impl_protocol_config!(crate::http3::Http3Options);
#[cfg(feature = "http3")]
impl_protocol_config!(crate::quic::QuicOptions);
impl_protocol_config!(TlsOptions);

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
            emulation: Emulation(HeaderMap::new(), OrigHeaderMap::new(), ConfigSet::default()),
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use super::*;
    use crate::{
        Client, Group, Proxy, config::RequestConfig, conn::transport::BindOptions, proxy::Matcher,
        rt::tokio::TokioRuntime, tls::TlsVersion,
    };

    #[test]
    fn profiles_replace_protocol_options_and_preserve_request_settings() {
        let tls = TlsOptions::builder()
            .min_tls_version(TlsVersion::TLS_1_2)
            .build();
        let http1 = Http1Options::builder().max_headers(32).build();
        #[cfg(feature = "http2")]
        let http2 = Http2Options::builder().header_table_size(4096).build();
        let headers =
            HeaderMap::from_iter([("x-profile".parse().unwrap(), "first".parse().unwrap())]);
        let mut orig_headers = OrigHeaderMap::new();
        orig_headers.insert("X-Profile");
        let profile = Emulation::builder()
            .headers(headers)
            .orig_headers(orig_headers.clone())
            .config(tls.clone())
            .config(http1.clone());
        #[cfg(feature = "http2")]
        let profile = profile.config(http2.clone());
        let profile = profile.build();

        // An empty profile keeps what the client already has.
        for client in [
            Client::builder(TokioRuntime).emulation(profile.clone()),
            Client::builder(TokioRuntime)
                .emulation(profile.clone())
                .emulation(Emulation::builder().build()),
        ] {
            let config = &client.config;
            assert_eq!(config.config_set.get::<TlsOptions>(), Some(&tls));
            assert_eq!(config.config_set.get::<Http1Options>(), Some(&http1));
            #[cfg(feature = "http2")]
            assert_eq!(config.config_set.get::<Http2Options>(), Some(&http2));
            assert_eq!(config.headers["x-profile"], "first");
            assert_eq!(config.orig_headers, orig_headers);
        }

        let client = Client::builder(TokioRuntime).build().unwrap();
        let group = Group::new("profile");
        let base = client
            .get("https://localhost/")
            .group(group.clone())
            .version(http::Version::HTTP_11)
            .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .proxy(Proxy::http("http://localhost:8080").unwrap())
            .emulation(profile.clone());
        let request = base.try_clone().unwrap().build().unwrap();
        let config_set = request.extensions().get::<ConfigSet>().unwrap();
        assert_eq!(config_set.get::<TlsOptions>(), Some(&tls));
        assert_eq!(config_set.get::<Http1Options>(), Some(&http1));
        #[cfg(feature = "http2")]
        assert_eq!(config_set.get::<Http2Options>(), Some(&http2));
        assert_eq!(
            RequestConfig::<OrigHeaderMap>::get(request.extensions()),
            Some(&orig_headers)
        );

        // A partial profile replaces matching types and keeps the other request settings. Its
        // empty header order keeps the existing one.
        let replacement = Http1Options::builder().max_headers(64).build();
        let replaced = base
            .emulation(Emulation::builder().config(replacement.clone()).build())
            .build()
            .unwrap();
        let replaced_set = replaced.extensions().get::<ConfigSet>().unwrap();
        assert_eq!(replaced_set.get::<TlsOptions>(), Some(&tls));
        #[cfg(feature = "http2")]
        assert_eq!(replaced_set.get::<Http2Options>(), Some(&http2));
        assert_eq!(replaced_set.get::<Http1Options>(), Some(&replacement));
        assert_eq!(replaced_set.get::<Group>(), Some(&group));
        assert_eq!(replaced_set.get::<Matcher>(), config_set.get::<Matcher>());
        assert_eq!(
            replaced.extensions().get::<Arc<BindOptions>>(),
            request.extensions().get::<Arc<BindOptions>>()
        );
        assert_eq!(replaced.version(), request.version());
        assert_eq!(replaced.headers()["x-profile"], "first");
        assert_eq!(
            RequestConfig::<OrigHeaderMap>::get(replaced.extensions()),
            Some(&orig_headers)
        );
        assert_eq!(config_set.get::<Http1Options>(), Some(&http1));
        assert_eq!(profile.2.get::<TlsOptions>(), Some(&tls));

        // Headers and their order do not partition protocol configuration identity.
        let same_options = Emulation::builder().config(tls).config(http1);
        #[cfg(feature = "http2")]
        let same_options = same_options.config(http2);
        assert_eq!(profile.2, same_options.build().2);
    }
}
