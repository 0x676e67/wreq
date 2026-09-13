use http::HeaderMap;
use wreq_proto::{http1::Http1Options, http2::Http2Options};

use crate::{conn::Extra, header::OrigHeaderMap, tls::TlsOptions};

/// Converts a predefined or user-defined profile into [`Emulation`].
pub trait IntoEmulation {
    /// Converts `self` into an [`Emulation`] configuration.
    fn into_emulation(self) -> Emulation;
}

/// Builder for creating an [`Emulation`] configuration.
/// Collects headers and typed protocol options before applying a profile.
/// Building transfers those settings without copying shared configuration.
#[must_use]
#[derive(Debug)]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// HTTP emulation settings for a client profile.
/// Stores default and original headers alongside typed protocol options.
/// Clones share options; only protocol configuration participates in pool identity.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Emulation(
    pub(super) HeaderMap,
    pub(super) OrigHeaderMap,
    pub(super) Extra,
);

// ===== impl EmulationBuilder =====

impl EmulationBuilder {
    /// Sets the HTTP/1 options configuration.
    #[inline]
    pub fn http1_options(mut self, opts: Http1Options) -> Self {
        self.emulation.2.insert_config(opts);
        self
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn http2_options(mut self, opts: Http2Options) -> Self {
        self.emulation.2.insert_config(opts);
        self
    }

    /// Sets the TLS options configuration.
    #[inline]
    pub fn tls_options(mut self, opts: TlsOptions) -> Self {
        self.emulation.2.insert_config(opts);
        self
    }

    /// Sets the default headers.
    #[inline]
    pub fn headers(mut self, src: HeaderMap) -> Self {
        crate::util::replace_headers(&mut self.emulation.0, src);
        self
    }

    /// Sets the original headers.
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
            emulation: Emulation(HeaderMap::new(), OrigHeaderMap::new(), Extra::default()),
        }
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
    use super::*;
    use crate::{Client, Group, config::RequestConfig, conn::SocketOptions};

    #[test]
    fn profiles_replace_protocol_options_and_preserve_request_settings() {
        let tls = TlsOptions::builder()
            .min_tls_version(crate::tls::TlsVersion::TLS_1_2)
            .build();
        let http1 = Http1Options::builder().max_headers(32).build();
        let http2 = Http2Options::builder().header_table_size(4096).build();
        let headers =
            HeaderMap::from_iter([("x-profile".parse().unwrap(), "first".parse().unwrap())]);
        let mut orig_headers = OrigHeaderMap::new();
        orig_headers.insert("X-Profile");
        let profile = Emulation::builder()
            .headers(headers.clone())
            .orig_headers(orig_headers.clone())
            .tls_options(tls.clone())
            .http1_options(http1.clone())
            .http2_options(http2.clone())
            .build();
        let client = Client::builder().emulation(profile.clone());
        assert_eq!(client.config.tls_options.as_ref(), Some(&tls));
        assert_eq!(client.config.http1_options.as_ref(), Some(&http1));
        assert_eq!(client.config.http2_options.as_ref(), Some(&http2));
        assert_eq!(client.config.headers["x-profile"], "first");
        assert_eq!(client.config.orig_headers, orig_headers);

        let client = client.emulation(Emulation::builder().build());
        assert_eq!(client.config.tls_options.as_ref(), Some(&tls));
        assert_eq!(client.config.http1_options.as_ref(), Some(&http1));
        assert_eq!(client.config.http2_options.as_ref(), Some(&http2));
        assert_eq!(client.config.orig_headers, orig_headers);
        let client = client.build().unwrap();
        let group = Group::new("profile");
        let base = client
            .get("https://localhost/")
            .group(group.clone())
            .version(http::Version::HTTP_11)
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .proxy(crate::Proxy::http("http://localhost:8080").unwrap())
            .emulation(profile.clone());
        let request = base.try_clone().unwrap().build().unwrap();
        let extra = request.extensions().get::<Extra>().unwrap();
        assert_eq!(extra.get::<TlsOptions>(), Some(&tls));
        assert_eq!(extra.get::<Http1Options>(), Some(&http1));
        assert_eq!(extra.get::<Http2Options>(), Some(&http2));
        assert!(extra.get::<OrigHeaderMap>().is_none());
        assert_eq!(
            RequestConfig::<OrigHeaderMap>::get(request.extensions()),
            Some(&orig_headers)
        );

        // A partial profile replaces matching types and retains the other request options.
        let replacement = Http1Options::builder().max_headers(64).build();
        let replaced = base
            .emulation(
                Emulation::builder()
                    .http1_options(replacement.clone())
                    .build(),
            )
            .build()
            .unwrap();
        let replaced_extra = replaced.extensions().get::<Extra>().unwrap();
        assert_eq!(replaced_extra.get::<TlsOptions>(), Some(&tls));
        assert_eq!(replaced_extra.get::<Http2Options>(), Some(&http2));
        assert_eq!(replaced_extra.get::<Http1Options>(), Some(&replacement));
        assert_eq!(replaced_extra.get::<Group>(), Some(&group));
        assert_eq!(
            replaced_extra.get::<SocketOptions>(),
            extra.get::<SocketOptions>()
        );
        assert_eq!(
            replaced_extra.get::<crate::proxy::Matcher>(),
            extra.get::<crate::proxy::Matcher>()
        );
        assert_eq!(replaced.version(), request.version());
        assert_eq!(replaced.headers()["x-profile"], "first");
        assert!(
            RequestConfig::<OrigHeaderMap>::get(replaced.extensions())
                .unwrap()
                .is_empty()
        );
        assert_eq!(extra.get::<Http1Options>(), Some(&http1));
        assert_eq!(profile.2.get::<TlsOptions>(), Some(&tls));

        // Header values and spelling cannot partition protocol configuration identity.
        let same_options = Emulation::builder()
            .tls_options(tls)
            .http1_options(http1)
            .http2_options(http2)
            .build();
        assert_eq!(profile.2, same_options.2);
    }
}
