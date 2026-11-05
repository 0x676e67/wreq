//! Frozen connection identity shared by pool lookup and transport setup.
//!
//! Request configuration is editable until a [`ConnectRequest`] is built. Its key then counts
//! socket bindings and typed entries that differ from the client's configuration.

use std::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    sync::Arc,
};

use http::{Uri, uri::PathAndQuery};

use super::{
    config::{ConfigSet, ConnectConfig, HASHER, Overrides},
    transport::BindOptions,
};
use crate::{Protocol, error::BoxError};

/// Connection request shared by pool lookup and transport connection attempts.
/// Keeps the origin, protocol choice, bindings and typed configuration fixed for an attempt.
/// A proxy may change the route without changing the original reuse identity.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    key: ConnectionKey,
    resolved_protocol: Protocol,
    route_uri: Option<Uri>,
}

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
/// Clones share configuration values and socket bindings.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    /// Preference; `None` inherits the client.
    protocol: Option<Protocol>,
    bind_options: Option<Arc<BindOptions>>,
    overrides: Overrides,
    hash: u64,
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Validates the absolute target and freezes its connection identity.
    ///
    /// The origin keeps scheme and authority with `/` as the path. The key counts the
    /// request entries the resolved protocol can use that differ from `client_config_set`.
    ///
    /// Returns an error if the URI lacks a scheme or authority.
    pub(crate) fn new(
        uri: &Uri,
        protocol: Option<Protocol>,
        client: Protocol,
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        bind_options: Option<Arc<BindOptions>>,
        base_bind_options: &BindOptions,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        Ok(Self {
            key: ConnectionKey::new(
                origin,
                protocol,
                client,
                config_set,
                client_config_set,
                bind_options.filter(|options| options.as_ref() != base_bind_options),
            ),
            resolved_protocol: protocol.unwrap_or(client),
            route_uri: None,
        })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Pool and session keys use this origin, not the request's path or query.
    /// Proxy routing leaves it unchanged; use `route_uri` for transport setup.
    pub(crate) fn uri(&self) -> &Uri {
        &self.key.origin
    }

    /// Returns the request's connection protocol preference.
    /// `None` inherits the client; `Some(Protocol::Auto)` allows protocol negotiation.
    /// This is a selection policy, not the established connection's wire version.
    pub(crate) fn protocol(&self) -> Option<Protocol> {
        self.key.protocol
    }

    /// Returns the protocol selection after inheriting the client's preference.
    /// Frozen before pool checkout; proxy routing does not change this selection.
    pub(crate) fn resolved_protocol(&self) -> Protocol {
        self.resolved_protocol
    }

    /// All request connection options, including those this key does not count.
    pub(crate) fn config_set(&self) -> &ConfigSet {
        self.key.overrides.config_set()
    }

    /// Returns a request override selected for this connection's protocol.
    /// Unselected values are inherited from the client; see [`Overrides`] for selection rules.
    #[inline]
    pub(crate) fn config_override<T: ConnectConfig>(&self) -> Option<&T> {
        self.key.overrides.get::<T>()
    }

    /// Shares a request override used by this connection's protocol.
    /// Has the same inheritance rules as [`Self::config_override`].
    #[inline]
    #[cfg(feature = "http3")]
    pub(crate) fn config_override_arc<T: ConnectConfig>(&self) -> Option<Arc<T>> {
        self.key.overrides.get_arc::<T>()
    }

    /// Request socket bindings shared by transport setup, pool and session keys.
    /// `None` inherits the client's bindings.
    pub(crate) fn bind_options(&self) -> &Option<Arc<BindOptions>> {
        &self.key.bind_options
    }

    /// Returns the reuse identity of this origin and configuration.
    pub(crate) fn key(&self) -> ConnectionKey {
        self.key.clone()
    }

    /// Returns the identity of this origin and configuration under another preference.
    #[cfg(any(test, feature = "http2"))]
    pub(crate) fn key_with_protocol(
        &self,
        protocol: Option<Protocol>,
        client: Protocol,
        client_config_set: &ConfigSet,
    ) -> ConnectionKey {
        let config_set = self.key.overrides.config_set().clone();
        ConnectionKey::new(
            self.key.origin.clone(),
            protocol,
            client,
            config_set,
            client_config_set,
            self.key.bind_options.clone(),
        )
    }

    /// Returns the address used for transport setup and TLS host selection.
    /// It defaults to the original origin until a proxy supplies another route.
    /// Routing does not participate in the original connection's reuse identity.
    pub(crate) fn route_uri(&self) -> &Uri {
        self.route_uri.as_ref().unwrap_or_else(|| self.uri())
    }

    /// Changes the transport address without changing origin or reuse identity.
    /// Proxy connectors supply an already validated URI for the next hop.
    /// Consuming this request leaves sibling clones and their routes unchanged.
    pub(crate) fn with_route_uri(mut self, uri: Uri) -> Self {
        self.route_uri = Some(uri);
        self
    }
}

// ===== impl ConnectionKey =====

impl ConnectionKey {
    fn new(
        origin: Uri,
        protocol: Option<Protocol>,
        client: Protocol,
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        bind_options: Option<Arc<BindOptions>>,
    ) -> Self {
        let overrides =
            Overrides::for_pool(config_set, client_config_set, protocol.unwrap_or(client));
        let hash = HASHER.hash_one((&origin, protocol, &bind_options, overrides.hash()));
        Self {
            origin,
            protocol,
            bind_options,
            overrides,
            hash,
        }
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.protocol == other.protocol
            && self.origin == other.origin
            && self.bind_options == other.bind_options
            && self.overrides == other.overrides
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionKey")
            .field("origin", &self.origin)
            .field("protocol", &self.protocol)
            .field("bind_options", &self.bind_options)
            .field("overrides", &self.overrides)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::*;
    #[cfg(feature = "http2")]
    use crate::http2::Http2Options;
    use crate::{
        group::Group,
        http1::Http1Options,
        tls::{AlpnProtocol, TlsOptions},
    };

    impl ConnectRequest {
        /// Freezes `config_set` for a client without options in automatic mode.
        #[cfg(feature = "tokio-rt")]
        pub(crate) fn test(uri: Uri, protocol: Option<Protocol>, config_set: ConfigSet) -> Self {
            Self::new(
                &uri,
                protocol,
                Protocol::Auto,
                config_set,
                &ConfigSet::default(),
                None,
                &BindOptions::default(),
            )
            .unwrap()
        }
    }

    fn request(
        protocol: Option<Protocol>,
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
    ) -> ConnectRequest {
        let uri = Uri::from_static("https://localhost/upload?part=1");
        ConnectRequest::new(
            &uri,
            protocol,
            Protocol::Auto,
            config_set,
            client_config_set,
            None,
            &BindOptions::default(),
        )
        .unwrap()
    }

    fn key(
        protocol: Option<Protocol>,
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
    ) -> ConnectionKey {
        request(protocol, config_set, client_config_set).key()
    }

    fn with<T: ConnectConfig>(mut config_set: ConfigSet, value: T) -> ConfigSet {
        config_set.insert(value);
        config_set
    }

    fn tls(alpn: AlpnProtocol) -> TlsOptions {
        TlsOptions::builder().alpn_protocols([alpn]).build()
    }

    #[test]
    fn keys_count_only_request_options_that_differ_from_the_client() {
        let client_config_set = with(ConfigSet::default(), tls(AlpnProtocol::HTTP2));
        let plain = key(None, ConfigSet::default(), &client_config_set);
        let hasher = lru::DefaultHasher::default();

        // Equal values and a shared emulation inherit the client's options.
        let inherited = with(ConfigSet::default(), tls(AlpnProtocol::HTTP2));
        for config_set in [inherited, client_config_set.clone()] {
            let other = key(None, config_set, &client_config_set);
            assert_eq!(plain, other);
            assert_eq!(hasher.hash_one(&plain), hasher.hash_one(&other));
        }

        let changed = request(
            None,
            with(ConfigSet::default(), tls(AlpnProtocol::HTTP1)),
            &client_config_set,
        );
        assert_ne!(plain, changed.key());
        assert!(changed.config_override::<TlsOptions>().is_some());
        assert_ne!(
            plain,
            key(
                Some(Protocol::Auto),
                ConfigSet::default(),
                &client_config_set
            )
        );

        let rerouted = changed
            .clone()
            .with_route_uri(Uri::from_static("https://proxy:8443/"));
        assert_eq!(rerouted.uri(), "https://localhost/");
        assert_eq!(rerouted.route_uri(), "https://proxy:8443/");
        assert_eq!(rerouted.key(), changed.key());

        // Inherited and explicit choices keep their meaning through proxy routing.
        let assert_rerouted = |client: Protocol, protocol: Option<Protocol>, resolved: Protocol| {
            let request = ConnectRequest::new(
                changed.uri(),
                protocol,
                client,
                ConfigSet::default(),
                &client_config_set,
                None,
                &BindOptions::default(),
            )
            .unwrap();
            let key = request.key();
            let rerouted = request.with_route_uri(Uri::from_static("https://proxy:8443/"));
            assert_eq!(rerouted.protocol(), protocol);
            assert_eq!(rerouted.resolved_protocol(), resolved);
            assert_eq!(rerouted.key(), key);
        };
        assert_rerouted(Protocol::Http1, None, Protocol::Http1);
        #[cfg(feature = "http2")]
        {
            assert_rerouted(Protocol::Http2, None, Protocol::Http2);
            assert_rerouted(Protocol::Http2, Some(Protocol::Auto), Protocol::Auto);
        }
        #[cfg(feature = "http3")]
        {
            assert_rerouted(Protocol::Http3, None, Protocol::Http3);
            assert_rerouted(Protocol::Http3, Some(Protocol::Auto), Protocol::Auto);
            assert_rerouted(Protocol::Http3, Some(Protocol::Http1), Protocol::Http1);
            assert_rerouted(Protocol::Auto, Some(Protocol::Http3), Protocol::Http3);
        }
        #[cfg(all(feature = "http2", feature = "http3"))]
        assert_rerouted(Protocol::Http3, Some(Protocol::Http2), Protocol::Http2);

        // Equal hashes still compare the counted values.
        let mut collision = changed.key();
        collision.hash = plain.hash;
        assert_ne!(plain, collision);

        let relative = Uri::from_static("/relative");
        let client_config_set = ConfigSet::default();
        assert!(
            ConnectRequest::new(
                &relative,
                None,
                Protocol::Auto,
                client_config_set.clone(),
                &client_config_set,
                None,
                &BindOptions::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn socket_bindings_keep_pool_identities_isolated() {
        let client_config_set = ConfigSet::default();
        let uri = Uri::from_static("https://localhost/");
        let mut bindings = BindOptions::default();
        bindings.set_local_addresses(Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
        let partial_bindings = BindOptions {
            ipv4_address: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        };
        let mut effective = bindings.clone();
        effective.merge(&partial_bindings);
        assert_eq!(effective, bindings);
        let other_bindings = BindOptions {
            ipv4_address: Some(Ipv4Addr::UNSPECIFIED),
            ..Default::default()
        };
        for protocol in [
            None,
            Some(Protocol::Http1),
            #[cfg(feature = "http2")]
            Some(Protocol::Http2),
            #[cfg(feature = "http3")]
            Some(Protocol::Http3),
        ] {
            let request = |bind_options, base_bind_options| {
                ConnectRequest::new(
                    &uri,
                    protocol,
                    Protocol::Auto,
                    ConfigSet::default(),
                    &client_config_set,
                    bind_options,
                    base_bind_options,
                )
                .unwrap()
            };
            let inherited = request(None, &bindings);
            let same = request(Some(Arc::new(bindings.clone())), &bindings);
            assert!(same.bind_options().is_none());
            assert_eq!(same.key(), inherited.key());
            assert_eq!(same.key().hash, inherited.key().hash);

            let partial = request(Some(Arc::new(partial_bindings.clone())), &bindings);
            assert_ne!(partial.key(), inherited.key());
            assert_eq!(partial.bind_options().as_deref(), Some(&partial_bindings));

            let changed = request(Some(Arc::new(other_bindings.clone())), &bindings);
            assert_ne!(changed.key(), inherited.key());
            assert_eq!(changed.bind_options().as_deref(), Some(&other_bindings));
            assert_eq!(
                changed.key_with_protocol(protocol, Protocol::Auto, &client_config_set),
                changed.key()
            );
            assert_eq!(
                changed
                    .clone()
                    .with_route_uri(Uri::from_static("https://proxy:8443/"))
                    .key(),
                changed.key()
            );

            let mut collision = changed.key();
            collision.hash = inherited.key().hash;
            assert_ne!(collision, inherited.key());
        }
    }

    #[test]
    fn keys_ignore_options_of_protocols_a_connection_cannot_use() {
        let client_config_set = ConfigSet::default();
        let http1 = with(
            ConfigSet::default(),
            Http1Options::builder().max_headers(8).build(),
        );
        let h1 = Some(Protocol::Http1);
        assert_ne!(
            key(h1, http1.clone(), &client_config_set),
            key(h1, ConfigSet::default(), &client_config_set)
        );
        #[cfg(feature = "http2")]
        {
            let http2 = with(
                ConfigSet::default(),
                Http2Options::builder().header_table_size(1024).build(),
            );

            let h2 = Some(Protocol::Http2);
            assert_eq!(
                key(h1, http2.clone(), &client_config_set),
                key(h1, ConfigSet::default(), &client_config_set)
            );
            assert_eq!(
                key(h2, http1.clone(), &client_config_set),
                key(h2, ConfigSet::default(), &client_config_set)
            );
            assert_ne!(
                key(None, http2.clone(), &client_config_set),
                key(None, ConfigSet::default(), &client_config_set)
            );

            // Another preference selects again from the whole request storage.
            let probe = request(h1, http2, &client_config_set).key_with_protocol(
                None,
                Protocol::Auto,
                &client_config_set,
            );
            assert_ne!(probe, key(None, ConfigSet::default(), &client_config_set));
        }

        // Groups and proxies shape every connection.
        let proxy = crate::Proxy::all("http://localhost:8080")
            .unwrap()
            .into_matcher();
        for config_set in [
            with(ConfigSet::default(), Group::new("tenant")),
            with(ConfigSet::default(), proxy),
        ] {
            assert_ne!(
                key(h1, config_set, &client_config_set),
                key(h1, ConfigSet::default(), &client_config_set)
            );
        }

        #[cfg(feature = "http3")]
        {
            let h3 = Some(Protocol::Http3);
            let http3 = netty::http3::Http3Options::builder()
                .max_field_section_size(1024)
                .build();
            let tcp = with(http1, tls(AlpnProtocol::HTTP1));
            assert_eq!(
                key(h3, tcp, &client_config_set),
                key(h3, ConfigSet::default(), &client_config_set)
            );
            let quic = with(ConfigSet::default(), http3);
            assert_eq!(
                key(None, quic.clone(), &client_config_set),
                key(None, ConfigSet::default(), &client_config_set)
            );
            assert_ne!(
                key(h3, quic, &client_config_set),
                key(h3, ConfigSet::default(), &client_config_set)
            );
        }
    }

    #[test]
    fn compressor_identity_uses_ordered_algorithms() {
        use crate::{
            conn::config::KeyPart,
            tls::compress::{CertificateCompressionAlgorithm, CertificateCompressor, Codec},
        };

        /// Supplies algorithm identity without installing a TLS codec.
        /// Distinct instances model independently constructed configurations.
        /// Codec invocation is outside this connection-key test.
        #[derive(Debug)]
        struct Compressor(CertificateCompressionAlgorithm);
        impl CertificateCompressor for Compressor {
            fn algorithm(&self) -> CertificateCompressionAlgorithm {
                self.0
            }
            fn compress(&self) -> Codec {
                Codec::Pointer(|_, _| Err(std::io::ErrorKind::Unsupported.into()))
            }
            fn decompress(&self) -> Codec {
                self.compress()
            }
        }
        static FIRST: Compressor = Compressor(CertificateCompressionAlgorithm::ZLIB);
        static SECOND: Compressor = Compressor(CertificateCompressionAlgorithm::ZLIB);
        static BROTLI: Compressor = Compressor(CertificateCompressionAlgorithm::BROTLI);

        fn check_parts<T: ConnectConfig>(
            options: impl Fn(Option<Vec<&'static dyn CertificateCompressor>>) -> T,
        ) {
            let first = options(Some(vec![&FIRST, &BROTLI]));
            let second = options(Some(vec![&SECOND, &BROTLI]));
            let reordered = options(Some(vec![&BROTLI, &FIRST]));
            let absent = options(None);
            let empty = options(Some(Vec::new()));
            assert!(first == second);
            assert!(first != reordered);
            assert!(absent == empty);
            assert_eq!(HASHER.hash_one(&first), HASHER.hash_one(&second));
            assert_eq!(HASHER.hash_one(&absent), HASHER.hash_one(&empty));
            for part in [KeyPart::Whole, KeyPart::Session, KeyPart::Context] {
                assert!(first.eq_part(&second, part));
                assert!(!first.eq_part(&reordered, part));
                assert!(absent.eq_part(&empty, part));
            }
            assert_eq!(first.hash_parts(), second.hash_parts());
            assert_eq!(absent.hash_parts(), empty.hash_parts());
        }

        let options = |compressors: Option<Vec<&'static dyn CertificateCompressor>>| TlsOptions {
            certificate_compressors: compressors.map(Cow::Owned),
            ..Default::default()
        };
        check_parts(options);
        #[cfg(feature = "http3")]
        check_parts(|compressors| crate::quic::QuicOptions {
            certificate_compressors: compressors.map(Cow::Owned),
            ..Default::default()
        });

        let key = |compressors| {
            key(
                None,
                with(ConfigSet::default(), options(compressors)),
                &ConfigSet::default(),
            )
        };
        let first = key(Some(vec![&FIRST, &BROTLI]));
        let second = key(Some(vec![&SECOND, &BROTLI]));
        assert_eq!(first, second);
        assert_eq!(first.hash, second.hash);
        assert_ne!(first, key(Some(vec![&BROTLI, &FIRST])));
        assert_eq!(key(None), key(Some(vec![])));
    }
}
