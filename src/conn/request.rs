//! Frozen connection inputs and the keys derived from them.

use std::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use http::{Uri, uri::PathAndQuery};
use netty::http1::Http1Options;
#[cfg(feature = "http2")]
use netty::http2::Http2Options;
#[cfg(feature = "http3")]
use {crate::quic::QuicOptions, netty::http3::Http3Options};

use super::dialer::Interface;
use crate::{
    config::connect::{ConnectConfig, ConnectExtension, HASHER, KeyPart, Whole, changed},
    error::BoxError,
    group::Group,
    protocol::Protocol,
    proxy::Matcher,
    tls::TlsOptions,
};

/// The destination and settings for a new connection.
/// Keeps the origin, protocol choice and configuration fixed across retries and proxy hops.
#[derive(Clone)]
pub(crate) struct ConnectRequest {
    origin: Uri,
    protocol: Protocol,
    config: ConnectConfig,
}

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    protocol: Protocol,
    identity: ConnectionIdentity,
}

/// Precomputed parts of a key. The origin and protocol travel with the request.
#[derive(Clone)]
pub(crate) struct ConnectionIdentity {
    overrides: Option<Arc<PoolOverrides>>,
    hash: u64,
}

#[derive(Eq, PartialEq, Hash)]
struct PoolOverrides {
    common: CommonOverrides,
    protocol: ProtocolOverrides,
}

/// Route and socket settings shared by the pool and session identities.
#[derive(Clone, Default, Eq, PartialEq, Hash)]
pub(crate) struct CommonOverrides {
    group: Option<Group>,
    matcher: Option<Whole<Matcher>>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    interface: Option<Interface>,
}

#[derive(Eq, PartialEq, Hash)]
enum ProtocolOverrides {
    None,
    Stream {
        tls: Option<Whole<TlsOptions>>,
        http1: Option<Whole<Http1Options>>,
        #[cfg(feature = "http2")]
        http2: Option<Whole<Http2Options>>,
    },
    #[cfg(feature = "http3")]
    Quic {
        quic: Option<Whole<QuicOptions>>,
        http3: Option<Whole<Http3Options>>,
    },
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Validates the absolute target and freezes the connection inputs.
    ///
    /// The origin keeps scheme and authority with `/` as the path.
    ///
    /// Returns an error if the URI lacks a scheme or authority.
    pub(crate) fn new(
        uri: &Uri,
        protocol: Protocol,
        config: ConnectConfig,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        Ok(Self {
            origin,
            protocol,
            config,
        })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Proxy routing leaves it unchanged.
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.origin
    }

    /// Returns the protocol selection after inheriting the client's preference.
    /// Frozen before pool checkout.
    #[inline]
    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// All request connection options, including those outside the pool identity.
    #[inline]
    pub(crate) fn config(&self) -> &ConnectConfig {
        &self.config
    }
}

// ===== impl ConnectionKey =====

impl ConnectionKey {
    /// Computes a regular checkout key or an established-connection probe under `protocol`.
    #[cfg(any(test, feature = "http2", feature = "http3"))]
    pub(crate) fn for_request(
        request: &ConnectRequest,
        protocol: Protocol,
        client_config: &ConnectConfig,
    ) -> Self {
        Self {
            origin: request.uri().clone(),
            protocol,
            identity: ConnectionIdentity::for_protocol(request, protocol, client_config),
        }
    }
}

// ===== impl ConnectionIdentity =====

impl ConnectionIdentity {
    pub(crate) fn new(request: &ConnectRequest, client_config: &ConnectConfig) -> Self {
        Self::for_protocol(request, request.protocol(), client_config)
    }

    fn for_protocol(
        request: &ConnectRequest,
        protocol: Protocol,
        client_config: &ConnectConfig,
    ) -> Self {
        let request_config = request.config();
        let overrides = (!request_config.is_empty())
            .then(|| PoolOverrides {
                common: CommonOverrides::new(request_config, client_config),
                protocol: ProtocolOverrides::new(protocol, request_config, client_config),
            })
            .filter(|overrides| {
                !overrides.common.is_empty()
                    || !matches!(overrides.protocol, ProtocolOverrides::None)
            });

        Self {
            hash: HASHER.hash_one((request.uri(), protocol, &overrides)),
            overrides: overrides.map(Arc::new),
        }
    }

    /// Attaches the request's origin without recalculating the key's projection or hash.
    pub(crate) fn key(&self, request: &ConnectRequest) -> ConnectionKey {
        ConnectionKey {
            origin: request.uri().clone(),
            protocol: request.protocol(),
            identity: self.clone(),
        }
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.identity.hash == other.identity.hash
            && self.protocol == other.protocol
            && self.origin == other.origin
            && self.identity.overrides == other.identity.overrides
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.identity.hash);
    }
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionKey")
            .field("origin", &self.origin)
            .field("protocol", &self.protocol)
            .field("hash", &self.identity.hash)
            .finish()
    }
}

// ===== impl CommonOverrides =====

impl CommonOverrides {
    pub(crate) fn new(request_config: &ConnectConfig, client_config: &ConnectConfig) -> Self {
        fn changed_value<T: ConnectExtension + Clone + Eq>(
            request_config: &ConnectConfig,
            client_config: &ConnectConfig,
        ) -> Option<T> {
            let value = request_config.get_ref::<T>()?;
            (client_config.get_ref::<T>() != Some(value)).then(|| value.clone())
        }

        if request_config.is_empty() {
            return Self::default();
        }

        Self {
            group: changed_value(request_config, client_config),
            matcher: changed::<Matcher>(request_config, client_config, KeyPart::Whole)
                .map(Whole::new),
            ipv4: changed_value(request_config, client_config),
            ipv6: changed_value(request_config, client_config),
            interface: changed_value(request_config, client_config),
        }
    }

    fn is_empty(&self) -> bool {
        self.group.is_none()
            && self.matcher.is_none()
            && self.ipv4.is_none()
            && self.ipv6.is_none()
            && self.interface.is_none()
    }
}

// ===== impl ProtocolOverrides =====

impl ProtocolOverrides {
    fn new(
        protocol: Protocol,
        request_config: &ConnectConfig,
        client_config: &ConnectConfig,
    ) -> Self {
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 {
            let quic = changed::<QuicOptions>(request_config, client_config, KeyPart::Whole)
                .map(Whole::new);
            let http3 = changed::<Http3Options>(request_config, client_config, KeyPart::Whole)
                .map(Whole::new);
            return if quic.is_some() || http3.is_some() {
                Self::Quic { quic, http3 }
            } else {
                Self::None
            };
        }

        let tls =
            changed::<TlsOptions>(request_config, client_config, KeyPart::Whole).map(Whole::new);
        let http1 = if matches!(protocol, Protocol::Auto | Protocol::Http1) {
            changed::<Http1Options>(request_config, client_config, KeyPart::Whole).map(Whole::new)
        } else {
            None
        };
        #[cfg(feature = "http2")]
        let http2 = if matches!(protocol, Protocol::Auto | Protocol::Http2) {
            changed::<Http2Options>(request_config, client_config, KeyPart::Whole).map(Whole::new)
        } else {
            None
        };

        let has_override = tls.is_some()
            || http1.is_some()
            || cfg_select! {
                feature = "http2" => http2.is_some(),
                _ => false,
            };
        if has_override {
            Self::Stream {
                tls,
                http1,
                #[cfg(feature = "http2")]
                http2,
            }
        } else {
            Self::None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{config::connect::ScopedConfig, tls::AlpnProtocol};

    impl ConnectRequest {
        /// Freezes `config` for a client without options in automatic mode.
        pub(crate) fn test(uri: Uri, protocol: Option<Protocol>, config: ConnectConfig) -> Self {
            Self::new(&uri, protocol.unwrap_or(Protocol::Auto), config).unwrap()
        }
    }

    fn request(protocol: Option<Protocol>, request_config: ConnectConfig) -> ConnectRequest {
        let uri = Uri::from_static("https://localhost/upload?part=1");
        ConnectRequest::test(uri, protocol, request_config)
    }

    fn key(
        protocol: Option<Protocol>,
        request_config: ConnectConfig,
        client_config: &ConnectConfig,
    ) -> ConnectionKey {
        let request = request(protocol, request_config);
        ConnectionKey::for_request(&request, request.protocol(), client_config)
    }

    fn with<T: ConnectExtension>(mut config: ConnectConfig, value: T) -> ConnectConfig {
        config.insert(value);
        config
    }

    fn tls(alpn: AlpnProtocol) -> TlsOptions {
        TlsOptions::builder().alpn_protocols([alpn]).build()
    }

    #[test]
    fn keys_count_only_request_options_that_differ_from_the_client() {
        let client_config = with(ConnectConfig::default(), tls(AlpnProtocol::HTTP2));
        let plain = key(None, ConnectConfig::default(), &client_config);
        let hasher = lru::DefaultHasher::default();

        // Independently built equal options share the client's pool key.
        let inherited = with(ConnectConfig::default(), tls(AlpnProtocol::HTTP2));
        let other = key(None, inherited, &client_config);
        assert_eq!(plain, other);
        assert_eq!(hasher.hash_one(&plain), hasher.hash_one(&other));

        let mut changed = key(
            None,
            with(ConnectConfig::default(), tls(AlpnProtocol::HTTP1)),
            &client_config,
        );
        assert_ne!(plain, changed);
        changed.identity.hash = plain.identity.hash;
        assert_ne!(plain, changed);
    }

    #[test]
    fn socket_bindings_keep_pool_identities_isolated() {
        use crate::conn::dialer;
        let mut client_config = ConnectConfig::default();
        dialer::set_local_addresses(
            &mut client_config,
            Some(Ipv4Addr::LOCALHOST),
            Some(Ipv6Addr::LOCALHOST),
        );
        #[cfg(target_os = "linux")]
        dialer::set_interface(&mut client_config, "lo".into());
        let uri = Uri::from_static("https://localhost/");
        let partial = with(ConnectConfig::default(), Ipv4Addr::LOCALHOST);
        let changed = with(ConnectConfig::default(), Ipv4Addr::UNSPECIFIED);
        let mut merged = client_config.clone();
        merged.insert(Ipv4Addr::UNSPECIFIED);
        let check = |protocol| {
            let key = |request_config| {
                let request = ConnectRequest::new(&uri, protocol, request_config).unwrap();
                ConnectionKey::for_request(&request, protocol, &client_config)
            };
            let inherited = key(ConnectConfig::default());
            assert_eq!(key(partial.clone()), inherited);
            let changed = key(changed.clone());
            assert_ne!(changed, inherited);
            assert_eq!(key(merged.clone()), changed);
            assert_ne!(
                key(with(ConnectConfig::default(), Ipv6Addr::UNSPECIFIED)),
                inherited
            );
            #[cfg(target_os = "linux")]
            {
                let mut interface = ConnectConfig::default();
                dialer::set_interface(&mut interface, String::from("lo").into());
                assert_eq!(key(interface.clone()), inherited);
                dialer::set_interface(&mut interface, "eth0".into());
                assert_ne!(key(interface), inherited);
            }
        };

        check(Protocol::Auto);
        #[cfg(feature = "http3")]
        check(Protocol::Http3);
    }

    #[test]
    fn keys_ignore_options_of_protocols_a_connection_cannot_use() {
        let client_config = ConnectConfig::default();
        let http1 = with(
            ConnectConfig::default(),
            Http1Options::builder().max_headers(8).build(),
        );
        let h1 = Some(Protocol::Http1);
        assert_ne!(
            key(h1, http1.clone(), &client_config),
            key(h1, ConnectConfig::default(), &client_config)
        );
        #[cfg(feature = "http2")]
        {
            let http2 = with(
                ConnectConfig::default(),
                Http2Options::builder().header_table_size(1024).build(),
            );

            let h2 = Some(Protocol::Http2);
            assert_eq!(
                key(h1, http2.clone(), &client_config),
                key(h1, ConnectConfig::default(), &client_config)
            );
            assert_eq!(
                key(h2, http1.clone(), &client_config),
                key(h2, ConnectConfig::default(), &client_config)
            );
            assert_ne!(
                key(None, http2.clone(), &client_config),
                key(None, ConnectConfig::default(), &client_config)
            );

            // Another protocol selects again from the whole request storage.
            let probe =
                ConnectionKey::for_request(&request(h1, http2), Protocol::Auto, &client_config);
            assert_ne!(probe, key(None, ConnectConfig::default(), &client_config));
        }

        // Groups and proxies shape every connection.
        let proxy = crate::Proxy::all("http://localhost:8080")
            .unwrap()
            .into_matcher();
        for request_config in [
            with(ConnectConfig::default(), Group::new("tenant")),
            with(ConnectConfig::default(), proxy),
        ] {
            assert_ne!(
                key(h1, request_config, &client_config),
                key(h1, ConnectConfig::default(), &client_config)
            );
        }

        #[cfg(feature = "http3")]
        {
            let h3 = Some(Protocol::Http3);
            let http3 = Http3Options::builder().max_field_section_size(1024).build();
            let quic = QuicOptions::builder().max_datagram_frame_size(1200).build();
            let h3_key = key(h3, ConnectConfig::default(), &client_config);
            let auto_key = key(None, ConnectConfig::default(), &client_config);
            let tcp = with(http1, tls(AlpnProtocol::HTTP1));
            assert_eq!(key(h3, tcp.clone(), &client_config), h3_key);

            let unused_tls = Arc::downgrade(&tcp.get_arc::<TlsOptions>().unwrap());
            let grouped = key(h3, with(tcp, Group::new("tenant")), &client_config);
            std::assert_matches!(unused_tls.upgrade(), None);
            assert_ne!(grouped, h3_key);
            for request_config in [
                with(ConnectConfig::default(), http3),
                with(ConnectConfig::default(), quic),
            ] {
                assert_eq!(key(None, request_config.clone(), &client_config), auto_key);
                assert_ne!(key(h3, request_config, &client_config), h3_key);
            }
        }
    }

    #[test]
    fn compressor_identity_uses_ordered_algorithms() {
        use crate::tls::compress::{CertificateCompressionAlgorithm, CertificateCompressor, Codec};

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

        fn check_parts<T: ScopedConfig>(
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

            assert!(first.context_identity() == second.context_identity());
            assert!(first.session_identity() != reordered.session_identity());
            assert!(absent.context_identity() == empty.context_identity());
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
                with(ConnectConfig::default(), options(compressors)),
                &ConnectConfig::default(),
            )
        };
        let first = key(Some(vec![&FIRST, &BROTLI]));
        let second = key(Some(vec![&SECOND, &BROTLI]));
        assert_eq!(first, second);
        assert_eq!(first.identity.hash, second.identity.hash);
        assert_ne!(first, key(Some(vec![&BROTLI, &FIRST])));
        assert_eq!(key(None), key(Some(vec![])));
    }
}
