//! Frozen connection inputs and their pool identity.

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
    config::connect::{Extension, Extensions, HASHER, KeyPart, Whole, changed},
    error::BoxError,
    group::Group,
    protocol::Protocol,
    proxy::Matcher,
    tls::TlsOptions,
};

/// Connection request shared by pool lookup and transport connection attempts.
/// Keeps the origin, protocol choice and configuration fixed across retries and proxy hops.
#[derive(Clone)]
pub struct ConnectRequest {
    key: ConnectionKey,
    connect_options: Extensions,
}

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    protocol: Protocol,
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
        protocol: Option<Protocol>,
        client_protocol: Protocol,
        connect_options: Extensions,
        client_options: &Extensions,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        let protocol = protocol.unwrap_or(client_protocol);
        let key = ConnectionKey::new(origin, protocol, &connect_options, client_options);

        Ok(Self {
            key,
            connect_options,
        })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Proxy routing leaves it unchanged.
    pub(crate) fn uri(&self) -> &Uri {
        &self.key.origin
    }

    /// Returns the protocol selection after inheriting the client's preference.
    /// Frozen before pool checkout.
    pub(crate) fn resolved_protocol(&self) -> Protocol {
        self.key.protocol
    }

    /// All request connection options, including those outside the pool identity.
    pub(crate) fn connect_options(&self) -> &Extensions {
        &self.connect_options
    }

    /// Returns the reuse identity of this origin and configuration.
    pub(crate) fn key(&self) -> ConnectionKey {
        self.key.clone()
    }

    /// Returns the identity of this origin and configuration under another resolved protocol.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(crate) fn key_with_protocol(
        &self,
        protocol: Protocol,
        client_options: &Extensions,
    ) -> ConnectionKey {
        ConnectionKey::new(
            self.uri().clone(),
            protocol,
            &self.connect_options,
            client_options,
        )
    }
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("key", &self.key)
            .field("options", &self.connect_options)
            .finish()
    }
}

// ===== impl ConnectionKey =====

impl ConnectionKey {
    fn new(origin: Uri, protocol: Protocol, request: &Extensions, client: &Extensions) -> Self {
        let overrides = (!request.is_empty())
            .then(|| PoolOverrides {
                common: CommonOverrides::new(request, client),
                protocol: ProtocolOverrides::new(protocol, request, client),
            })
            .filter(|overrides| {
                !overrides.common.is_empty()
                    || !matches!(overrides.protocol, ProtocolOverrides::None)
            });
        let hash = HASHER.hash_one((&origin, protocol, &overrides));

        Self {
            origin,
            protocol,
            overrides: overrides.map(Arc::new),
            hash,
        }
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.protocol == other.protocol
            && self.origin == other.origin
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
            .field("hash", &self.hash)
            .finish()
    }
}

// ===== impl CommonOverrides =====

impl CommonOverrides {
    pub(crate) fn new(request: &Extensions, client: &Extensions) -> Self {
        fn changed_value<T: Extension + Clone + Eq>(
            request: &Extensions,
            client: &Extensions,
        ) -> Option<T> {
            let value = request.get_ref::<T>()?;
            (client.get_ref::<T>() != Some(value)).then(|| value.clone())
        }

        if request.is_empty() {
            return Self::default();
        }

        Self {
            group: changed_value(request, client),
            matcher: changed::<Matcher>(request, client, KeyPart::Whole).map(Whole::new),
            ipv4: changed_value(request, client),
            ipv6: changed_value(request, client),
            interface: changed_value(request, client),
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
    fn new(protocol: Protocol, request: &Extensions, client: &Extensions) -> Self {
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 {
            let quic = changed::<QuicOptions>(request, client, KeyPart::Whole).map(Whole::new);
            let http3 = changed::<Http3Options>(request, client, KeyPart::Whole).map(Whole::new);
            return if quic.is_some() || http3.is_some() {
                Self::Quic { quic, http3 }
            } else {
                Self::None
            };
        }

        let tls = changed::<TlsOptions>(request, client, KeyPart::Whole).map(Whole::new);
        let http1 = if matches!(protocol, Protocol::Auto | Protocol::Http1) {
            changed::<Http1Options>(request, client, KeyPart::Whole).map(Whole::new)
        } else {
            None
        };
        #[cfg(feature = "http2")]
        let http2 = if matches!(protocol, Protocol::Auto | Protocol::Http2) {
            changed::<Http2Options>(request, client, KeyPart::Whole).map(Whole::new)
        } else {
            None
        };

        let has_override = tls.is_some() || http1.is_some();
        #[cfg(feature = "http2")]
        let has_override = has_override || http2.is_some();
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
        /// Freezes `connect_options` for a client without options in automatic mode.
        pub(crate) fn test(
            uri: Uri,
            protocol: Option<Protocol>,
            connect_options: Extensions,
        ) -> Self {
            Self::new(
                &uri,
                protocol,
                Protocol::Auto,
                connect_options,
                &Extensions::default(),
            )
            .unwrap()
        }
    }

    fn request(
        protocol: Option<Protocol>,
        connect_options: Extensions,
        client_options: &Extensions,
    ) -> ConnectRequest {
        let uri = Uri::from_static("https://localhost/upload?part=1");
        ConnectRequest::new(
            &uri,
            protocol,
            Protocol::Auto,
            connect_options,
            client_options,
        )
        .unwrap()
    }

    fn key(
        protocol: Option<Protocol>,
        connect_options: Extensions,
        client_options: &Extensions,
    ) -> ConnectionKey {
        request(protocol, connect_options, client_options).key()
    }

    fn with<T: Extension>(mut connect_options: Extensions, value: T) -> Extensions {
        connect_options.insert(value);
        connect_options
    }

    fn tls(alpn: AlpnProtocol) -> TlsOptions {
        TlsOptions::builder().alpn_protocols([alpn]).build()
    }

    #[test]
    fn keys_count_only_request_options_that_differ_from_the_client() {
        let client_options = with(Extensions::default(), tls(AlpnProtocol::HTTP2));
        let plain = key(None, Extensions::default(), &client_options);
        let hasher = lru::DefaultHasher::default();

        // Independently built equal options share the client's pool key.
        let inherited = with(Extensions::default(), tls(AlpnProtocol::HTTP2));
        let other = key(None, inherited, &client_options);
        assert_eq!(plain, other);
        assert_eq!(hasher.hash_one(&plain), hasher.hash_one(&other));

        let changed = request(
            None,
            with(Extensions::default(), tls(AlpnProtocol::HTTP1)),
            &client_options,
        );
        let mut changed = changed.key();
        assert_ne!(plain, changed);
        changed.hash = plain.hash;
        assert_ne!(plain, changed);
    }

    #[test]
    fn socket_bindings_keep_pool_identities_isolated() {
        use crate::conn::dialer;
        let mut client = Extensions::default();
        dialer::set_local_addresses(
            &mut client,
            Some(Ipv4Addr::LOCALHOST),
            Some(Ipv6Addr::LOCALHOST),
        );
        #[cfg(target_os = "linux")]
        dialer::set_interface(&mut client, "lo".into());
        let uri = Uri::from_static("https://localhost/");
        let partial = with(Extensions::default(), Ipv4Addr::LOCALHOST);
        let changed = with(Extensions::default(), Ipv4Addr::UNSPECIFIED);
        let mut merged = client.clone();
        merged.insert(Ipv4Addr::UNSPECIFIED);
        let check = |protocol| {
            let request = |config| {
                ConnectRequest::new(&uri, protocol, Protocol::Auto, config, &client).unwrap()
            };
            let inherited = request(Extensions::default());
            assert_eq!(request(partial.clone()).key(), inherited.key());
            let changed = request(changed.clone());
            assert_ne!(changed.key(), inherited.key());
            assert_eq!(request(merged.clone()).key(), changed.key());
            assert_ne!(
                request(with(Extensions::default(), Ipv6Addr::UNSPECIFIED)).key(),
                inherited.key()
            );
            #[cfg(target_os = "linux")]
            {
                let mut interface = Extensions::default();
                dialer::set_interface(&mut interface, String::from("lo").into());
                assert_eq!(request(interface.clone()).key(), inherited.key());
                dialer::set_interface(&mut interface, "eth0".into());
                assert_ne!(request(interface).key(), inherited.key());
            }
        };

        check(None);
        #[cfg(feature = "http3")]
        check(Some(Protocol::Http3));
    }

    #[test]
    fn keys_ignore_options_of_protocols_a_connection_cannot_use() {
        let client_options = Extensions::default();
        let http1 = with(
            Extensions::default(),
            Http1Options::builder().max_headers(8).build(),
        );
        let h1 = Some(Protocol::Http1);
        assert_ne!(
            key(h1, http1.clone(), &client_options),
            key(h1, Extensions::default(), &client_options)
        );
        #[cfg(feature = "http2")]
        {
            let http2 = with(
                Extensions::default(),
                Http2Options::builder().header_table_size(1024).build(),
            );

            let h2 = Some(Protocol::Http2);
            assert_eq!(
                key(h1, http2.clone(), &client_options),
                key(h1, Extensions::default(), &client_options)
            );
            assert_eq!(
                key(h2, http1.clone(), &client_options),
                key(h2, Extensions::default(), &client_options)
            );
            assert_ne!(
                key(None, http2.clone(), &client_options),
                key(None, Extensions::default(), &client_options)
            );

            // Another protocol selects again from the whole request storage.
            let probe = request(h1, http2, &client_options)
                .key_with_protocol(Protocol::Auto, &client_options);
            assert_ne!(probe, key(None, Extensions::default(), &client_options));
        }

        // Groups and proxies shape every connection.
        let proxy = crate::Proxy::all("http://localhost:8080")
            .unwrap()
            .into_matcher();
        for connect_options in [
            with(Extensions::default(), Group::new("tenant")),
            with(Extensions::default(), proxy),
        ] {
            assert_ne!(
                key(h1, connect_options, &client_options),
                key(h1, Extensions::default(), &client_options)
            );
        }

        #[cfg(feature = "http3")]
        {
            let h3 = Some(Protocol::Http3);
            let http3 = Http3Options::builder().max_field_section_size(1024).build();
            let quic = QuicOptions::builder().max_datagram_frame_size(1200).build();
            let h3_key = key(h3, Extensions::default(), &client_options);
            let auto_key = key(None, Extensions::default(), &client_options);
            let tcp = with(http1, tls(AlpnProtocol::HTTP1));
            assert_eq!(key(h3, tcp.clone(), &client_options), h3_key);

            let unused_tls = Arc::downgrade(&tcp.get_arc::<TlsOptions>().unwrap());
            let grouped = key(h3, with(tcp, Group::new("tenant")), &client_options);
            std::assert_matches!(unused_tls.upgrade(), None);
            assert_ne!(grouped, h3_key);
            for connect_options in [
                with(Extensions::default(), http3),
                with(Extensions::default(), quic),
            ] {
                assert_eq!(
                    key(None, connect_options.clone(), &client_options),
                    auto_key
                );
                assert_ne!(key(h3, connect_options, &client_options), h3_key);
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
                with(Extensions::default(), options(compressors)),
                &Extensions::default(),
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
