//! Frozen connection inputs and their pool identity.

use std::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
};

use http::{Uri, uri::PathAndQuery};
use netty::http1::Http1Options;
#[cfg(feature = "http2")]
use netty::http2::Http2Options;
#[cfg(feature = "http3")]
use {crate::quic::QuicOptions, netty::http3::Http3Options};

use super::dialer::Interface;
use crate::{
    config::connect::{Extension, Extensions, HASHER, KeyPart, Projection, Selection},
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
    origin: Uri,
    protocol: Protocol,
    connect_options: Extensions,
    pool_selection: Selection,
    pool_hash: u64,
}

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
/// Clones share configuration values.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    /// Selection after inheriting the client's; configuration, not the negotiated version.
    protocol: Protocol,
    overrides: Projection,
    hash: u64,
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Validates the absolute target and freezes the connection inputs.
    ///
    /// The origin keeps scheme and authority with `/` as the path. The pool key uses the
    /// resolved protocol and its request overrides that differ from the client's settings.
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
        let pool_selection = pool_selection(protocol, &connect_options, client_options);
        let pool_hash = pool_hash(&origin, protocol, pool_selection);
        Ok(Self {
            origin,
            protocol,
            connect_options,
            pool_selection,
            pool_hash,
        })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Pool and session keys use this origin, not the request's path or query.
    /// Proxy routing leaves it unchanged.
    pub(crate) fn uri(&self) -> &Uri {
        &self.origin
    }

    /// Returns the protocol selection after inheriting the client's preference.
    /// Frozen before pool checkout; proxy routing does not change this selection.
    pub(crate) fn resolved_protocol(&self) -> Protocol {
        self.protocol
    }

    /// All request connection options, including those outside the pool identity.
    pub(crate) fn connect_options(&self) -> &Extensions {
        &self.connect_options
    }

    /// Returns the override used by the pool entry's handshake builder.
    #[inline]
    pub(crate) fn pool_override<T: Extension>(&self) -> Option<&T> {
        self.pool_selection.get_ref::<T>(&self.connect_options)
    }

    /// Returns the reuse identity of this origin and configuration.
    pub(crate) fn key(&self) -> ConnectionKey {
        ConnectionKey {
            origin: self.origin.clone(),
            protocol: self.protocol,
            overrides: self.pool_selection.key(&self.connect_options),
            hash: self.pool_hash,
        }
    }

    /// Returns the identity of this origin and configuration under another resolved protocol.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(crate) fn key_with_protocol(
        &self,
        protocol: Protocol,
        client_options: &Extensions,
    ) -> ConnectionKey {
        let selection = pool_selection(protocol, &self.connect_options, client_options);
        ConnectionKey {
            origin: self.origin.clone(),
            protocol,
            overrides: selection.key(&self.connect_options),
            hash: pool_hash(&self.origin, protocol, selection),
        }
    }
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("origin", &self.origin)
            .field("protocol", &self.protocol)
            .field("options", &self.pool_selection.key(&self.connect_options))
            .field("pool_hash", &self.pool_hash)
            .finish()
    }
}

// ===== impl ConnectionKey =====

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
            .field("overrides", &self.overrides)
            .finish()
    }
}

fn pool_selection(protocol: Protocol, request: &Extensions, client: &Extensions) -> Selection {
    let mut selection = Selection::new(KeyPart::Whole);
    if request.is_empty() {
        return selection;
    }

    selection.include::<Group>(request, client);
    selection.include::<Matcher>(request, client);
    selection.include::<Ipv4Addr>(request, client);
    selection.include::<Ipv6Addr>(request, client);
    selection.include::<Interface>(request, client);

    match protocol {
        Protocol::Auto => {
            selection.include::<Http1Options>(request, client);
            #[cfg(feature = "http2")]
            selection.include::<Http2Options>(request, client);
        }
        Protocol::Http1 => selection.include::<Http1Options>(request, client),
        #[cfg(feature = "http2")]
        Protocol::Http2 => selection.include::<Http2Options>(request, client),
        #[cfg(feature = "http3")]
        Protocol::Http3 => {
            selection.include::<Http3Options>(request, client);
            selection.include::<QuicOptions>(request, client);
            return selection;
        }
    }
    selection.include::<TlsOptions>(request, client);
    selection
}

fn pool_hash(origin: &Uri, protocol: Protocol, selection: Selection) -> u64 {
    HASHER.hash_one((origin, protocol, selection.hash()))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{config::connect::ConnectConfig, tls::AlpnProtocol};

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
        assert_ne!(plain, changed.key());
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
        for protocol in [
            None,
            #[cfg(feature = "http3")]
            Some(Protocol::Http3),
        ] {
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
        }
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
            assert_eq!(key(h3, tcp, &client_options), h3_key);
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
