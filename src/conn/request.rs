//! Typed connection configuration shared by pool lookup and transport setup.
//!
//! Configuration is editable before the connection request is constructed. Once frozen,
//! its values define reuse identity and must remain stable for its lifetime.

use std::{
    hash::{BuildHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
};

use http::Uri;
use lru::DefaultHasher;

use super::Extra;
use crate::{HttpVersion, error::BoxError};

/// Connection request shared by pool lookup and transport connection attempts.
/// Exposes the frozen origin, protocol choice, and typed connection data.
/// A proxy may change the route without changing the original reuse identity.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    inner: Arc<RequestData>,
    route_uri: Option<Uri>,
}

/// Value identity for interchangeable connections.
/// Pool entries and TLS sessions share the request's frozen configuration.
/// Cached hashes accelerate lookup; equality still checks the complete values.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionKey(Arc<RequestData>);

/// Immutable values backing a connection request and its pool/session keys.
/// The hash is computed once when request configuration is frozen.
/// Neither routing changes nor protocol builders are retained here.
#[derive(Debug)]
struct RequestData {
    uri: Uri,
    version: Option<HttpVersion>,
    extra: Extra,
    hash: u64,
}

/// Local addresses and interface selected for an outbound socket.
/// Request configuration applies these bindings before a transport connects.
/// Connection configuration retains the values to prevent incompatible reuse.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SocketOptions {
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    pub interface: Option<std::borrow::Cow<'static, str>>,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Validates the absolute target and freezes its connection configuration.
    /// The origin retains scheme and authority; its path is replaced with `/`.
    /// Only configuration in `extra` contributes to the cached reuse identity.
    ///
    /// Returns an error if the URI lacks a scheme or authority, or rebuilding
    /// the origin fails. The caller retains the HTTP request's original target.
    pub(crate) fn new(
        uri: Uri,
        version: Option<HttpVersion>,
        extra: Extra,
    ) -> Result<Self, BoxError> {
        let uri = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query("/")
            .build()?;
        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let mut hasher = HASHER.build_hasher();
        (&uri, version).hash(&mut hasher);
        extra.hash(&mut hasher);
        let hash = hasher.finish();
        Ok(Self {
            inner: Arc::new(RequestData {
                uri,
                version,
                extra,
                hash,
            }),
            route_uri: None,
        })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Pool and session keys use this origin, not the request's path or query.
    /// Proxy routing leaves it unchanged; use `route_uri` for transport setup.
    pub(crate) fn uri(&self) -> &Uri {
        &self.inner.uri
    }

    /// Returns the request's connection protocol preference.
    /// None inherits the client; Auto explicitly allows protocol negotiation.
    /// This is a selection policy, not the established connection's wire version.
    pub(crate) fn version(&self) -> Option<HttpVersion> {
        self.inner.version
    }

    /// Borrows the typed configuration and metadata frozen into this request.
    /// Only configuration participates in reuse identity; metadata is ignored.
    /// No mutable access is exposed, so clones and existing keys remain stable.
    pub(crate) fn extra(&self) -> &Extra {
        &self.inner.extra
    }

    /// Shares the original origin, protocol preference, and configuration identity.
    /// Lookup reuses a cached hash but still compares complete configuration values.
    /// The key keeps those values alive independently of this request's route.
    pub(crate) fn key(&self) -> ConnectionKey {
        ConnectionKey(self.inner.clone())
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

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.hash == other.0.hash
                && self.0.uri == other.0.uri
                && self.0.version == other.0.version
                && self.0.extra == other.0.extra)
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Repeated pool/session lookups do not rehash the full configuration.
        state.write_u64(self.0.hash);
    }
}

// ===== impl SocketOptions =====

impl SocketOptions {
    /// Selects the interface used when opening the outbound socket.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    pub(crate) fn set_interface<I>(&mut self, interface: I) -> &mut Self
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        self.interface = Some(interface.into());
        self
    }

    pub(crate) fn set_local_address<V>(&mut self, address: V)
    where
        V: Into<Option<IpAddr>>,
    {
        match address.into() {
            Some(IpAddr::V4(address)) => self.ipv4_address = Some(address),
            Some(IpAddr::V6(address)) => self.ipv6_address = Some(address),
            None => {}
        }
    }

    pub(crate) fn set_local_addresses<V4, V6>(&mut self, ipv4: V4, ipv6: V6)
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        if let Some(address) = ipv4.into() {
            self.ipv4_address = Some(address);
        }
        if let Some(address) = ipv6.into() {
            self.ipv6_address = Some(address);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, hash::DefaultHasher};

    use super::*;
    use crate::{
        group::Group,
        http1::Http1Options,
        http2::Http2Options,
        tls::{AlpnProtocol, TlsOptions},
    };

    fn request(extra: Extra) -> ConnectRequest {
        ConnectRequest::new(
            "https://localhost/upload?part=1".parse().unwrap(),
            None,
            extra,
        )
        .unwrap()
    }

    fn hash(value: &impl Hash) -> u64 {
        let mut state = DefaultHasher::new();
        value.hash(&mut state);
        state.finish()
    }

    #[test]
    fn typed_extensions_freeze_value_identity() {
        let mut first = Extra::default();
        *first.config_or_default::<u32>() = 6;
        *first.config_or_default::<u32>() += 1;
        first.insert_config(Cow::Borrowed("config"));
        let frozen = request(first.clone());
        let mut second = Extra::default();
        second.insert_config(Cow::<'static, str>::Owned("config".into()));
        second.insert_config(7_u32);
        // Ordinary metadata neither partitions reuse nor needs value identity.
        second.insert(Arc::new(std::sync::atomic::AtomicUsize::new(1)));
        assert_eq!(first, second);
        assert_eq!(hash(&first), hash(&second));
        assert_eq!(frozen.key(), request(second.clone()).key());
        assert_eq!(hash(&frozen.key()), hash(&request(second.clone()).key()));
        second.insert_config(9_u32);
        assert_ne!(first, second);
        assert_eq!(frozen.extra().get::<u32>(), Some(&7));
        assert_ne!(frozen.key(), request(second.clone()).key());
        second.remove::<u32>();
        assert!(second.get::<u32>().is_none());
        second.insert_config(7_u64);
        assert_ne!(frozen.key(), request(second).key());
        *first.config_or_default::<u32>() = 8;
        assert_eq!(first.get::<u32>(), Some(&8));
        assert_eq!(frozen.extra().get::<u32>(), Some(&7));
        assert_ne!(frozen.key(), request(first.clone()).key());
        first.set_config::<u32>(None);
        assert!(first.get::<u32>().is_none());

        let rerouted = frozen
            .clone()
            .with_route_uri("https://proxy:8443/".parse().unwrap());
        assert_eq!(rerouted.uri(), "https://localhost/");
        assert_eq!(rerouted.route_uri(), "https://proxy:8443/");
        assert_eq!(rerouted.key(), frozen.key());
        assert_eq!(hash(&rerouted.key()), hash(&frozen.key()));
        assert!(ConnectRequest::new("/relative".parse().unwrap(), None, Extra::default()).is_err());

        // A cached-hash collision must still compare all frozen values.
        let mut collision = request(Extra::default());
        Arc::get_mut(&mut collision.inner).unwrap().hash = frozen.inner.hash;
        assert_ne!(collision.key(), frozen.key());
    }

    #[test]
    fn connection_options_partition_reuse_by_value() {
        let tls_options = TlsOptions::builder()
            .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
            .build();
        let mut extra = Extra::default();
        extra.insert_config(tls_options);
        extra.insert_config(Http1Options::builder().max_headers(32).build());
        extra.insert_config(Http2Options::builder().header_table_size(4096).build());
        let baseline = request(extra.clone()).key();
        assert_eq!(baseline, request(extra.clone()).key());

        let mut variants = Vec::new();
        let mut changed = extra.clone();
        changed.insert_config(
            TlsOptions::builder()
                .alpn_protocols([AlpnProtocol::HTTP1, AlpnProtocol::HTTP2])
                .build(),
        );
        variants.push(changed);
        let mut changed = extra.clone();
        changed.insert_config(Http1Options::builder().max_headers(64).build());
        variants.push(changed);
        let mut changed = extra.clone();
        changed.insert_config(Http2Options::builder().header_table_size(8192).build());
        variants.push(changed);
        let mut changed = extra.clone();
        changed.insert_config(Group::new("tenant"));
        variants.push(changed);
        let mut changed = extra.clone();
        changed.insert_config(
            crate::Proxy::all("http://localhost:8080")
                .unwrap()
                .into_matcher(),
        );
        variants.push(changed);
        let mut changed = extra.clone();
        changed.insert_config(SocketOptions {
            ipv4_address: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        });
        variants.push(changed);
        for changed in variants {
            assert_ne!(baseline, request(changed).key());
        }
        let explicit = ConnectRequest::new(
            "https://localhost/".parse().unwrap(),
            Some(HttpVersion::Auto),
            extra,
        )
        .unwrap();
        assert_ne!(baseline, explicit.key());
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
        let key = |compressors: Option<Vec<&'static dyn CertificateCompressor>>| {
            let mut extra = Extra::default();
            extra.insert_config(TlsOptions {
                certificate_compressors: compressors.map(Cow::Owned),
                ..Default::default()
            });
            request(extra).key()
        };
        let first = key(Some(vec![&FIRST, &BROTLI]));
        let second = key(Some(vec![&SECOND, &BROTLI]));
        assert_eq!(first, second);
        assert_eq!(hash(&first), hash(&second));
        assert_ne!(first, key(Some(vec![&BROTLI, &FIRST])));
        assert_eq!(key(None), key(Some(vec![])));
    }
}
