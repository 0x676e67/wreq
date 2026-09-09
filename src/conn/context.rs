//! Typed connection configuration shared by pool lookup and transport setup.
//!
//! Extensions are editable before the context is constructed. Once frozen,
//! their values define reuse identity and must remain stable for its lifetime.

use std::{
    any::{Any, TypeId, type_name},
    collections::BTreeMap,
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
};

use http::Uri;
use lru::DefaultHasher;

use crate::{HttpVersion, error::BoxError};

/// Input context shared by pool lookup and transport connection attempts.
/// Exposes the frozen origin, protocol choice, and typed connection extensions.
/// A proxy may change the route without changing the original reuse identity.
#[derive(Debug, Clone)]
pub struct ConnectContext {
    inner: Arc<ContextData>,
    route_uri: Option<Uri>,
}

/// Value identity for interchangeable connections.
/// Pool entries and TLS sessions share the frozen connection context.
/// Cached hashes accelerate lookup; equality still checks the complete values.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionKey(Arc<ContextData>);

/// Immutable values backing a context and its pool/session keys.
/// The hash is computed once when request configuration is frozen.
/// Neither routing changes nor protocol builders are retained here.
#[derive(Debug)]
struct ContextData {
    uri: Uri,
    version: Option<HttpVersion>,
    extensions: Extensions,
    hash: u64,
}

/// Type-indexed connection settings with value equality and hashing.
/// Clones share stored values; replacement leaves existing contexts unchanged.
/// Values must keep their Eq/Hash identity stable while a context retains them.
#[derive(Default, Clone)]
pub(crate) struct Extensions(BTreeMap<TypeId, Arc<dyn Value>>);

trait Value: Any + Send + Sync {
    fn equals(&self, other: &dyn Value) -> bool;
    fn hash_value(&self, state: &mut dyn Hasher);
    fn type_name(&self) -> &'static str;
}

/// Local addresses and interface selected for an outbound socket.
/// Request configuration applies these bindings before a transport connects.
/// Connection extensions retain the values to prevent incompatible reuse.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BindOptions {
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

// ===== impl ConnectContext =====

impl ConnectContext {
    /// Validates the absolute target and freezes its connection configuration.
    /// Paths and queries belong to HTTP requests and are excluded from the key.
    pub(crate) fn new(
        uri: Uri,
        version: Option<HttpVersion>,
        extensions: Extensions,
    ) -> Result<Self, BoxError> {
        let uri = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query("/")
            .build()?;
        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let hash = HASHER.hash_one((&uri, version, &extensions));
        Ok(Self {
            inner: Arc::new(ContextData {
                uri,
                version,
                extensions,
                hash,
            }),
            route_uri: None,
        })
    }

    pub(crate) fn uri(&self) -> &Uri {
        &self.inner.uri
    }

    /// None inherits the client; Auto explicitly allows protocol negotiation.
    pub(crate) fn version(&self) -> Option<HttpVersion> {
        self.inner.version
    }

    pub(crate) fn extensions(&self) -> &Extensions {
        &self.inner.extensions
    }

    pub(crate) fn key(&self) -> ConnectionKey {
        ConnectionKey(self.inner.clone())
    }

    pub(crate) fn route_uri(&self) -> &Uri {
        self.route_uri.as_ref().unwrap_or_else(|| self.uri())
    }

    /// Changes the transport address without changing origin or reuse identity.
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
                && self.0.extensions == other.0.extensions)
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Repeated pool/session lookups do not rehash the full configuration.
        state.write_u64(self.0.hash);
    }
}

// ===== impl Extensions =====

impl Extensions {
    /// Stores one value per Rust type, returning the replaced value if present.
    pub(crate) fn insert<T>(&mut self, value: T) -> Option<T>
    where
        T: Clone + Eq + Hash + Send + Sync + 'static,
    {
        self.0
            .insert(TypeId::of::<T>(), Arc::new(value))
            .and_then(|value| {
                let value: Arc<dyn Any + Send + Sync> = value;
                value.downcast::<T>().ok().map(Arc::unwrap_or_clone)
            })
    }

    pub(crate) fn get<T: 'static>(&self) -> Option<&T> {
        self.0
            .get(&TypeId::of::<T>())
            .and_then(|value| (value.as_ref() as &dyn Any).downcast_ref())
    }

    /// Replaces an optional setting, removing the previous value when absent.
    pub(crate) fn set<T>(&mut self, value: Option<T>)
    where
        T: Clone + Eq + Hash + Send + Sync + 'static,
    {
        // Unlike insert/remove, discarded shared values need no owned clone.
        match value {
            Some(value) => self.0.insert(TypeId::of::<T>(), Arc::new(value)),
            None => self.0.remove(&TypeId::of::<T>()),
        };
    }

    pub(crate) fn remove<T: Clone + Send + Sync + 'static>(&mut self) -> Option<T> {
        self.0.remove(&TypeId::of::<T>()).and_then(|value| {
            let value: Arc<dyn Any + Send + Sync> = value;
            value.downcast::<T>().ok().map(Arc::unwrap_or_clone)
        })
    }
}

impl PartialEq for Extensions {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().zip(&other.0).all(|((a, left), (b, right))| {
                a == b && (Arc::ptr_eq(left, right) || left.equals(right.as_ref()))
            })
    }
}

impl Eq for Extensions {}

impl Hash for Extensions {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // TypeId ordering makes identity independent of insertion order.
        // These hashes are process-local, not a serialized configuration format.
        self.0.len().hash(state);
        for (id, value) in &self.0 {
            id.hash(state);
            value.hash_value(state);
        }
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.0.values().map(|value| value.type_name()))
            .finish()
    }
}

// ===== impl Value =====

impl<T: Eq + Hash + Send + Sync + 'static> Value for T {
    fn equals(&self, other: &dyn Value) -> bool {
        (other as &dyn Any).downcast_ref::<T>() == Some(self)
    }

    fn hash_value(&self, mut state: &mut dyn Hasher) {
        self.hash(&mut state);
    }

    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

// ===== impl BindOptions =====

impl BindOptions {
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

    fn context(extensions: Extensions) -> ConnectContext {
        ConnectContext::new(
            "https://localhost/upload?part=1".parse().unwrap(),
            None,
            extensions,
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
        let mut first = Extensions::default();
        first.insert(7_u32);
        first.insert(Cow::Borrowed("config"));
        let frozen = context(first.clone());
        let mut second = Extensions::default();
        second.insert(Cow::<'static, str>::Owned("config".into()));
        second.insert(7_u32);
        assert_eq!(frozen.key(), context(second.clone()).key());
        assert_eq!(hash(&first), hash(&second));
        assert_eq!(second.insert(9_u32), Some(7));
        assert_eq!(frozen.extensions().get::<u32>(), Some(&7));
        assert_ne!(frozen.key(), context(second.clone()).key());
        assert_eq!(second.remove::<u32>(), Some(9));
        second.insert(7_u64);
        assert_ne!(frozen.key(), context(second).key());
        first.set::<u32>(None);
        assert!(first.get::<u32>().is_none());

        let rerouted = frozen
            .clone()
            .with_route_uri("https://proxy:8443/".parse().unwrap());
        assert_eq!(rerouted.uri(), "https://localhost/");
        assert_eq!(rerouted.route_uri(), "https://proxy:8443/");
        assert_eq!(rerouted.key(), frozen.key());
        assert_eq!(hash(&rerouted.key()), hash(&frozen.key()));
        assert!(
            ConnectContext::new("/relative".parse().unwrap(), None, Extensions::default()).is_err()
        );

        // A cached-hash collision must still compare all frozen values.
        let mut collision = context(Extensions::default());
        Arc::get_mut(&mut collision.inner).unwrap().hash = frozen.inner.hash;
        assert_ne!(collision.key(), frozen.key());
    }

    #[test]
    fn connection_options_partition_reuse_by_value() {
        let tls_options = TlsOptions::builder()
            .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
            .build();
        let mut extensions = Extensions::default();
        extensions.insert(tls_options);
        extensions.insert(Http1Options::builder().max_headers(32).build());
        extensions.insert(Http2Options::builder().header_table_size(4096).build());
        let baseline = context(extensions.clone()).key();
        assert_eq!(baseline, context(extensions.clone()).key());

        let mut variants = Vec::new();
        let mut changed = extensions.clone();
        changed.insert(
            TlsOptions::builder()
                .alpn_protocols([AlpnProtocol::HTTP1, AlpnProtocol::HTTP2])
                .build(),
        );
        variants.push(changed);
        let mut changed = extensions.clone();
        changed.insert(Http1Options::builder().max_headers(64).build());
        variants.push(changed);
        let mut changed = extensions.clone();
        changed.insert(Http2Options::builder().header_table_size(8192).build());
        variants.push(changed);
        let mut changed = extensions.clone();
        changed.insert(Group::new("tenant"));
        variants.push(changed);
        let mut changed = extensions.clone();
        changed.insert(
            crate::Proxy::all("http://localhost:8080")
                .unwrap()
                .into_matcher(),
        );
        variants.push(changed);
        let mut changed = extensions.clone();
        changed.insert(BindOptions {
            ipv4_address: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        });
        variants.push(changed);
        for changed in variants {
            assert_ne!(baseline, context(changed).key());
        }
        let explicit = ConnectContext::new(
            "https://localhost/".parse().unwrap(),
            Some(HttpVersion::Auto),
            extensions,
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
            let mut extensions = Extensions::default();
            extensions.insert(TlsOptions {
                certificate_compressors: compressors.map(Cow::Owned),
                ..Default::default()
            });
            context(extensions).key()
        };
        let first = key(Some(vec![&FIRST, &BROTLI]));
        let second = key(Some(vec![&SECOND, &BROTLI]));
        assert_eq!(first, second);
        assert_eq!(hash(&first), hash(&second));
        assert_ne!(first, key(Some(vec![&BROTLI, &FIRST])));
        assert_eq!(key(None), key(Some(vec![])));
    }
}
