use std::{
    hash::BuildHasher,
    sync::{Arc, LazyLock},
};

use educe::Educe;
use http::{Uri, Version};
use lru::DefaultHasher;
use wreq_proto::{http1::Http1Options, http2::Http2Options};

use crate::{conn::net::SocketBindOptions, group::Group, proxy::Matcher, tls::TlsOptions};

/// Connection settings that may be overridden for one request.
/// The complete value becomes part of the pool identity before a connection
/// is selected or created.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub(crate) struct ConnectionOptions {
    /// Optional caller-defined pool partition.
    pub group: Option<Group>,

    /// Proxy matcher selected for this request.
    pub proxy: Option<Matcher>,

    /// Requested HTTP protocol version.
    pub version: Option<Version>,

    /// TLS settings that override the client configuration.
    pub tls_options: Option<TlsOptions>,

    /// HTTP/1 settings used if this connection negotiates HTTP/1.
    pub http1_options: Option<Http1Options>,

    /// HTTP/2 settings used if this connection negotiates HTTP/2.
    pub http2_options: Option<Http2Options>,

    /// Local addresses and interface used when opening the socket.
    pub socket_bind_options: Option<SocketBindOptions>,
}

impl ConnectionOptions {
    /// Records a wire-version change made after request construction.
    /// An unchanged wire version keeps the original optional override.
    #[inline]
    pub(crate) fn reconcile_version(&mut self, wire_version: Version, client_version: Version) {
        if wire_version != self.version.unwrap_or(client_version) {
            self.version = Some(wire_version);
        }
    }
}

impl_request_config_value!(ConnectionOptions);

/// A key identifying connections that are safe to interchange.
/// Clones share the immutable settings, while hashing uses the value computed
/// when the descriptor freezes those settings.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct ConnectionId(Arc<ConnectionIdentity>);

/// Immutable origin and settings used to create a physical connection.
/// Equality checks the full value, while pool hashing uses the cached hash.
#[derive(Debug, Educe)]
#[educe(PartialEq, Eq, Hash)]
struct ConnectionIdentity {
    #[educe(Hash(ignore))]
    origin: Uri,
    #[educe(Hash(ignore))]
    options: ConnectionOptions,
    #[educe(PartialEq(ignore))]
    hash: u64,
}

/// A connection blueprint and its current routing target.
/// Proxy routing may replace `route_uri`, but the frozen identity always
/// retains the original origin and compatibility settings.
#[must_use]
#[derive(Clone)]
pub(crate) struct ConnectionDescriptor {
    route_uri: Option<Uri>,
    connection_id: ConnectionId,
}

impl ConnectionDescriptor {
    /// Freezes the origin and connection options into a pool identity.
    pub(crate) fn new(origin: Uri, options: ConnectionOptions) -> Self {
        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let hash = HASHER.hash_one((&origin, &options));
        let identity = ConnectionIdentity {
            origin,
            options,
            hash,
        };

        Self {
            route_uri: None,
            connection_id: ConnectionId(Arc::new(identity)),
        }
    }

    /// Returns the immutable pool identity.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// Returns the current routing URI or the original origin.
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        self.route_uri
            .as_ref()
            .unwrap_or(&self.connection_id.0.origin)
    }

    /// Replaces only the routing target without changing pool compatibility.
    #[inline]
    pub(crate) fn set_uri(&mut self, uri: Uri) {
        self.route_uri = Some(uri);
    }

    /// Returns the settings frozen into this descriptor's identity.
    #[inline]
    pub(crate) fn options(&self) -> &ConnectionOptions {
        &self.connection_id.0.options
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;
    use crate::Proxy;

    fn hash(connection_id: &ConnectionId) -> u64 {
        let mut hasher = DefaultHasher::new();
        connection_id.hash(&mut hasher);
        hasher.finish()
    }

    fn descriptor(origin: &'static str, options: ConnectionOptions) -> ConnectionDescriptor {
        ConnectionDescriptor::new(Uri::from_static(origin), options)
    }

    #[test]
    fn connection_identity_includes_every_request_override() {
        let options = ConnectionOptions {
            group: Some(Group::new("partition")),
            version: Some(Version::HTTP_2),
            tls_options: Some(TlsOptions::builder().pre_shared_key(true).build()),
            http1_options: Some(Http1Options::builder().max_headers(64).build()),
            http2_options: Some(Http2Options::builder().header_table_size(4096).build()),
            ..Default::default()
        };
        let first = descriptor("https://example.test", options.clone()).id();
        let same = descriptor("https://example.test", options.clone()).id();

        assert_eq!(first, same);
        assert_eq!(hash(&first), hash(&same));

        let mut different_group = options.clone();
        different_group.group = Some(Group::new("other"));
        let mut different_proxy = options.clone();
        different_proxy.proxy = Some(
            Proxy::all("http://proxy.example:8080")
                .unwrap()
                .into_matcher(),
        );
        let mut different_version = options.clone();
        different_version.version = Some(Version::HTTP_11);
        let mut different_tls = options.clone();
        different_tls.tls_options = Some(TlsOptions::default());
        let mut different_http1 = options.clone();
        different_http1.http1_options = Some(Http1Options::builder().max_headers(32).build());
        let mut different_http2 = options.clone();
        different_http2.http2_options =
            Some(Http2Options::builder().header_table_size(8192).build());
        let mut different_socket = options.clone();
        different_socket.socket_bind_options = Some(SocketBindOptions::default());

        for different in [
            descriptor("https://other.test", options).id(),
            descriptor("https://example.test", different_group).id(),
            descriptor("https://example.test", different_proxy).id(),
            descriptor("https://example.test", different_version).id(),
            descriptor("https://example.test", different_tls).id(),
            descriptor("https://example.test", different_http1).id(),
            descriptor("https://example.test", different_http2).id(),
            descriptor("https://example.test", different_socket).id(),
        ] {
            assert_ne!(first, different);
        }

        let mut routed = descriptor("https://example.test", ConnectionOptions::default());
        let identity = routed.id();
        routed.set_uri(Uri::from_static("http://proxy.example:8080"));
        assert_eq!(routed.id(), identity);
        assert_eq!(routed.uri(), &Uri::from_static("http://proxy.example:8080"));
    }
}
