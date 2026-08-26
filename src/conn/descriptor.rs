use std::{
    hash::BuildHasher,
    sync::{Arc, LazyLock},
};

use educe::Educe;
use http::{Uri, Version};
use lru::DefaultHasher;

use crate::{conn::net::SocketBindOptions, group::Group, proxy::Matcher, tls::TlsOptions};

/// A key that uniquely identifies a group of interchangeable connections for pooling.
///
/// This ID is derived from all parameters that define a connection endpoint,
/// such as URI, proxy, and local socket bindings. Connections with the same
/// ID are considered equivalent and can be reused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ConnectionId(Arc<ConnectionIdentity>);

/// Immutable connection identity and its precomputed hash.
/// The hash avoids traversing the full identity during pool lookups.
#[derive(Debug, Educe)]
#[educe(PartialEq, Eq, Hash)]
struct ConnectionIdentity {
    #[educe(Hash(ignore))]
    group: Group,
    #[educe(Hash(ignore))]
    tls_options: Option<TlsOptions>,
    #[educe(PartialEq(ignore))]
    hash: u64,
}

/// A blueprint for creating a new client connection, containing all necessary parameters.
///
/// This descriptor bundles the target `Uri`, HTTP version, `TlsOptions`, proxy settings,
/// and other configurations needed to establish a connection.
#[must_use]
#[derive(Clone)]
pub(crate) struct ConnectionDescriptor {
    uri: Uri,
    version: Option<Version>,
    proxy: Option<Matcher>,
    socket_bind: Option<SocketBindOptions>,
    connection_id: ConnectionId,
}

// ===== impl ConnectionDescriptor =====

impl ConnectionDescriptor {
    /// Create a new [`ConnectionDescriptor`].
    pub(crate) fn new(
        uri: Uri,
        mut group: Group,
        proxy: Option<Matcher>,
        version: Option<Version>,
        tls_options: Option<TlsOptions>,
        socket_bind: Option<SocketBindOptions>,
    ) -> ConnectionDescriptor {
        let connection_id = {
            group
                .uri(uri.clone())
                .version(version)
                .proxy(proxy.clone())
                .socket_bind(socket_bind.clone());
            static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
            let hash = HASHER.hash_one((&group, &tls_options));
            ConnectionId(Arc::new(ConnectionIdentity {
                group,
                tls_options,
                hash,
            }))
        };

        ConnectionDescriptor {
            uri,
            proxy,
            version,
            socket_bind,
            connection_id,
        }
    }

    /// Returns a [`ConnectionId`] group ID for this descriptor.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Return the negotiated HTTP version, if any.
    pub(crate) fn version(&self) -> Option<Version> {
        self.version
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.connection_id.0.tls_options.as_ref()
    }

    /// Return a reference to the [`Matcher`].
    #[inline]
    pub(crate) fn proxy(&self) -> Option<&Matcher> {
        self.proxy.as_ref()
    }

    /// Return a reference to the [`SocketBindOptions`].
    #[inline]
    pub(crate) fn socket_bind_options(&self) -> Option<&SocketBindOptions> {
        self.socket_bind.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;

    fn hash(connection_id: &ConnectionId) -> u64 {
        let mut hasher = DefaultHasher::new();
        connection_id.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn connection_identity_includes_tls_options() {
        let descriptor = |tls_options| {
            ConnectionDescriptor::new(
                Uri::from_static("https://example.test"),
                Group::new("tls-options"),
                None,
                None,
                Some(tls_options),
                None,
            )
        };
        let first = TlsOptions::builder().pre_shared_key(true).build();
        let same = first.clone();
        let different = TlsOptions::builder().pre_shared_key(false).build();

        let first = descriptor(first).id();
        let same = descriptor(same).id();
        let different = descriptor(different).id();

        assert_eq!(first, same);
        assert_eq!(hash(&first), hash(&same));
        assert_ne!(first, different);
    }
}
