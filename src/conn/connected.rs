//! Metadata of an established connection: addresses, negotiated protocol, proxy identity and
//! values copied into every response. Each transport path builds it once after connecting.

use std::{
    any::{TypeId, type_name},
    fmt::{self, Debug, Formatter},
    iter,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ::http::{Extensions, HeaderMap, HeaderValue};
use btls::x509::X509Ref;
use bytes::Bytes;

use crate::{proxy::matcher::Intercept, tls::TlsInfo};

/// Local and remote socket addresses captured after connecting a transport.
/// Stored in connection metadata and attached to response extensions.
/// Custom transports may omit this information.
#[derive(Clone, Debug)]
pub(crate) struct HttpInfo {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
}

/// Metadata describing the established transport and its negotiated protocol.
/// Carries proxy details and extra values copied into response extensions.
/// Clones share the poison flag so reuse can be disabled from any response.
#[derive(Debug, Clone)]
pub struct Connected {
    negotiated_h2: bool,
    proxy: Arc<ProxyIdentity>,
    metadata: Metadata,
    poisoned: PoisonPill,
}

/// Shared reuse status for an established connection.
/// Poisoning any clone prevents the transport from returning to the pool.
/// The flag stays alive while connection metadata still references it.
#[derive(Clone)]
struct PoisonPill(Arc<AtomicBool>);

/// Information about an HTTP proxy identity.
/// Carries forward-proxy status, credentials, and headers for request preparation.
/// Connection clones share it; updates use copy-on-write to preserve other clones.
#[derive(Debug, Default, Clone)]
struct ProxyIdentity {
    is_proxied: bool,
    auth: Option<HeaderValue>,
    headers: Option<HeaderMap>,
}

/// Shared response metadata, ordered by concrete type.
/// Edits copy shared handles; values are cloned only when exported to a response.
#[derive(Clone, Default)]
#[expect(clippy::type_complexity)]
struct Metadata(Option<Arc<[(TypeId, Arc<dyn MetadataValue>)]>>);

trait MetadataValue: Send + Sync {
    fn copy_to(&self, extensions: &mut Extensions);
    fn type_name(&self) -> &'static str;
}

/// Converts the peer's leaf certificate and chain to DER, skipping certificates that fail.
pub(super) fn tls_info<'a>(
    leaf: Option<&X509Ref>,
    chain: Option<impl IntoIterator<Item = &'a X509Ref>>,
) -> TlsInfo {
    let der = |cert: &X509Ref| cert.to_der().ok().map(Bytes::from);
    TlsInfo {
        peer_certificate: leaf.and_then(der),
        peer_certificate_chain: chain.map(|chain| chain.into_iter().filter_map(der).collect()),
    }
}

// ===== impl HttpInfo =====

impl HttpInfo {
    /// Get the remote address of the transport used.
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address of the transport used.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ===== impl Connected =====

impl Connected {
    /// Create new `Connected` type with empty metadata.
    pub fn new() -> Connected {
        Connected {
            negotiated_h2: false,
            proxy: Arc::new(ProxyIdentity::default()),
            metadata: Metadata::default(),
            poisoned: PoisonPill::healthy(),
        }
    }

    /// Attaches metadata copied into the extensions of every response.
    /// A later value replaces an earlier value of the same Rust type.
    /// Other connection clones retain their existing metadata.
    pub fn extra<T: Clone + Send + Sync + 'static>(mut self, extra: T) -> Connected {
        self.metadata.insert(extra);
        self
    }

    /// Copies attached metadata into response extensions by concrete Rust type.
    /// Each stored metadata value is cloned once.
    #[inline]
    pub fn set_extras(&self, extensions: &mut Extensions) {
        self.metadata.copy_to(extensions);
    }

    /// Set that the proxy was used for this connected transport.
    pub fn proxy(mut self, proxy: Intercept) -> Connected {
        let identity = Arc::make_mut(&mut self.proxy);
        identity.is_proxied = true;

        if let Some(auth) = proxy.basic_auth() {
            identity.auth.replace(auth.clone());
        }

        if let Some(headers) = proxy.custom_headers() {
            identity.headers.replace(headers.clone());
        }

        self
    }

    /// Determines if the connected transport is to an HTTP proxy.
    #[inline]
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_proxied
    }

    /// Get the proxy identity information for the connected transport.
    #[inline]
    pub fn proxy_auth(&self) -> Option<&HeaderValue> {
        self.proxy.auth.as_ref()
    }

    /// Get the custom proxy headers for the connected transport.
    #[inline]
    pub fn proxy_headers(&self) -> Option<&HeaderMap> {
        self.proxy.headers.as_ref()
    }

    /// Set that the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn negotiated_h2(mut self) -> Connected {
        self.negotiated_h2 = true;
        self
    }

    /// Determines if the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn is_negotiated_h2(&self) -> bool {
        self.negotiated_h2
    }

    /// Determine if this connection is poisoned
    #[inline]
    pub fn poisoned(&self) -> bool {
        self.poisoned.0.load(Ordering::Relaxed)
    }

    /// Poison this connection
    ///
    /// A poisoned connection will not be reused for subsequent requests by the pool
    #[inline]
    pub fn poison(&self) {
        self.poisoned.0.store(true, Ordering::Relaxed);
        debug!(
            "connection was poisoned. this connection will not be reused for subsequent requests"
        );
    }
}

// ===== impl PoisonPill =====

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill, which makes debugging issues much easier
        write!(
            f,
            "PoisonPill@{:p} {{ poisoned: {} }}",
            self.0,
            self.0.load(Ordering::Relaxed)
        )
    }
}

impl PoisonPill {
    /// Create a healthy (not poisoned) pill.
    #[inline]
    fn healthy() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}

// ===== impl Metadata =====

impl Metadata {
    fn insert<T: Clone + Send + Sync + 'static>(&mut self, value: T) {
        let entries = self.0.as_deref().unwrap_or_default();
        let id = TypeId::of::<T>();
        let (index, replaced) = match entries.binary_search_by_key(&id, |entry| entry.0) {
            Ok(index) => (index, 1),
            Err(index) => (index, 0),
        };
        let value: Arc<dyn MetadataValue> = Arc::new(value);
        self.0 = Some(
            entries[..index]
                .iter()
                .cloned()
                .chain(iter::once((id, value)))
                .chain(entries[index + replaced..].iter().cloned())
                .collect(),
        );
    }

    fn copy_to(&self, extensions: &mut Extensions) {
        for (_, value) in self.0.as_deref().unwrap_or_default() {
            value.as_ref().copy_to(extensions);
        }
    }
}

impl Debug for Metadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(
                self.0
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|(_, value)| value.as_ref().type_name()),
            )
            .finish()
    }
}

// ===== impl MetadataValue =====

impl<T: Clone + Send + Sync + 'static> MetadataValue for T {
    fn copy_to(&self, extensions: &mut Extensions) {
        extensions.insert(self.clone());
    }

    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use ::http::header::VIA;

    use super::*;

    /// Counts metadata value clones independently of shared handle clones.
    #[derive(Debug)]
    struct CloneCount(Arc<AtomicUsize>);

    impl Clone for CloneCount {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }

    #[test]
    fn connected_shares_metadata_without_changing_response_extras() {
        let clones = Arc::new(AtomicUsize::new(0));
        let original = Connected::new()
            .extra(CloneCount(clones.clone()))
            .extra(String::from("original"));
        let changed = original
            .clone()
            .extra(42_u32)
            .extra(CloneCount(clones.clone()))
            .extra(String::from("changed"));
        let proxy = crate::Proxy::http("http://localhost:8080")
            .unwrap()
            .basic_auth("user", "password")
            .custom_http_headers(HeaderMap::from_iter([(
                VIA,
                HeaderValue::from_static("1.1 localhost"),
            )]))
            .into_matcher();
        let proxy = match proxy.intercept(&"http://localhost/".parse().unwrap()) {
            Some(crate::proxy::Intercepted::Proxy(proxy)) => proxy,
            _ => unreachable!("expected HTTP proxy"),
        };
        let changed = changed.proxy(proxy).negotiated_h2();
        assert_eq!(clones.load(Ordering::Relaxed), 0);
        assert!(!original.is_proxied());
        assert!(!original.is_negotiated_h2());
        assert_eq!(original.proxy_auth(), None);
        assert_eq!(original.proxy_headers(), None);
        assert!(changed.is_proxied());
        assert!(changed.proxy_auth().is_some());
        assert_eq!(changed.proxy_headers().unwrap()[VIA], "1.1 localhost");

        for (connected, value) in [(&original, "original"), (&changed, "changed")] {
            let mut extensions = Extensions::new();
            connected.set_extras(&mut extensions);
            assert_eq!(extensions.get::<String>().unwrap(), value);
            assert!(extensions.get::<CloneCount>().is_some());
            assert_eq!(
                extensions.get::<u32>().copied(),
                (value == "changed").then_some(42)
            );
        }
        assert_eq!(clones.load(Ordering::Relaxed), 2);
        changed.poison();
        assert!(original.poisoned());
    }
}
