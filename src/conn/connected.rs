//! Metadata shared by established connections and response extensions.

use std::{
    fmt::{self, Debug, Formatter},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use http::{Extensions, HeaderMap, HeaderValue};

use crate::proxy::matcher::Intercept;

/// Indicates the negotiated ALPN protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Alpn {
    H2,
    None,
}

/// Shared reuse status for an established connection.
/// Poisoning any clone prevents the transport from returning to the pool.
/// The flag stays alive while connection metadata still references it.
#[derive(Clone)]
struct PoisonPill(Arc<AtomicBool>);

/// Shared connection metadata copied into each response's extensions.
/// Cloning a connection shares this handle without copying the user's metadata.
/// The metadata is cloned only when it is inserted into a response.
#[derive(Debug, Clone)]
struct Extra(Arc<dyn ExtraInner>);

/// Inner trait for extra connection information.
trait ExtraInner: Send + Sync + Debug {
    fn set(&self, res: &mut Extensions);
}

/// Preserves a metadata value's concrete type inside a type-erased extra.
/// Uses that type when inserting a clone into response extensions.
/// The original value remains owned by the connection's shared metadata.
#[derive(Debug)]
struct ExtraEnvelope<T>(T);

/// Adds metadata after the connection's previously attached extras.
/// Response insertion visits the shared chain before inserting this value.
/// The chain shares earlier extras without copying their contents.
#[derive(Debug)]
struct ExtraChain<T>(Arc<dyn ExtraInner>, T);

/// Information about an HTTP proxy identity.
/// Carries forward-proxy status, credentials, and headers for request preparation.
/// Connection clones share it; updates use copy-on-write to preserve other clones.
#[derive(Debug, Default, Clone)]
struct ProxyIdentity {
    is_proxied: bool,
    auth: Option<HeaderValue>,
    headers: Option<HeaderMap>,
}

/// Metadata describing the established transport and its negotiated protocol.
/// Carries proxy details and extra values copied into response extensions.
/// Clones share the poison flag so reuse can be disabled from any response.
#[derive(Debug, Clone)]
pub struct Connected {
    alpn: Alpn,
    proxy: Arc<ProxyIdentity>,
    extra: Option<Extra>,
    poisoned: PoisonPill,
}

// ===== impl PoisonPill =====

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill—this makes debugging issues much easier
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

// ===== impl Connected =====

impl Connected {
    /// Create new `Connected` type with empty metadata.
    pub fn new() -> Connected {
        Connected {
            alpn: Alpn::None,
            proxy: Arc::new(ProxyIdentity::default()),
            extra: None,
            poisoned: PoisonPill::healthy(),
        }
    }

    /// Set extra connection information to be set in the extensions of every `Response`.
    pub fn extra<T: Clone + Send + Sync + Debug + 'static>(mut self, extra: T) -> Connected {
        if let Some(prev) = self.extra {
            self.extra = Some(Extra(Arc::new(ExtraChain(prev.0, extra))));
        } else {
            self.extra = Some(Extra(Arc::new(ExtraEnvelope(extra))));
        }
        self
    }

    /// Copies the extra connection information into an `Extensions` map.
    #[inline]
    pub fn set_extras(&self, extensions: &mut Extensions) {
        if let Some(extra) = &self.extra {
            extra.set(extensions);
        }
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
        self.alpn = Alpn::H2;
        self
    }

    /// Determines if the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn is_negotiated_h2(&self) -> bool {
        self.alpn == Alpn::H2
    }

    /// Determine if this connection is poisoned
    #[inline]
    pub fn poisoned(&self) -> bool {
        self.poisoned.0.load(Ordering::Relaxed)
    }

    /// Poison this connection
    ///
    /// A poisoned connection will not be reused for subsequent requests by the pool
    #[allow(unused)]
    #[inline]
    pub fn poison(&self) {
        self.poisoned.0.store(true, Ordering::Relaxed);
        debug!(
            "connection was poisoned. this connection will not be reused for subsequent requests"
        );
    }
}

// ===== impl Extra =====

impl Extra {
    #[inline]
    fn set(&self, res: &mut Extensions) {
        self.0.set(res);
    }
}

// ===== impl ExtraEnvelope =====

impl<T> ExtraInner for ExtraEnvelope<T>
where
    T: Clone + Send + Sync + Debug + 'static,
{
    fn set(&self, res: &mut Extensions) {
        res.insert(self.0.clone());
    }
}

// ===== impl ExtraChain =====

impl<T> ExtraInner for ExtraChain<T>
where
    T: Clone + Send + Sync + Debug + 'static,
{
    fn set(&self, res: &mut Extensions) {
        self.0.set(res);
        res.insert(self.1.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use ::http::header::VIA;

    use super::*;

    /// Counts copies of user metadata, excluding shared handle clones.
    /// Acts as a response extra whose Clone increments the test's counter.
    /// The counter survives metadata drops so each insertion remains observable.
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
        let changed = original.clone().extra(String::from("changed"));
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
        }
        assert_eq!(clones.load(Ordering::Relaxed), 2);
        changed.poison();
        assert!(original.poisoned());
    }
}
