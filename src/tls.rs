//! TLS configuration, trust roots, client identities, and session storage.
//!
//! Use [`TlsOptions`] to customize TLS over TCP and Unix sockets, and
//! [`ClientBuilder`](crate::ClientBuilder) for client-wide verification, identity,
//! version limits, and session storage.

pub(crate) mod macros;

pub(super) mod connector;

pub mod compress;
pub mod keylog;
pub mod session;
pub mod trust;

use std::{
    any::Any,
    borrow::Cow,
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

/// Re-exports of TLS-related types from `btls` for public use.
pub use btls::ssl::{EchGreaseAead, ExtensionType, KeyShare, Tls13Cipher};
use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{EchGreaseRounding, Ssl, SslContextBuilder, SslRef, SslVerifyMode},
};
use bytes::{BufMut, Bytes, BytesMut};
use compress::{CertificateCompressor, Compressors};
use derive_deftly::Deftly;
use educe::Educe;
use keylog::KeyLog;
use lru::{DefaultHasher, LruCache};
use session::Tickets;
use trust::{CertStore, Identity};

use crate::{Error, sync::Mutex};

/// Compares and hashes the subset of TLS options that define a cache or session key.
///
/// Used with the default `Rhs = Self` for compiled context caching in [`TlsContext`], and
/// with `Rhs = dyn Any` / `H = dyn Hasher` for type-erased session keys in [`session`].
pub(crate) trait KeyIdentity<
    Rhs: ?Sized = Self,
    H: Hasher + ?Sized = <lru::DefaultHasher as BuildHasher>::Hasher,
>: Any + Send + Sync
{
    /// Returns `true` if `self` and `other` share the same key.
    fn same(&self, other: &Rhs) -> bool;

    /// Hashes the fields compared by [`Self::same`].
    fn hash_key(&self, state: &mut H);
}

const REQUEST_CONTEXTS: NonZeroUsize =
    NonZeroUsize::new(16).expect("request context capacity must be non-zero");
static CONTEXT_HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Compiled base TLS context paired with a bounded LRU cache for per-request overrides.
///
/// Shared by both stream and QUIC TLS contexts so identical request overrides reuse a single
/// compiled BoringSSL context instead of rebuilding it on every connection.
pub(crate) struct TlsContext<O, T> {
    inner: T,
    cache: Mutex<LruCache<u64, (Arc<O>, T)>>,
}

// ===== impl TlsContext =====

impl<O: KeyIdentity, T: Clone> TlsContext<O, T> {
    /// Creates a cache around the compiled base context.
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            cache: Mutex::new(LruCache::sparse(REQUEST_CONTEXTS)),
        }
    }

    /// Returns the base context when `options` is `None`, or looks up (and compiles on miss)
    /// a cached override context.
    ///
    /// Compilation runs outside the lock, so concurrent misses may compile redundantly.
    pub(crate) fn get_or_compile(
        &self,
        options: Option<&Arc<O>>,
        compile: impl FnOnce(&O) -> crate::Result<T>,
    ) -> crate::Result<T> {
        let Some(value) = options else {
            return Ok(self.inner.clone());
        };

        let mut hasher = CONTEXT_HASHER.build_hasher();
        value.hash_key(&mut hasher);
        let hash = hasher.finish();
        // Guard against hash collisions by checking equality on hit.
        if let Some((cached, context)) = self.cache.lock().get(&hash)
            && cached.same(value)
        {
            return Ok(context.clone());
        }

        let context = compile(value)?;
        let entry = (value.clone(), context.clone());
        // Drop any evicted context after releasing the lock.
        let _evicted = self.cache.lock().push(hash, entry);
        Ok(context)
    }
}

/// Peer certificate information attached to response extensions when
/// [`ClientBuilder::tls_info`](crate::ClientBuilder::tls_info) is enabled.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Bytes>,
    pub(crate) peer_certificate_chain: Option<Vec<Bytes>>,
}

// ===== impl TlsInfo =====

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// Get the DER encoded certificate chain of the peer.
    ///
    /// This includes the leaf certificate on the client side.
    pub fn peer_certificate_chain(&self) -> Option<impl Iterator<Item = &[u8]>> {
        self.peer_certificate_chain
            .as_ref()
            .map(|v| v.iter().map(|b| b.as_ref()))
    }
}

/// A TLS protocol version supported by the backend.
///
/// Used to set minimum and maximum version bounds on [`ClientBuilder`](crate::ClientBuilder)
/// or per-connection [`TlsOptions`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TlsVersion(btls::ssl::SslVersion);

// ===== impl TlsVersion =====

impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1);

    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_1);

    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_2);

    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_3);
}

/// An application protocol identifier for TLS ALPN negotiation
/// ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
///
/// Passed in preference order via [`TlsOptions::alpn_protocols`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

// ===== impl AlpnProtocol =====

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(b"h3");

    pub(crate) fn encode_sequence(items: &[AlpnProtocol]) -> Bytes {
        // RFC 7301 section 3.1 uses length-prefixed identifiers in preference order.
        // https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(item.0);
        }
        buf.freeze()
    }
}

impl PartialEq<[u8]> for AlpnProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// An application protocol identifier for TLS ALPS (Application-Layer Protocol Settings).
///
/// Passed via [`TlsOptions::alps_protocols`] to exchange settings during the handshake for
/// protocols also offered in ALPN.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

// ===== impl AlpsProtocol =====

impl AlpsProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpsProtocol = AlpsProtocol(b"h3");

    /// Returns the identifier passed to BoringSSL.
    pub(crate) fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

impl PartialEq<[u8]> for AlpsProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// Policy used to generate an ECH GREASE extension.
///
/// AEAD selection here is independent of TLS cipher suite preferences.
/// For NSS policies, put ECH last in [`TlsOptions::extension_permutation`]
/// to match NSS's extension order. Other TLS settings are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EchGrease {
    /// BoringSSL's default policy: the AEAD follows the local AES hardware.
    Default,
    /// BoringSSL's default sizing with a fixed AEAD, so the extension does not
    /// vary with the local AES hardware.
    Aead(EchGreaseAead),
    /// NSS before 3.127, as used by Firefox 119-154: pad the inner length to
    /// 32k + 31.
    NssPre3127,
    /// NSS 3.127 and later, as used by Firefox 155 onward: round the inner
    /// length up to a multiple of 32.
    Nss3127,
}

// ===== impl EchGrease =====

impl Hash for EchGrease {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        if let Self::Aead(aead) = self {
            aead.id().hash(state);
        }
    }
}

fn host_length_index() -> Result<Index<Ssl, usize>, ErrorStack> {
    static INDEX: LazyLock<Result<Index<Ssl, usize>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    INDEX.clone()
}

/// Enables ECH GREASE and stores the target host length for NSS padding, even without SNI.
pub(crate) fn set_ech_grease_host(ssl: &mut SslRef, host_length: usize) -> Result<(), ErrorStack> {
    ssl.set_enable_ech_grease(true);
    ssl.set_ex_data(host_length_index()?, host_length);
    Ok(())
}

/// Installs the configured ECH GREASE callback on `builder`.
pub(crate) fn set_ech_grease_policy(builder: &mut SslContextBuilder, policy: Option<EchGrease>) {
    if let Some(policy) = policy
        && policy != EchGrease::Default
    {
        builder.set_ech_grease_callback(move |ssl, info| {
            let nss = |rounding| {
                let host_length = ssl.ex_data(host_length_index()?).copied().unwrap_or(0);
                info.nss_parameters(100, host_length, rounding)
            };
            match policy {
                EchGrease::Default => info.boringssl_parameters(info.default_aead()),
                EchGrease::Aead(aead) => info.boringssl_parameters(aead),
                EchGrease::NssPre3127 => nss(EchGreaseRounding::NssPre3127),
                EchGrease::Nss3127 => nss(EchGreaseRounding::Nss3127),
            }
        });
    }
}

/// Builder for [`TlsOptions`].
///
/// Created via [`TlsOptions::builder`] to configure TLS handshake options for TCP and Unix
/// connections.
#[must_use]
#[derive(Debug, Clone)]
pub struct TlsOptionsBuilder {
    config: TlsOptions,
}

/// TLS handshake options for TCP and Unix connections.
///
/// For HTTP/3 connections, use `QuicOptions` instead.
#[non_exhaustive]
#[derive(Debug, Clone, Educe, Deftly)]
#[educe(Default)]
#[derive_deftly(macros::TlsKey)]
pub struct TlsOptions {
    /// Protocols offered through ALPN, in preference order ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
    ///
    /// Fixed HTTP version requirements override this list. `None` and empty lists inherit
    /// the client's offer: HTTP/2 then HTTP/1.1 when HTTP/2 is enabled, otherwise HTTP/1.1.
    ///
    /// **Default:** `None` (inherits the client's offer).
    #[deftly(tls_key(pool))]
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// Protocols that exchange application-layer settings through ALPS during the handshake.
    ///
    /// Only protocols also offered through ALPN are sent. Unlike ALPN,
    /// request-level options do not inherit the client's list.
    ///
    /// **Default:** `None`.
    #[deftly(tls_key(pool))]
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Selects the new ALPS codepoint when ALPS protocols are offered.
    ///
    /// Current browsers and BoringSSL use the new codepoint.
    ///
    /// **Default:** `true`.
    #[educe(Default = true)]
    #[deftly(tls_key(pool))]
    pub alps_use_new_codepoint: bool,

    /// Controls TLS session tickets ([RFC 5077](https://tools.ietf.org/html/rfc5077)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub session_ticket: Option<bool>,

    /// Minimum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (uses
    /// [`ClientBuilder::tls_min_version`](crate::ClientBuilder::tls_min_version)).
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (uses
    /// [`ClientBuilder::tls_max_version`](crate::ClientBuilder::tls_max_version)).
    pub max_tls_version: Option<TlsVersion>,

    /// Controls PSK with (EC)DHE key establishment (`psk_dhe_ke`).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub psk_dhe_ke: Option<bool>,

    /// Omits the `session_ticket` extension when resuming a TLS 1.3 session.
    ///
    /// The session is still offered through `pre_shared_key`. Full handshakes and TLS 1.2
    /// resumption keep the extension.
    ///
    /// **Default:** `false`.
    #[deftly(tls_key(session))]
    pub psk_skip_session_ticket: bool,

    /// Enables ticket-based resumption and the TLS 1.3 `pre_shared_key` extension.
    ///
    /// Uses a previously established session, not out-of-band PSKs.
    /// See [RFC 8446 section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11).
    ///
    /// **Default:** `false`.
    pub pre_shared_key: bool,

    /// ECH GREASE policy, independent of the TLS cipher suite order.
    ///
    /// **Default:** `None` (GREASE disabled).
    pub ech_grease: Option<EchGrease>,

    /// Controls permutation of ClientHello extensions.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub permute_extensions: Option<bool>,

    /// Controls TLS GREASE ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_enabled: Option<bool>,

    /// Controls whether the ClientHello `signature_algorithms` extension includes a
    /// GREASE value ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_sigalgs_enabled: Option<bool>,

    /// Enables OCSP stapling for the connection.
    ///
    /// **Default:** `false`.
    pub enable_ocsp_stapling: bool,

    /// Enables Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`.
    pub enable_signed_cert_timestamps: bool,

    /// Maximum TLS record size.
    ///
    /// **Default:** `None`.
    pub record_size_limit: Option<u16>,

    /// Key shares offered in TLS 1.3 handshakes.
    ///
    /// **Default:** `None`.
    #[deftly(tls_key(session))]
    pub key_shares: Option<Cow<'static, [KeyShare]>>,

    /// Encoded Trust Anchor IDs sent in a TLS 1.3 [`ClientHello`].
    ///
    /// Each ID must be non-empty and have a one-byte length prefix; omit the list's outer two-byte
    /// length. IDs only guide server certificate selection and must identify roots accepted by the
    /// configured certificate store, or certificate verification may fail.
    ///
    /// `Some(&[])` sends an empty [`trust_anchors` extension]; `None` omits it. Invalid encoding
    /// fails TLS setup, and wreq does not implement the specification's retry mechanism.
    ///
    /// **Default:** `None`.
    ///
    /// [`ClientHello`]: https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2
    /// [`trust_anchors` extension]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-04#section-4.1
    pub trust_anchors: Option<Cow<'static, [u8]>>,

    /// Requests TLS 1.3 EncryptedExtensions padding from the server.
    ///
    /// `Some(0)` sends the experimental `server_padding` extension (4832) with
    /// a zero-byte padding request; `None` omits the extension. Servers may ignore
    /// the request and only honor padding requests of at most 16 KiB.
    ///
    /// **Default:** `None`
    #[deftly(tls_key(session))]
    pub server_padding: Option<u16>,

    /// Enables TLS renegotiation by sending the `renegotiation_info` extension.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub renegotiation: Option<bool>,

    /// Signature algorithms for delegated credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// **Default:** `None`.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of supported elliptic curves.
    ///
    /// **Default:** `None`.
    pub curves_list: Option<Cow<'static, str>>,

    /// List of supported signature algorithms.
    ///
    /// **Default:** `None`.
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Cipher suite selection and ordering for TLS 1.2 and earlier, in BoringSSL's cipher-list
    /// syntax.
    ///
    /// **Default:** `None`.
    pub cipher_list: Option<Cow<'static, str>>,

    /// TLS 1.3 cipher suites in the order offered to the server.
    ///
    /// An empty list uses backend defaults; duplicate suites fail TLS setup.
    ///
    /// **Default:** `None` (backend defaults).
    pub tls13_cipher_list: Option<Cow<'static, [Tls13Cipher]>>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`.
    certificate_compressors: Compressors,

    /// TLS extension order used for permutation.
    ///
    /// **Default:** `None`.
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,
}

/// Client-wide TLS settings shared across TCP/Unix and QUIC contexts.
///
/// `min_version` applies only to TCP/Unix; QUIC always requires TLS 1.3 and sets its own ALPN.
/// Clones share the same session ticket store across both transports.
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) min_version: Option<TlsVersion>,
    pub(crate) max_version: Option<TlsVersion>,
    pub(crate) sni: bool,
    pub(crate) verify_hostname: bool,
    pub(crate) cert_verification: bool,
    pub(crate) keylog: Option<KeyLog>,
    pub(crate) identity: Option<Identity>,
    pub(crate) cert_store: Option<CertStore>,
    pub(crate) tickets: Arc<Tickets>,
    pub(crate) tls_info: bool,
}

// ===== impl TlsOptionsBuilder =====

impl TlsOptionsBuilder {
    /// Sets the ALPN protocols to use.
    #[inline]
    pub fn alpn_protocols<I>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = AlpnProtocol>,
    {
        self.config.alpn_protocols = Some(Cow::Owned(alpn.into_iter().collect()));
        self
    }

    /// Sets the ALPS protocols to use.
    #[inline]
    pub fn alps_protocols<I>(mut self, alps: I) -> Self
    where
        I: IntoIterator<Item = AlpsProtocol>,
    {
        self.config.alps_protocols = Some(Cow::Owned(alps.into_iter().collect()));
        self
    }

    /// Sets whether to use a new codepoint for ALPS.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }
    /// Sets the session ticket flag.
    #[inline]
    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.config.session_ticket = Some(enabled);
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_tls_version = version.into();
        self
    }

    /// Sets the ECH GREASE policy, or disables GREASE with `None`.
    #[inline]
    pub fn ech_grease<T: Into<Option<EchGrease>>>(mut self, policy: T) -> Self {
        self.config.ech_grease = policy.into();
        self
    }

    /// Sets whether to permute ClientHello extensions.
    #[inline]
    pub fn permute_extensions<T>(mut self, permute: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the GREASE enabled flag.
    #[inline]
    pub fn grease_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets whether the ClientHello `signature_algorithms` extension includes a
    /// GREASE value.
    #[inline]
    pub fn grease_sigalgs_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_sigalgs_enabled = enabled.into();
        self
    }

    /// Sets the OCSP stapling flag.
    #[inline]
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    #[inline]
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    #[inline]
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = Some(enabled);
        self
    }

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets whether TLS 1.3 resumption omits the `session_ticket` extension.
    #[inline]
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the renegotiation flag.
    #[inline]
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = Some(enabled);
        self
    }

    /// Sets the delegated credentials.
    #[inline]
    pub fn delegated_credentials<T>(mut self, creds: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the client key shares to be used in the TLS 1.3 handshake.
    #[inline]
    pub fn key_shares<T>(mut self, key_shares: T) -> Self
    where
        T: Into<Cow<'static, [KeyShare]>>,
    {
        self.config.key_shares = Some(key_shares.into());
        self
    }

    /// Sets the encoded Trust Anchor IDs sent in ClientHello.
    ///
    /// See [`TlsOptions::trust_anchors`] for encoding and verification requirements.
    #[inline]
    pub fn trust_anchors<T>(mut self, ids: T) -> Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.config.trust_anchors = Some(ids.into());
        self
    }

    /// Sets the requested TLS 1.3 server padding, or disables the extension.
    ///
    /// See [`TlsOptions::server_padding`] for the experimental extension's behavior.
    #[inline]
    pub fn server_padding<T>(mut self, num_bytes: T) -> Self
    where
        T: Into<Option<u16>>,
    {
        self.config.server_padding = num_bytes.into();
        self
    }

    /// Sets the supported curves list.
    #[inline]
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the supported signature algorithms.
    #[inline]
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the cipher list for TLS 1.2 and earlier.
    #[inline]
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the TLS 1.3 cipher suites in offer order.
    ///
    /// An empty list restores backend defaults; duplicate suites fail TLS setup.
    #[inline]
    pub fn tls13_cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, [Tls13Cipher]>>,
    {
        self.config.tls13_cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compressors<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [&'static dyn CertificateCompressor]>>,
    {
        self.config.certificate_compressors = Compressors::new(&algs.into());
        self
    }

    /// Sets the extension permutation.
    #[inline]
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Builds the `TlsOptions` from the builder.
    #[inline]
    pub fn build(self) -> TlsOptions {
        self.config
    }
}

// ===== impl TlsOptions =====

impl TlsOptions {
    /// Creates a new `TlsOptionsBuilder` instance.
    pub fn builder() -> TlsOptionsBuilder {
        TlsOptionsBuilder {
            config: TlsOptions::default(),
        }
    }
}

// ===== impl Config =====

impl Config {
    /// Applies client identity, trust roots, verification, and key logging to `builder`.
    pub(crate) fn configure(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        if let Some(identity) = &self.identity {
            identity.configure(builder)?;
        }
        CertStore::configure(self.cert_store.as_ref(), builder)?;
        builder.set_verify(if self.cert_verification {
            SslVerifyMode::PEER
        } else {
            SslVerifyMode::NONE
        });

        if let Some(policy) = self.keylog.clone()
            && let Some(handle) = policy.handle().map_err(Error::tls)?
        {
            builder.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        Ok(())
    }

    /// Configures the shared session scope and re-verifies peer certificates on resumption
    /// when verification is enabled.
    pub(crate) fn enable_resumption(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        // BoringSSL skips certificate checks on resumption unless a custom verifier re-runs them.
        // Skip when verification is off, since VERIFY_NONE does not support re-verification.
        if self.cert_verification {
            builder.set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
                Ok(ssl.verify_peer_cert_chain()?)
            });
            builder.set_reverify_on_resume(true);
        }
        let scope = self.tickets.session_id_context().map_err(Error::tls)?;
        builder.set_session_id_context(&scope).map_err(Error::tls)?;
        // Limits TLS 1.2 sessions; TLS 1.3 also honors the server's ticket lifetime.
        builder.set_session_timeout(60 * 60);
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            sni: true,
            verify_hostname: true,
            cert_verification: true,
            keylog: None,
            identity: None,
            cert_store: None,
            tickets: Arc::new(Tickets::new(None)),
            tls_info: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocol_encode() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP2]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x08http/1.1"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[
            AlpnProtocol::HTTP1,
            AlpnProtocol::HTTP2,
            AlpnProtocol::HTTP3,
        ]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2\x02h3"));
    }

    #[test]
    fn alpn_protocol_encode_single() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1]);
        assert_eq!(alpn, b"\x08http/1.1".as_ref());

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2]);
        assert_eq!(alpn, b"\x02h2".as_ref());

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, b"\x02h3".as_ref());
    }
}
