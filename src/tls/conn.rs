//! SSL support via BoringSSL.

#[macro_use]
mod macros;
mod ext;
mod service;

use std::{
    borrow::Cow,
    fmt::{self, Debug},
    io,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode},
};
use ext::SslConnectorBuilderExt;
use http::{Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

use crate::{
    Error,
    conn::{Connected, Connection, descriptor::ConnectionDescriptor},
    tls::{
        AlpnProtocol, AlpsProtocol, EchGrease, KeyShare, TlsOptions, TlsVersion,
        keylog::KeyLog,
        session::{Key, LruTlsSessionCache, TlsSession, TlsSessionCache},
        trust::{CertStore, Identity},
    },
};

fn key_index() -> Result<Index<Ssl, Key>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Key>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Settings for [`TlsConnector`]
#[derive(Clone)]
pub struct HandshakeSettings {
    no_ticket: bool,
    ech_grease: Option<EchGrease>,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,
    alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,
    alps_use_new_codepoint: bool,
    key_shares: Option<Cow<'static, [KeyShare]>>,
    server_padding: Option<u16>,
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls: TlsConnector,
}

/// A builder for creating a `TlsConnector`.
pub struct TlsConnectorBuilder {
    alpn_protocol: Option<AlpnProtocol>,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
    keylog: Option<KeyLog>,
    session_cache: Arc<dyn TlsSessionCache>,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
    ssl: SslConnector,
    cache: Option<Arc<dyn TlsSessionCache>>,
    settings: HandshakeSettings,
}

// ===== impl HttpsConnector =====

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new [`HttpsConnector`] with a given [`TlsConnector`].
    #[inline]
    pub fn new(http: S, tls: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector { http, tls }
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.tls.settings.alpn_protocols = None;
        self
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Creates a new [`TlsConnectorBuilder`] with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            alpn_protocol: None,
            min_version: None,
            max_version: None,
            identity: None,
            tls_sni: true,
            verify_hostname: true,
            cert_store: None,
            cert_verification: true,
            keylog: None,
            session_cache: Arc::new(LruTlsSessionCache::new(8)),
        }
    }

    fn setup_ssl(&self, uri: Uri) -> Result<Ssl, BoxError> {
        let cfg = self.ssl.configure()?;
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);
        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    fn setup_ssl2(&self, descriptor: ConnectionDescriptor) -> Result<Ssl, BoxError> {
        let mut cfg = self.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(self.settings.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(self.settings.verify_hostname);

        // Set ALPN protocols
        if let Some(version) = descriptor.version() {
            match version {
                Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP1.encode())?;
                }
                Version::HTTP_2 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP2.encode())?;
                }
                Version::HTTP_3 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP3.encode())?;
                }
                _ => {
                    // For unknown versions, we don't set any ALPN protocols.
                }
            }
        } else {
            // Default use the connector configuration.
            if let Some(ref alpn_values) = self.settings.alpn_protocols {
                let encoded = AlpnProtocol::encode_sequence(alpn_values.as_ref());
                cfg.set_alpn_protos(&encoded)?;
            }
        }

        // Set ALPS protos
        if let Some(ref alps_values) = self.settings.alps_protocols {
            for alps in alps_values.iter() {
                cfg.add_application_settings(alps.0, None)?;
            }

            // By default, the new endpoint is used.
            if !alps_values.is_empty() {
                cfg.set_alps_use_new_codepoint(self.settings.alps_use_new_codepoint);
            }
        }

        // Set TLS key shares
        if let Some(ref key_shares) = self.settings.key_shares {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        let uri = descriptor.uri().clone();
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);

        if let Some(policy) = self.settings.ech_grease {
            cfg.set_enable_ech_grease(true);
            // NSS sizes name padding from the URL host, even for IPs or when SNI is disabled.
            let host_length = host.len();
            cfg.set_ech_grease_callback(move |_, info| match policy {
                EchGrease::BoringSsl { aead } => {
                    info.boringssl_parameters(aead.unwrap_or_else(|| info.default_aead()))
                }
                EchGrease::Nss {
                    max_name_length,
                    rounding,
                } => info.nss_parameters(max_name_length, host_length, rounding),
            })?;
        }

        if let Some(ref cache) = self.cache {
            let key = Key(descriptor.id());

            // If the session cache is enabled, we try to retrieve the session
            // associated with the key. If it exists, we set it in the SSL configuration.
            if let Some(session) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session.0) }?;

                if self.settings.no_ticket {
                    cfg.set_options(SslOptions::NO_TICKET);
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        let mut ssl = cfg.into_ssl(host)?;
        if let Some(num_bytes) = self.settings.server_padding {
            ssl.set_server_padding_request(num_bytes);
        }
        Ok(ssl)
    }

    /// If `host` is an IPv6 address, we must strip away the square brackets that surround
    /// it (otherwise, boring will fail to parse the host as an IP address, eventually
    /// causing the handshake to fail due a hostname verification error).
    fn normalize_host(host: &str) -> &str {
        let normalized = crate::util::strip_ipv6_brackets(host);
        if normalized.len() != host.len() && normalized.parse::<std::net::Ipv6Addr>().is_ok() {
            return normalized;
        }

        host
    }
}

// ====== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Sets the alpn protocol to be used.
    #[inline]
    pub fn alpn_protocol(mut self, protocol: Option<AlpnProtocol>) -> Self {
        self.alpn_protocol = protocol;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Sets a custom TLS session store.
    #[inline]
    pub fn session_store(mut self, store: Option<Arc<dyn TlsSessionCache>>) -> Self {
        if let Some(store) = store {
            self.session_cache = store;
        }
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build<'a, T>(&self, opts: T) -> crate::Result<TlsConnector>
    where
        T: Into<Cow<'a, TlsOptions>>,
    {
        let opts = opts.into();

        // Replace the default configuration with the provided one
        let max_tls_version = opts.max_tls_version.or(self.max_version);
        let min_tls_version = opts.min_tls_version.or(self.min_version);
        let alpn_protocols = self
            .alpn_protocol
            .map(|proto| Cow::Owned(vec![proto]))
            .or_else(|| opts.alpn_protocols.clone());

        // Create the SslConnector with the provided options
        let mut connector = SslConnector::bare_builder(SslMethod::tls())
            .map_err(Error::tls)?
            .set_identity(self.identity.as_ref())?
            .set_cert_store(self.cert_store.as_ref())?
            .set_cert_verification(self.cert_verification)
            .set_cert_compressors(opts.certificate_compressors.as_deref())?;

        // The specification distinguishes an empty requested list from omitting the extension.
        // https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-04#section-4.1
        if let Some(ids) = opts.trust_anchors.as_deref() {
            connector
                .set_requested_trust_anchors(ids)
                .map_err(Error::tls)?;
        }

        // Set minimum TLS version
        set_option_inner_try!(min_tls_version, connector, set_min_proto_version);

        // Set maximum TLS version
        set_option_inner_try!(max_tls_version, connector, set_max_proto_version);

        // Set OCSP stapling
        set_bool!(opts, enable_ocsp_stapling, connector, enable_ocsp_stapling);

        // Set Signed Certificate Timestamps (SCT)
        set_bool!(
            opts,
            enable_signed_cert_timestamps,
            connector,
            enable_signed_cert_timestamps
        );

        // Set TLS Session ticket options
        set_bool!(
            opts,
            !session_ticket,
            connector,
            set_options,
            SslOptions::NO_TICKET
        );

        // Set TLS PSK DHE key exchange options
        set_bool!(
            opts,
            !psk_dhe_ke,
            connector,
            set_options,
            SslOptions::NO_PSK_DHE_KE
        );

        // Set TLS No Renegotiation options
        set_bool!(
            opts,
            !renegotiation,
            connector,
            set_options,
            SslOptions::NO_RENEGOTIATION
        );

        // Set TLS grease options
        set_option!(opts, grease_enabled, connector, set_grease_enabled);

        // Set TLS signature algorithms grease options
        set_option!(
            opts,
            grease_sigalgs_enabled,
            connector,
            set_grease_sigalgs_enabled
        );

        // Set TLS permute extensions options
        set_option!(opts, permute_extensions, connector, set_permute_extensions);

        // Set TLS curves list
        set_option_ref_try!(opts, curves_list, connector, set_curves_list);

        // Set TLS signature algorithms list
        set_option_ref_try!(opts, sigalgs_list, connector, set_sigalgs_list);

        // Set TLS cipher list
        set_option_ref_try!(opts, cipher_list, connector, set_cipher_list);

        set_option_ref_try!(opts, tls13_cipher_list, connector, set_tls13_ciphers);

        // Set TLS delegated credentials
        set_option_ref_try!(
            opts,
            delegated_credentials,
            connector,
            set_delegated_credentials
        );

        // Set TLS record size limit
        set_option!(opts, record_size_limit, connector, set_record_size_limit);

        // Set TLS extension permutation
        if let Some(ref extension_permutation) = opts.extension_permutation {
            connector
                .set_extension_permutation(extension_permutation)
                .map_err(Error::tls)?;
        }

        // Set TLS keylog handler.
        if let Some(ref policy) = self.keylog {
            let handle = policy.clone().handle().map_err(Error::tls)?;
            connector.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        // Create the handshake settings with the default session cache capacity.
        let settings = HandshakeSettings {
            tls_sni: self.tls_sni,
            verify_hostname: self.verify_hostname,
            no_ticket: opts.psk_skip_session_ticket,
            alpn_protocols,
            alps_protocols: opts.alps_protocols.clone(),
            alps_use_new_codepoint: opts.alps_use_new_codepoint,
            ech_grease: opts.ech_grease,
            key_shares: opts.key_shares.clone(),
            server_padding: opts.server_padding,
        };

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.pre_shared_key.then(|| {
            let session_cache = self.session_cache.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = session_cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.put(key.clone(), TlsSession(session));
                    }
                }
            });

            session_cache
        });

        Ok(TlsConnector {
            ssl: connector.build(),
            cache,
            settings,
        })
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

/// A connection that has been established with a TLS handshake.
pub struct EstablishedConn<IO> {
    io: IO,
    descriptor: ConnectionDescriptor,
}

// ===== impl MaybeHttpsStream =====

impl<T> AsRef<T> for MaybeHttpsStream<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        match self {
            MaybeHttpsStream::Http(s) => s,
            MaybeHttpsStream::Https(s) => s.get_ref(),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    #[inline]
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => s.get_ref().connected(),
        }
    }
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_read(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write(ctx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write(ctx, buf),
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(ctx),
        }
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_shutdown(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_shutdown(ctx),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(inner) => inner.is_write_vectored(),
            MaybeHttpsStream::Https(inner) => inner.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }
}

// ===== impl EstablishedConn =====

impl<IO> EstablishedConn<IO> {
    /// Creates a new [`EstablishedConn`].
    #[inline]
    pub fn new(io: IO, descriptor: ConnectionDescriptor) -> EstablishedConn<IO> {
        EstablishedConn { io, descriptor }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use btls::ssl::{ErrorCode, SslStream as CaptureStream};

    use super::*;
    use crate::{
        Group,
        tls::{EchGreaseAead, EchGreaseRounding, Tls13Cipher},
    };

    #[test]
    fn tls13_cipher_list_preserves_order_independently_of_tls12() {
        for (ciphers, expected) in [
            (
                vec![
                    Tls13Cipher::AES_256_GCM_SHA384,
                    Tls13Cipher::CHACHA20_POLY1305_SHA256,
                    Tls13Cipher::AES_128_GCM_SHA256,
                ],
                vec![0x1302, 0x1303, 0x1301, 0xc02f, 0xc030],
            ),
            (
                vec![Tls13Cipher::CHACHA20_POLY1305_SHA256],
                vec![0x1303, 0xc02f, 0xc030],
            ),
        ] {
            let options = TlsOptions::builder()
                .cipher_list("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
                .tls13_cipher_list(ciphers)
                .build();
            let connector = TlsConnector::builder()
                .build(Cow::Borrowed(&options))
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    client_hello(&connector, "https://example.com/").ciphers,
                    expected
                );
            }
        }
    }

    #[test]
    fn ech_grease_policy_controls_payload_without_changing_ciphers() {
        let options = TlsOptions::builder()
            .tls13_cipher_list(vec![
                Tls13Cipher::CHACHA20_POLY1305_SHA256,
                Tls13Cipher::AES_128_GCM_SHA256,
            ])
            .build();
        let baseline = client_hello(
            &TlsConnector::builder()
                .build(Cow::Borrowed(&options))
                .unwrap(),
            "https://example.com/",
        );
        assert!(baseline.extension(0xfe0d).is_none());

        for aead in [EchGreaseAead::AES_128_GCM, EchGreaseAead::CHACHA20_POLY1305] {
            let mut options = options.clone();
            options.ech_grease = Some(EchGrease::BoringSsl { aead: Some(aead) });
            let hello = client_hello(
                &TlsConnector::builder()
                    .build(Cow::Borrowed(&options))
                    .unwrap(),
                "https://example.com/",
            );
            let ech = hello.extension(0xfe0d).unwrap();
            assert_eq!(u16::from_be_bytes([ech[3], ech[4]]), aead.id());
            assert_eq!(&ech[6..8], &[0, 32]);
            assert!(matches!(ech.len() - 42, 144 | 176 | 208 | 240));
            assert_eq!(ech[39] & 0x80, 0); // X25519 public enc, not random octets.
            assert_eq!(hello.ciphers, baseline.ciphers);
        }

        for rounding in [EchGreaseRounding::NssPre3127, EchGreaseRounding::Rfc9849] {
            let mut options = options.clone();
            options.ech_grease = Some(EchGrease::Nss {
                max_name_length: 100,
                rounding,
            });
            let connector = TlsConnector::builder()
                .build(Cow::Borrowed(&options))
                .unwrap();
            for (uri, host_length) in [("https://example.com/", 11), ("https://[::1]/", 3)] {
                let hello = client_hello(&connector, uri);
                let ech = hello.extension(0xfe0d).unwrap();
                assert!(matches!(u16::from_be_bytes([ech[3], ech[4]]), 1 | 3));
                assert_eq!(&ech[6..8], &[0, 32]);
                assert_eq!(
                    ech.len() - 42,
                    nss_payload_length(&hello, host_length, rounding)
                );
                assert_eq!(hello.ciphers, baseline.ciphers);
            }
        }
    }

    // Independently size the non-PSK fixture from its serialized fields. This
    // catches a policy wired to SNI length instead of the normalized URL host.
    fn nss_payload_length(
        hello: &ClientHello,
        host_length: usize,
        rounding: EchGreaseRounding,
    ) -> usize {
        let mut inner = 41 + hello.ciphers.len() * 2 + 5 + 7;
        if let Some(sni) = hello.extension(0) {
            inner += 4 + sni.len();
        }
        let compressed = hello
            .extensions
            .iter()
            .filter(|(kind, _)| ![0, 11, 21, 23, 35, 43, 46, 0xfe0d, 0xff01].contains(kind))
            .count();
        if compressed != 0 {
            inner += 5 + 2 * compressed;
        }
        inner += 100usize.saturating_sub(host_length);
        match rounding {
            EchGreaseRounding::NssPre3127 => inner + 31 - inner % 32 + 16,
            EchGreaseRounding::Rfc9849 => inner.div_ceil(32) * 32 + 16,
            _ => panic!("unsupported test rounding"),
        }
    }

    struct ClientHello {
        ciphers: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    impl ClientHello {
        fn extension(&self, kind: u16) -> Option<&[u8]> {
            self.extensions
                .iter()
                .find(|(id, _)| *id == kind)
                .map(|(_, body)| body.as_slice())
        }
    }

    fn client_hello(connector: &TlsConnector, uri: &str) -> ClientHello {
        let descriptor = ConnectionDescriptor::new(
            uri.parse().unwrap(),
            Group::default(),
            None,
            None,
            None,
            None,
        );
        let ssl = connector.setup_ssl2(descriptor).unwrap();
        let mut stream = CaptureStream::new(ssl, Capture(Vec::new())).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let bytes = &stream.get_ref().0;
        assert_eq!(bytes[0], 22);
        let mut offset = 44 + usize::from(bytes[43]);
        let mut vector = || {
            let len = usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            offset += 2;
            let body = &bytes[offset..offset + len];
            offset += len;
            body
        };
        let ciphers = vector()
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .collect();
        offset += 1 + usize::from(bytes[offset]); // Compression methods.
        let end = offset + 2 + usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
        let mut extensions = Vec::new();
        while offset < end {
            let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let len = usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
            offset += 4;
            extensions.push((kind, bytes[offset..offset + len].to_vec()));
            offset += len;
        }
        ClientHello {
            ciphers,
            extensions,
        }
    }

    struct Capture(Vec<u8>);

    impl Read for Capture {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
