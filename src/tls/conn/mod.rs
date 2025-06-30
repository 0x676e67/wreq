//! SSL support via BoringSSL.

mod cache;
mod cert_compression;
mod ext;
mod service;

use std::{
    fmt,
    fmt::Debug,
    io::IoSlice,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use boring2::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode},
};
use bytes::Bytes;
use cache::{SessionCache, SessionKey};
use http::Uri;
use tokio::io;
use tokio_boring2::SslStream;
use tower_service::Service;

use crate::{
    connect::HttpConnector,
    core::{
        client::connect::{Connected, Connection, TcpConnectOptions},
        rt::{Read, ReadBufCursor, TokioIo, Write},
    },
    error::BoxError,
    sync::Mutex,
    tls::{
        AlpnProtocol, CertStore, Identity, KeyLogPolicy, TlsConfig, TlsVersion,
        conn::ext::{ConnectConfigurationExt, SslConnectorBuilderExt},
    },
};

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, SessionKey>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Builds for [`HandshakeConfig`].
pub struct HandshakeConfigBuilder {
    settings: HandshakeConfig,
}

/// Settings for [`TlsConnector`]
#[derive(Clone)]
pub struct HandshakeConfig {
    session_cache_capacity: usize,
    session_cache: bool,
    skip_session_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protos: Option<Bytes>,
    alps_protos: Option<Bytes>,
    alps_use_new_codepoint: bool,
    random_aes_hw_override: bool,
}

impl HandshakeConfigBuilder {
    /// Sets the session cache capacity.
    pub fn session_cache_capacity(mut self, capacity: usize) -> Self {
        self.settings.session_cache_capacity = capacity;
        self
    }

    /// Enables or disables session cache.
    pub fn session_cache(mut self, enabled: bool) -> Self {
        self.settings.session_cache = enabled;
        self
    }

    /// Skips the session ticket.
    pub fn skip_session_ticket(mut self, skip: bool) -> Self {
        self.settings.skip_session_ticket = skip;
        self
    }

    /// Enables or disables ECH grease.
    pub fn enable_ech_grease(mut self, enable: bool) -> Self {
        self.settings.enable_ech_grease = enable;
        self
    }

    /// Sets hostname verification.
    pub fn verify_hostname(mut self, verify: bool) -> Self {
        self.settings.verify_hostname = verify;
        self
    }

    /// Sets TLS SNI.
    pub fn tls_sni(mut self, sni: bool) -> Self {
        self.settings.tls_sni = sni;
        self
    }

    /// Sets ALPS protocol.
    pub fn alps_protos(mut self, protos: Option<Bytes>) -> Self {
        self.settings.alps_protos = protos;
        self
    }

    /// Sets ALPS new codepoint usage.
    pub fn alps_use_new_codepoint(mut self, use_new: bool) -> Self {
        self.settings.alps_use_new_codepoint = use_new;
        self
    }

    /// Sets random AES hardware override.
    pub fn random_aes_hw_override(mut self, override_: bool) -> Self {
        self.settings.random_aes_hw_override = override_;
        self
    }

    /// Builds the `HandshakeConfig`.
    pub fn build(self) -> HandshakeConfig {
        self.settings
    }
}

impl HandshakeConfig {
    /// Creates a new `HandshakeConfigBuilder`.
    pub fn builder() -> HandshakeConfigBuilder {
        HandshakeConfigBuilder {
            settings: HandshakeConfig::default(),
        }
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            session_cache_capacity: 8,
            session_cache: false,
            skip_session_ticket: false,
            enable_ech_grease: false,
            verify_hostname: true,
            tls_sni: true,
            alpn_protos: None,
            alps_protos: None,
            alps_use_new_codepoint: false,
            random_aes_hw_override: false,
        }
    }
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Option<Arc<Mutex<SessionCache>>>,
    config: HandshakeConfig,
}

/// A builder for creating a `TlsConnector`.
#[derive(Clone)]
pub struct TlsConnectorBuilder {
    keylog_policy: Option<KeyLogPolicy>,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Inner,
}

// ===== impl HttpsConnector =====

impl HttpsConnector<HttpConnector> {
    /// Sets the ALPN protocol to be used for the connection.
    pub fn set_alpn_protocol(&mut self, alpn: Option<AlpnProtocol>) {
        self.inner.config.alpn_protos = alpn.map(|p| p.encode());
    }

    /// Sets the tcp connect options for the connector.
    pub fn set_tcp_connect_options(&mut self, options: Option<TcpConnectOptions>) {
        self.http.set_tcp_connect_options(options);
    }
}

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: Read + Write + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new `HttpsConnector` with a given `HttpConnector`
    pub fn with_connector(http: S, connector: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector {
            http,
            inner: connector.inner,
        }
    }
}

// ===== impl Inner =====

impl Inner {
    /// Connects to the given URI using the given connection.
    ///
    /// This function is used to connect to the given URI using the given connection.
    pub async fn connect<A>(
        &self,
        uri: &Uri,
        host: &str,
        conn: A,
    ) -> Result<SslStream<TokioIo<A>>, BoxError>
    where
        A: Read + Write + Unpin + Send + Sync + Debug + 'static,
    {
        let mut cfg = self.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(self.config.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(self.config.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(self.config.enable_ech_grease);

        // Set AES hardware override
        cfg.set_random_aes_hw_override(self.config.random_aes_hw_override);

        // Set ALPS protos
        cfg.set_alps_protos(
            self.config.alps_protos.clone(),
            self.config.alps_use_new_codepoint,
        )?;

        // Set ALPN protocols
        if let Some(ref alpn_protos) = self.config.alpn_protos {
            cfg.set_alpn_protos(alpn_protos)?;
        }

        if let Some(authority) = uri.authority() {
            let key = SessionKey(authority.clone());

            if let Some(ref cache) = self.cache {
                if let Some(session) = cache.lock().get(&key) {
                    unsafe {
                        cfg.set_session(&session)?;
                    }

                    if self.config.skip_session_ticket {
                        cfg.set_options(SslOptions::NO_TICKET)?;
                    }
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        let ssl = cfg.into_ssl(host)?;

        tokio_boring2::SslStreamBuilder::new(ssl, TokioIo::new(conn))
            .connect()
            .await
            .map_err(Into::into)
    }
}

// ====== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Sets the TLS keylog policy.
    #[inline(always)]
    pub fn keylog(mut self, policy: Option<KeyLogPolicy>) -> Self {
        self.keylog_policy = policy;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline(always)]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline(always)]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline(always)]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline(always)]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline(always)]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline(always)]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline(always)]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build(&self, mut cfg: TlsConfig) -> crate::Result<TlsConnector> {
        // Replace the default configuration with the provided one
        cfg.max_tls_version = cfg.max_tls_version.or(self.max_version);
        cfg.min_tls_version = cfg.min_tls_version.or(self.min_version);

        let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())?
            .set_cert_store(self.cert_store.as_ref())?
            .set_cert_verification(self.cert_verification)?
            .add_certificate_compression_algorithms(cfg.certificate_compression_algorithms)?;

        // Set Identity
        call_option_ref_try!(self, identity, &mut connector, add_to_tls);

        // Set minimum TLS version
        set_option_inner_try!(cfg, min_tls_version, connector, set_min_proto_version);

        // Set maximum TLS version
        set_option_inner_try!(cfg, max_tls_version, connector, set_max_proto_version);

        // Set OCSP stapling
        set_bool!(cfg, enable_ocsp_stapling, connector, enable_ocsp_stapling);

        // Set Signed Certificate Timestamps (SCT)
        set_bool!(
            cfg,
            enable_signed_cert_timestamps,
            connector,
            enable_signed_cert_timestamps
        );

        // Set TLS Session ticket options
        set_bool!(
            cfg,
            !session_ticket,
            connector,
            set_options,
            SslOptions::NO_TICKET
        );

        // Set TLS PSK DHE key exchange options
        set_bool!(
            cfg,
            !psk_dhe_ke,
            connector,
            set_options,
            SslOptions::NO_PSK_DHE_KE
        );

        // Set TLS No Renegotiation options
        set_bool!(
            cfg,
            !renegotiation,
            connector,
            set_options,
            SslOptions::NO_RENEGOTIATION
        );

        // Set TLS grease options
        set_option!(cfg, grease_enabled, connector, set_grease_enabled);

        // Set TLS permute extensions options
        set_option!(cfg, permute_extensions, connector, set_permute_extensions);

        // Set TLS ALPN protocols
        set_option_ref_try!(cfg, alpn_protos, connector, set_alpn_protos);

        // Set TLS curves list
        set_option_ref_try!(cfg, curves_list, connector, set_curves_list);

        // Set TLS signature algorithms list
        set_option_ref_try!(cfg, sigalgs_list, connector, set_sigalgs_list);

        // Set TLS cipher list
        set_option_ref_try!(cfg, cipher_list, connector, set_cipher_list);

        // Set TLS delegated credentials
        set_option_ref_try!(
            cfg,
            delegated_credentials,
            connector,
            set_delegated_credentials
        );

        // Set TLS record size limit
        set_option!(cfg, record_size_limit, connector, set_record_size_limit);

        // Set TLS key shares limit
        set_option!(cfg, key_shares_limit, connector, set_key_shares_limit);

        // Set TLS extension permutation
        set_option_ref_try!(
            cfg,
            extension_permutation,
            connector,
            set_extension_permutation
        );

        // Set TLS aes hardware override
        set_option!(cfg, aes_hw_override, connector, set_aes_hw_override);

        // Set TLS prefer chacha20 (Encryption order between AES-256-GCM/AES-128-GCM)
        set_option!(cfg, prefer_chacha20, connector, set_prefer_chacha20);

        // Set TLS keylog policy if provided
        if let Some(ref policy) = self.keylog_policy {
            let handle = policy
                .clone()
                .open_handle()
                .map_err(crate::Error::builder)?;
            connector.set_keylog_callback(move |_, line| {
                handle.write_log_line(line);
            });
        }

        // Create the `HandshakeConfig` with the default session cache capacity.
        let config = HandshakeConfig::builder()
            .session_cache_capacity(8)
            .session_cache(cfg.pre_shared_key)
            .skip_session_ticket(cfg.psk_skip_session_ticket)
            .alps_protos(cfg.alps_protos)
            .alps_use_new_codepoint(cfg.alps_use_new_codepoint)
            .enable_ech_grease(cfg.enable_ech_grease)
            .tls_sni(self.tls_sni)
            .verify_hostname(self.verify_hostname)
            .random_aes_hw_override(cfg.random_aes_hw_override)
            .build();

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = config.session_cache.then(|| {
            let cache = Arc::new(Mutex::new(SessionCache::with_capacity(
                config.session_cache_capacity,
            )));

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.lock().insert(key.clone(), session);
                    }
                }
            });

            cache
        });

        Ok(TlsConnector {
            inner: Inner {
                ssl: connector.build(),
                cache,
                config,
            },
        })
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Creates a new `TlsConnectorBuilder` with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            keylog_policy: None,
            identity: None,
            cert_store: None,
            cert_verification: true,
            min_version: None,
            max_version: None,
            tls_sni: true,
            verify_hostname: true,
        }
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(TokioIo<SslStream<TokioIo<T>>>),
}

// ===== impl MaybeHttpsStream =====

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let mut connected = s.inner().get_ref().connected();

                if s.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }

                connected
            }
        }
    }
}

impl<T: Read + Write + Unpin> Read for MaybeHttpsStream<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: Write + Read + Unpin> Write for MaybeHttpsStream<T> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(s) => s.is_write_vectored(),
            MaybeHttpsStream::Https(s) => s.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
