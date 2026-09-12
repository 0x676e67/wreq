//! SSL support via BoringSSL.

#[macro_use]
mod macros;
mod ext;

use std::{
    borrow::Cow,
    fmt, io,
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
use futures_util::future::BoxFuture;
use http::{Uri, uri::Scheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Layer, Service};

use crate::{
    Error, HttpVersion,
    conn::{Connected, Connection, descriptor::ConnectionDescriptor},
    ext::UriExt,
    tls::{
        AlpnProtocol, AlpsProtocol, KeyShare, TlsOptions, TlsVersion,
        keylog::KeyLog,
        session::{Key, LruTlsSessionCache, TlsSession, TlsSessionCache},
        trust::{CertStore, Identity},
    },
};

fn key_index() -> Result<Index<Ssl, Key>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Key>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

async fn perform_handshake<T>(ssl: Ssl, conn: T) -> Result<MaybeHttpsStream<T>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = SslStream::new(ssl, conn)?;
    Pin::new(&mut stream).connect().await?;
    Ok(MaybeHttpsStream::Https(stream))
}

/// TLS configuration applied when preparing an individual connection.
/// Combines client policy with handshake parameters from [`TlsOptions`].
/// Retained by its TLS context for reuse across handshakes.
#[derive(Clone)]
pub struct HandshakeConfig {
    version: HttpVersion,
    alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,
    alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,
    alps_use_new_codepoint: bool,
    key_shares: Option<Cow<'static, [KeyShare]>>,
    tls_sni: bool,
    verify_hostname: bool,
    no_ticket: bool,
    enable_ech_grease: bool,
    random_aes_hw_override: bool,
}

/// Connects an inner transport and applies TLS when the destination requires it.
/// Shares client TLS state and optionally owns a request-specific context.
/// Proxy ALPN policy stays local to this service, leaving shared contexts unchanged.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls: TlsConnector,
    context: Option<TlsContext>,
    alpn_enabled: bool,
}

/// Configures the client-wide TLS connector before transport services are composed.
/// Building validates the base context and consumes this builder.
/// Its immutable configuration remains available for request-specific contexts.
pub struct TlsConnectorBuilder {
    config: Config,
}

/// Immutable TLS policy used to construct base and request-specific contexts.
/// Retains trust, identity, client protocols, and the shared session cache.
/// Moves from the builder into the base context and is cloned for overrides.
#[derive(Clone)]
struct Config {
    version: HttpVersion,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
    keylog: Option<KeyLog>,
    session: Arc<dyn TlsSessionCache>,
}

/// Provides shared TLS state for HTTPS connection services.
/// Shares the validated base context and immutable policy in one allocation.
/// Implements `Layer<S>` to compose an [`HttpsConnector`] without rebuilding contexts.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<TlsContext>,
}

/// A compiled TLS context and its [`HandshakeConfig`].
/// Retains client policy for rebuilding contexts with request-specific options.
/// Shares the session cache while keeping each context's TLS settings independent.
#[derive(Clone)]
struct TlsContext {
    config: Config,
    ssl: SslConnector,
    session: Option<Arc<dyn TlsSessionCache>>,
    settings: HandshakeConfig,
}

// ===== impl HttpsConnector =====

impl<S> HttpsConnector<S> {
    /// Prepares a request-specific context before the TLS handshake.
    /// Without overrides, the service continues to borrow the shared base context.
    pub fn with_options(mut self, options: Option<&TlsOptions>) -> crate::Result<Self> {
        self.context = match options {
            Some(options) => Some(TlsContext::new(
                self.tls.inner.config.clone(),
                Some(options),
            )?),
            None => None,
        };
        Ok(self)
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.alpn_enabled = false;
        self
    }
}

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect = self.http.call(uri.clone());
        let tls = self.tls.clone();
        let context = self.context.clone();

        Box::pin(async move {
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if uri.scheme() != Some(&Scheme::HTTPS) {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = tls.ssl_for_uri(uri, context.as_ref())?;
            perform_handshake(ssl, conn).await
        })
    }
}

impl<T, S> Service<ConnectionDescriptor> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, descriptor: ConnectionDescriptor) -> Self::Future {
        let alpn_enabled = self.alpn_enabled;
        let tls = self.tls.clone();
        let context = self.context.clone();
        let connect = self.http.call(descriptor.uri().clone());

        Box::pin(async move {
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if descriptor.uri().is_http() {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = tls.ssl_for_connection(descriptor, context.as_ref(), alpn_enabled)?;
            perform_handshake(ssl, conn).await
        })
    }
}

impl<T, S, IO> Service<EstablishedConn<IO>> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + Sync + fmt::Debug + 'static,
{
    type Response = MaybeHttpsStream<IO>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, conn: EstablishedConn<IO>) -> Self::Future {
        let alpn_enabled = self.alpn_enabled;
        let tls = self.tls.clone();
        let context = self.context.clone();

        Box::pin(async move {
            // Early return if it is not a tls scheme
            if conn.descriptor.uri().is_http() {
                return Ok(MaybeHttpsStream::Http(conn.io));
            }

            let ssl = tls.ssl_for_connection(conn.descriptor, context.as_ref(), alpn_enabled)?;
            perform_handshake(ssl, conn.io).await
        })
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Prepares URI-only TLS using the request context or shared base context.
    /// Descriptor-specific ALPN and session selection stay in `ssl_for_connection`.
    fn ssl_for_uri(&self, uri: Uri, context: Option<&TlsContext>) -> Result<Ssl, BoxError> {
        let context = context.unwrap_or(&self.inner);
        let cfg = context.ssl.configure()?;
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);
        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    /// Prepares a connection using its request context or the shared base context.
    /// Unset or empty request ALPN inherits the base list during handshake setup.
    fn ssl_for_connection(
        &self,
        descriptor: ConnectionDescriptor,
        context: Option<&TlsContext>,
        alpn_enabled: bool,
    ) -> Result<Ssl, BoxError> {
        let context = context.unwrap_or(&self.inner);
        let mut cfg = context.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(context.settings.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(context.settings.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(context.settings.enable_ech_grease);

        // Proxy TLS can suppress ALPN entirely via no_alpn().
        if alpn_enabled {
            // HTTPS ALPN after client::svc::Stack resolves the explicit request version:
            // | Client     | Request                   | TlsOptions ALPN | Offered ALPN |
            // |------------|---------------------------|-----------------|--------------|
            // | any        | HTTP/1.0 or HTTP/1.1      | ignored         | [http/1.1]   |
            // | any        | HTTP/2 + Extended CONNECT | ignored         | [h2]         |
            // | Http1      | unset                     | ignored         | [http/1.1]   |
            // | Http2      | unset or HTTP/2           | ignored         | [h2]         |
            // | Auto       | unset                     | see below       | TLS list     |
            // | Auto/Http1 | HTTP/2 (ordinary request) | see below       | TLS list     |
            // TLS list: nonempty request list, then client list, else [h2, http/1.1].
            // None and empty lists inherit; custom list order is preserved.
            let protocols: &[AlpnProtocol] = match (
                descriptor.version().unwrap_or(context.settings.version),
                context.settings.alpn_protocols.as_deref(),
                self.inner.settings.alpn_protocols.as_deref(),
            ) {
                (HttpVersion::Http1, _, _) => &[AlpnProtocol::HTTP1],
                (HttpVersion::Http2, _, _) => &[AlpnProtocol::HTTP2],
                (HttpVersion::Auto, Some(protocols), _) if !protocols.is_empty() => protocols,
                (HttpVersion::Auto, _, Some(protocols)) if !protocols.is_empty() => protocols,
                (HttpVersion::Auto, _, _) => &[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1],
            };
            cfg.set_alpn_protos(&AlpnProtocol::encode_sequence(protocols))?;
        }

        // Set ALPS protos
        if let Some(ref alps_values) = context.settings.alps_protocols {
            for alps in alps_values.iter() {
                cfg.add_application_settings(alps.0)?;
            }

            // By default, the new endpoint is used.
            if !alps_values.is_empty() {
                cfg.set_alps_use_new_codepoint(context.settings.alps_use_new_codepoint);
            }
        }

        // Set random AES hardware override
        if context.settings.random_aes_hw_override {
            let random = (crate::util::fast_random() & 1) == 0;
            cfg.set_aes_hw_override(random);
        }

        // Set TLS key shares
        if let Some(ref key_shares) = context.settings.key_shares {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        let uri = descriptor.uri().clone();
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);

        if let Some(ref cache) = context.session {
            let key = Key(descriptor.id());

            // If the session cache is enabled, we try to retrieve the session
            // associated with the key. If it exists, we set it in the SSL configuration.
            if let Some(session) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session.0) }?;

                if context.settings.no_ticket {
                    cfg.set_options(SslOptions::NO_TICKET);
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        Ok(cfg.into_ssl(host)?)
    }

    /// Strips brackets from valid IPv6 literals before TLS hostname verification.
    /// BoringSSL requires the unbracketed address to recognize an IP literal.
    fn normalize_host(host: &str) -> &str {
        let normalized = crate::util::strip_ipv6_brackets(host);
        if normalized.len() != host.len() && normalized.parse::<std::net::Ipv6Addr>().is_ok() {
            return normalized;
        }

        host
    }

    /// Starts configuring the client-wide TLS policy.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            config: Config {
                version: HttpVersion::Auto,
                min_version: None,
                max_version: None,
                identity: None,
                tls_sni: true,
                verify_hostname: true,
                cert_store: None,
                cert_verification: true,
                keylog: None,
                session: Arc::new(LruTlsSessionCache::new(8)),
            },
        }
    }
}

impl<S> Layer<S> for TlsConnector {
    type Service = HttpsConnector<S>;

    fn layer(&self, http: S) -> Self::Service {
        HttpsConnector {
            http,
            tls: self.clone(),
            context: None,
            alpn_enabled: true,
        }
    }
}

// ===== impl TlsContext =====

impl TlsContext {
    /// Builds the backend context from client policy and optional TLS overrides.
    /// Takes ownership of the policy so later overrides can reuse its inputs.
    /// ALPN selection remains deferred until an individual connection is prepared.
    fn new(config: Config, opts: Option<&TlsOptions>) -> crate::Result<Self> {
        // Determine the minimum and maximum TLS versions to use.
        let max_tls_version = opts
            .and_then(|opts| opts.max_tls_version)
            .or(config.max_version);
        let min_tls_version = opts
            .and_then(|opts| opts.min_tls_version)
            .or(config.min_version);

        // Create the SslConnector with the provided options
        let mut connector = SslConnector::bare_builder(SslMethod::tls())
            .map_err(Error::tls)?
            .set_identity(config.identity.as_ref())?
            .set_cert_store(config.cert_store.as_ref())?
            .set_cert_verification(config.cert_verification);

        // Set minimum TLS version
        set_option_inner_try!(min_tls_version, connector, set_min_proto_version);

        // Set maximum TLS version
        set_option_inner_try!(max_tls_version, connector, set_max_proto_version);

        // Skip customization when options are absent, while retaining client policy.
        if let Some(opts) = opts {
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
            set_option!(opts, !session_ticket, connector, SslOptions::NO_TICKET);

            // Set TLS PSK DHE key exchange options
            set_option!(opts, !psk_dhe_ke, connector, SslOptions::NO_PSK_DHE_KE);

            // Set TLS No Renegotiation options
            set_option!(
                opts,
                !renegotiation,
                connector,
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

            // Preserve TLS 1.3 cipher list order
            set_option!(
                opts,
                preserve_tls13_cipher_list,
                connector,
                set_preserve_tls13_cipher_list
            );

            // Set TLS cipher list
            set_option_ref_try!(opts, cipher_list, connector, set_cipher_list);

            // Set certificate compression algorithms
            set_option_ref_try!(
                opts,
                certificate_compressors,
                connector,
                set_cert_compressors
            );

            // Set TLS delegated credentials
            set_option_ref_try!(
                opts,
                delegated_credentials,
                connector,
                set_delegated_credentials
            );

            // Set TLS record size limit
            set_option!(opts, record_size_limit, connector, set_record_size_limit);

            // Set TLS aes hardware override
            set_option!(opts, aes_hw_override, connector, set_aes_hw_override);

            // The specification distinguishes an empty requested list from omitting the extension.
            set_option_ref_try!(opts, trust_anchors, connector, set_requested_trust_anchors);

            // Set TLS extension permutation
            set_option_ref_try!(
                opts,
                extension_permutation,
                connector,
                set_extension_permutation
            );
        }

        // Set TLS keylog handler.
        if let Some(ref policy) = config.keylog {
            let handle = policy.clone().handle().map_err(Error::tls)?;
            connector.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        // Prepare the settings used by individual handshakes.
        let settings = HandshakeConfig {
            tls_sni: config.tls_sni,
            verify_hostname: config.verify_hostname,
            version: config.version,
            alpn_protocols: opts.and_then(|opts| opts.alpn_protocols.clone()),
            alps_protocols: opts.and_then(|opts| opts.alps_protocols.clone()),
            alps_use_new_codepoint: opts.is_some_and(|opts| opts.alps_use_new_codepoint),
            enable_ech_grease: opts.is_some_and(|opts| opts.enable_ech_grease),
            key_shares: opts.and_then(|opts| opts.key_shares.clone()),
            no_ticket: opts.is_some_and(|opts| opts.psk_skip_session_ticket),
            random_aes_hw_override: opts.is_some_and(|opts| opts.random_aes_hw_override),
        };

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.is_some_and(|opts| opts.pre_shared_key).then(|| {
            let cache = config.session.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.put(key.clone(), TlsSession(session));
                    }
                }
            });

            cache
        });

        Ok(Self {
            config,
            ssl: connector.build(),
            session: cache,
            settings,
        })
    }
}

// ===== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Supplies the client's protocol selection without encoding an ALPN offer.
    /// Fixed modes take precedence over TLS options during the handshake.
    /// Automatic selection preserves the configured TLS ALPN list.
    #[inline]
    pub fn http_version(mut self, version: HttpVersion) -> Self {
        self.config.version = version;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.config.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.config.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.config.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.config.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.config.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.config.verify_hostname = enabled;
        self
    }

    /// Sets the shared TLS session cache.
    #[inline]
    pub fn session(mut self, session: Option<Arc<dyn TlsSessionCache>>) -> Self {
        if let Some(session) = session {
            self.config.session = session;
        }
        self
    }

    /// Validates the base context and consumes this builder into a shared TLS connector.
    /// Missing options leave TLS customization to the backend's defaults.
    /// Client-wide trust, version, and ALPN policy still applies.
    pub fn build(self, opts: Option<TlsOptions>) -> crate::Result<TlsConnector> {
        Ok(TlsConnector {
            inner: Arc::new(TlsContext::new(self.config, opts.as_ref())?),
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

/// An established transport paired with its target connection descriptor.
/// Bypasses physical dialing when the TLS service upgrades a proxy tunnel.
/// Owns the stream until the handshake completes or the connection attempt is dropped.
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
