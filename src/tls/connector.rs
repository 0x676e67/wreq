//! TLS connection services for TCP and Unix sockets, including proxy hops.

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVersion},
};
use futures_util::future::BoxFuture;
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

use super::{
    config::{ContextCache, TlsConfig},
    ext::{SslContextBuilderExt, set_ech_grease_host},
};
use crate::{
    Error, Protocol,
    conn::{
        Connected, Connection,
        config::{ConfigSet, Overrides},
        request::ConnectRequest,
    },
    ext::UriExt,
    protocol::TransportKind,
    tls::{AlpnProtocol, TlsOptions, session::SessionTarget},
};

const URI_MISSING_HOST: &str = "URI missing host";

/// Provides shared TLS state for HTTPS connection services.
/// Clones share the client policy and its compiled contexts.
/// Different request context options are compiled once and cached.
#[derive(Clone)]
pub struct HttpsLayer {
    inner: Arc<Inner>,
}

/// Client TLS policy and its compiled contexts.
struct Inner {
    config: TlsConfig,
    config_set: ConfigSet,
    options: Option<Arc<TlsOptions>>,
    contexts: ContextCache<SslConnector>,
}

/// Applies TLS to a route unless it is plain HTTP.
/// Holds the client's TLS state and the context selected for this request's options.
/// As a service it dials through `T`; proxy ALPN policy stays local to this connector.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    inner: T,
    tls: HttpsLayer,
    context: SslConnector,
    alpn_enabled: bool,
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

// ===== impl HttpsLayer =====

impl HttpsLayer {
    /// Compiles the client's TLS context while preserving the shared session scope.
    pub(super) fn new(config: TlsConfig, config_set: ConfigSet) -> crate::Result<Self> {
        let options = config_set.get_arc::<TlsOptions>();
        let contexts = ContextCache::new(compile(&config, options.as_deref())?);
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                config_set,
                options,
                contexts,
            }),
        })
    }

    /// Selects the context for the request's TLS options before dialing.
    /// Requests without different context options keep the client's context.
    pub(crate) fn for_request(self, req: &ConnectRequest) -> crate::Result<HttpsConnector<()>> {
        let inner = &*self.inner;
        let overrides = Overrides::for_context(
            req.config_set().clone(),
            &inner.config_set,
            TransportKind::Stream,
        );
        let context = inner.contexts.get(overrides, |overrides| {
            compile(&inner.config, overrides.get::<TlsOptions>())
        })?;
        Ok(HttpsConnector {
            inner: (),
            tls: self,
            context,
            alpn_enabled: true,
        })
    }

    /// Prepares a connection using its request-specific or shared TLS context.
    /// Unset or empty request ALPN inherits the client's list during handshake setup.
    fn ssl_for_connection(
        &self,
        req: ConnectRequest,
        conn: &dyn Connection,
        context: &SslConnector,
        alpn_enabled: bool,
    ) -> Result<Ssl, BoxError> {
        let inner = &*self.inner;
        let options = req
            .config_override::<TlsOptions>()
            .or(inner.options.as_deref());
        let mut cfg = context.configure()?;

        cfg.set_use_server_name_indication(inner.config.sni);
        cfg.set_verify_hostname(inner.config.verify_hostname);

        if let Some(options) = options
            && let Some(ref key_shares) = options.key_shares
        {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        // Disabled proxy ALPN also skips ALPS. An advertised ALPN list must be nonempty:
        // https://www.rfc-editor.org/rfc/rfc7301#section-3.1
        if alpn_enabled {
            let protocols: &[AlpnProtocol] = match req.resolved_protocol() {
                Protocol::Http1 => &[AlpnProtocol::HTTP1],
                #[cfg(feature = "http2")]
                Protocol::Http2 => &[AlpnProtocol::HTTP2],
                // Auto prefers the first nonempty request or client list, preserving its
                // order. HTTP/3 dials QUIC, which sets its own ALPN, so it never gets here.
                _ => options
                    .into_iter()
                    .chain(inner.options.as_deref())
                    .filter_map(|options| options.alpn_protocols.as_deref())
                    .find(|protocols| !protocols.is_empty())
                    .unwrap_or(&[
                        #[cfg(feature = "http2")]
                        AlpnProtocol::HTTP2,
                        AlpnProtocol::HTTP1,
                    ]),
            };
            cfg.set_alpn_protos(&AlpnProtocol::encode_sequence(protocols))?;

            // Offer ALPS only for protocols in this ALPN list, in ALPN order;
            // BoringSSL sends every configured ALPS protocol otherwise.
            if let Some(options) = options
                && let Some(ref alps) = options.alps_protocols
            {
                let mut offered = false;
                for (index, protocol) in protocols.iter().enumerate() {
                    let configured = alps.iter().any(|alps| alps.0 == protocol.0);
                    let repeated = protocols[..index].iter().any(|seen| seen.0 == protocol.0);
                    if configured && !repeated {
                        cfg.add_application_settings(protocol.0, None)?;
                        offered = true;
                    }
                }

                if offered {
                    cfg.set_alps_use_new_codepoint(options.alps_use_new_codepoint);
                }
            }
        }

        let host = req
            .route_uri()
            .host()
            .ok_or(URI_MISSING_HOST)
            .map(Self::normalize_host)?;

        if options.is_some_and(|options| options.ech_grease.is_some()) {
            set_ech_grease_host(&mut cfg, host.len())?;
        }

        if options.is_some_and(|options| options.pre_shared_key) {
            let tickets = &inner.config.tickets;
            let target = SessionTarget::new(
                &req,
                &inner.config_set,
                TransportKind::Stream,
                conn.remote_addr().map(|addr| addr.ip()),
                tickets.session_id_context()?,
            );

            if let Some(session) = tickets.pop_stream(&target) {
                // The key covers the TLS peer, request TLS options, proxy, and socket bindings;
                // btls checks the domain and client scope. HTTP-only options and ALPN do not
                // affect resumption without early data, which is never enabled.
                cfg.set_client_session(session);
            }

            let idx = target_index()?;
            cfg.set_ex_data(idx, target);
        }

        let mut ssl = cfg.into_ssl(host)?;

        if let Some(num_bytes) = options.and_then(|options| options.server_padding) {
            ssl.set_server_padding_request(num_bytes);
        }

        // A kept TLS 1.3 session is offered through pre_shared_key alone. TLS 1.2 ticket sessions
        // need session_ticket, and BoringSSL drops them when NO_TICKET is set.
        if options.is_some_and(|options| options.psk_skip_session_ticket)
            && ssl
                .session()
                .is_some_and(|session| session.protocol_version() == SslVersion::TLS1_3)
        {
            ssl.set_options(SslOptions::NO_TICKET);
        }

        Ok(ssl)
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
}

// ===== impl HttpsConnector =====

impl<S> HttpsConnector<S> {
    /// Replaces the transport while preserving the selected request context and ALPN policy.
    #[inline]
    pub(crate) fn with_inner<T>(self, inner: T) -> HttpsConnector<T> {
        HttpsConnector {
            inner,
            tls: self.tls,
            context: self.context,
            alpn_enabled: self.alpn_enabled,
        }
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.alpn_enabled = false;
        self
    }

    /// Returns whether responses carry the peer's [`TlsInfo`](crate::tls::TlsInfo).
    #[inline]
    pub(crate) fn tls_info(&self) -> bool {
        self.tls.inner.config.tls_info
    }

    /// Runs the TLS handshake over an established transport, or returns it unchanged for
    /// an `http` route. The transport may already carry a proxy's TLS.
    pub(crate) async fn handshake<IO>(
        &self,
        io: IO,
        req: ConnectRequest,
    ) -> Result<MaybeHttpsStream<IO>, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Connection + Unpin,
    {
        if req.route_uri().is_http() {
            return Ok(MaybeHttpsStream::Http(io));
        }

        let ssl = self
            .tls
            .ssl_for_connection(req, &io, &self.context, self.alpn_enabled)?;
        perform_handshake(ssl, io).await
    }
}

impl<T, S> Service<ConnectRequest> for HttpsConnector<S>
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
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        let connect = self.inner.call(req.route_uri().clone());
        let tls = HttpsConnector {
            inner: (),
            tls: self.tls.clone(),
            context: self.context.clone(),
            alpn_enabled: self.alpn_enabled,
        };

        Box::pin(async move {
            let conn = connect.await.map_err(Into::into)?;
            tls.handshake(conn, req).await
        })
    }
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

    #[inline]
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.as_ref().remote_addr()
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
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(cx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_shutdown(cx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_shutdown(cx),
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

/// Builds a TCP/Unix context from client policy and optional TLS options.
/// ALPN selection remains deferred until an individual connection is prepared.
fn compile(config: &TlsConfig, opts: Option<&TlsOptions>) -> crate::Result<SslConnector> {
    let max_tls_version = opts
        .and_then(|opts| opts.max_tls_version)
        .or(config.max_version);
    let min_tls_version = opts
        .and_then(|opts| opts.min_tls_version)
        .or(config.min_version);

    let mut builder = SslConnector::bare_builder(SslMethod::tls()).map_err(Error::tls)?;
    config.configure(&mut builder)?;

    builder
        .set_min_proto_version(min_tls_version.map(|version| version.0))
        .map_err(Error::tls)?;
    builder
        .set_max_proto_version(max_tls_version.map(|version| version.0))
        .map_err(Error::tls)?;

    if let Some(opts) = opts {
        builder.set_tls_options(opts)?;
    }

    // Register session storage callbacks only when resumption is enabled.
    if opts.is_some_and(|opts| opts.pre_shared_key) {
        config.enable_resumption(&mut builder)?;
        builder
            .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        let tickets = Arc::downgrade(&config.tickets);
        builder.set_client_session_callback(move |ssl, session| {
            if let Some(tickets) = tickets.upgrade()
                && let Ok(Some(target)) = target_index().map(|idx| ssl.ex_data(idx))
            {
                tickets.insert_stream(target, session);
            }
        });
    }

    Ok(builder.build())
}

fn target_index() -> Result<Index<Ssl, SessionTarget>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, SessionTarget>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
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
