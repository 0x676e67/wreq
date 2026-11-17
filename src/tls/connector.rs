//! TLS connection services for TCP and Unix sockets, including proxy hops.

use std::{
    fmt, io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVersion},
};
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::BoxError;

use super::{
    Config,
    context::TlsContext,
    ext::{SslContextBuilderExt, set_ech_grease_host},
};
use crate::{
    Error,
    config::connect::ConnectConfig,
    protocol::Protocol,
    tls::{AlpnProtocol, TlsOptions, session::SessionTarget},
};

const URI_MISSING_HOST: &str = "URI missing host";

/// Compiled TLS for TCP and Unix streams, including proxy hops.
/// Clones share the client policy and its compiled contexts.
/// Different request context options are compiled once and cached.
#[derive(Clone)]
pub struct StreamTls {
    contexts: Arc<TlsContext<TlsOptions, SslConnector>>,
}

/// Runs the TLS handshakes of one request over streams it is given: the target's and an
/// `https` proxy hop's. Holds the client's TLS state and the context selected for the
/// request's options; the ALPN switch stays local to each copy.
#[derive(Clone)]
pub struct TlsConnector {
    tls: StreamTls,
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

// ===== impl StreamTls =====

impl StreamTls {
    /// Compiles the client's TLS context while preserving the shared session scope.
    pub(super) fn new(tls: Config, config: &ConnectConfig) -> crate::Result<Self> {
        Ok(Self {
            contexts: Arc::new(TlsContext::new(tls, config, compile)?),
        })
    }

    /// Selects the context for the request's TLS options before dialing.
    /// Requests without different context options keep the client's context.
    pub(crate) fn for_config(self, overrides: &ConnectConfig) -> crate::Result<TlsConnector> {
        let context = self.contexts.for_config(overrides, compile)?;
        Ok(TlsConnector {
            tls: self,
            context,
            alpn_enabled: true,
        })
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Prepares a connection using its request-specific or shared TLS context.
    /// Unset or empty request ALPN inherits the client's list during handshake setup.
    /// `remote_ip` is the dialed socket's peer, which keys session resumption.
    fn ssl_for_connection(
        &self,
        origin: &Uri,
        protocol: Protocol,
        overrides: &ConnectConfig,
        route: &Uri,
        remote_ip: Option<IpAddr>,
    ) -> Result<Ssl, BoxError> {
        let contexts = &self.tls.contexts;
        let options = overrides.get_ref::<TlsOptions>();
        let options = options.or(contexts.options.as_deref());
        let mut cfg = self.context.configure()?;

        cfg.set_use_server_name_indication(contexts.tls.sni);
        cfg.set_verify_hostname(contexts.tls.verify_hostname);

        if let Some(options) = options
            && let Some(ref key_shares) = options.key_shares
        {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        // Disabled proxy ALPN also skips ALPS. An advertised ALPN list must be nonempty:
        // https://www.rfc-editor.org/rfc/rfc7301#section-3.1
        if self.alpn_enabled {
            let auto = || {
                options
                    .into_iter()
                    .chain(contexts.options.as_deref())
                    .filter_map(|options| options.alpn_protocols.as_deref())
                    .find(|protocols| !protocols.is_empty())
                    .unwrap_or(&[
                        #[cfg(feature = "http2")]
                        AlpnProtocol::HTTP2,
                        AlpnProtocol::HTTP1,
                    ])
            };
            let protocols: &[AlpnProtocol] = match protocol {
                Protocol::Http1 => &[AlpnProtocol::HTTP1],
                #[cfg(feature = "http2")]
                Protocol::Http2 => &[AlpnProtocol::HTTP2],
                // Auto prefers the first nonempty request or client list, preserving its
                // order. HTTP/3 dials QUIC, which sets its own ALPN, so it never gets here.
                Protocol::Auto => auto(),
                #[cfg(feature = "http3")]
                Protocol::Http3 => auto(),
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

        let host = route
            .host()
            .ok_or(URI_MISSING_HOST)
            .map(Self::normalize_host)?;

        if options.is_some_and(|options| options.ech_grease.is_some()) {
            set_ech_grease_host(&mut cfg, host.len())?;
        }

        if options.is_some_and(|options| options.pre_shared_key) {
            let tickets = &contexts.tls.tickets;
            let target = SessionTarget::new(
                origin,
                overrides,
                &contexts.client_config,
                route,
                false,
                remote_ip,
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

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.alpn_enabled = false;
        self
    }

    /// Returns whether responses carry the peer's [`TlsInfo`](crate::tls::TlsInfo).
    #[inline]
    pub(crate) fn tls_info(&self) -> bool {
        self.tls.contexts.tls.tls_info
    }

    /// Authenticates the origin or proxy at `route` with the selected TLS options.
    /// `remote_ip` is the peer of the underlying socket, even inside a CONNECT tunnel.
    pub(crate) async fn handshake<IO>(
        &self,
        io: IO,
        origin: &Uri,
        protocol: Protocol,
        overrides: &ConnectConfig,
        route: &Uri,
        remote_ip: Option<IpAddr>,
    ) -> Result<SslStream<IO>, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self.ssl_for_connection(origin, protocol, overrides, route, remote_ip)?;
        let mut stream = SslStream::new(ssl, io)?;
        Pin::new(&mut stream).connect().await?;
        Ok(stream)
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
fn compile(config: &Config, opts: Option<&TlsOptions>) -> crate::Result<SslConnector> {
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
