//! TLS connector for TCP and Unix streams, including `https://` proxy hops.

use std::{
    fmt, io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{self, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    nid::Nid,
    ssl::{
        ClientSession, Ssl, SslCipherRef, SslConnector, SslMethod, SslOptions, SslSessionCacheMode,
        SslVersion,
    },
};
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::BoxError;

use super::{
    AlpnProtocol, Config, KeyIdentity, TlsContext, TlsOptions,
    macros::set_hello_options,
    session::{Key, Ticket, Tickets},
    set_ech_grease_host,
};
use crate::{Error, config::ConnectConfig};

/// The error message used when a URI is missing its host component.
const URI_MISSING_HOST: &str = "URI missing host";

/// The ex data index for storing the session identity in an SSL connection.
static IDX: LazyLock<Result<Index<Ssl, Target>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);

/// Shared TLS settings and compiled context cache for TCP and Unix streams.
///
/// Owned by the stream connector; [`Context::for_config`] resolves a [`TlsConnector`] for
/// each request using either the base context or a cached override.
pub struct Context {
    config: Config,
    context: TlsContext<TlsOptions, SslConnector>,
}

/// Performs TLS handshakes for a request and its `https://` proxy hop.
///
/// Holds the context selected for the request's options; ALPN can be toggled independently
/// on each clone.
#[derive(Clone)]
pub struct TlsConnector {
    inner: SslConnector,
    context: Arc<Context>,
    alpn_enabled: bool,
}

/// Byte stream that may be either plaintext or wrapped in a BoringSSL [`SslStream`].
///
/// Used while routing direct, tunneled, and proxied stream connections before boxing.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

/// Session lookup identity stored in an SSL connection's ex-data.
///
/// Carries the base session key and the underlying socket's peer IP so BoringSSL's
/// new-session callback can store RSA tickets under an IP-bound key.
struct Target {
    key: Key,
    remote_ip: Option<IpAddr>,
}

// ===== impl Context =====

impl Context {
    /// Compiles the base TLS context from client settings and default options.
    ///
    /// Without [`TlsOptions`], uses BoringSSL defaults alongside the client-wide TLS settings.
    pub(crate) fn new(tls: Config, config: &ConnectConfig) -> crate::Result<Self> {
        compile(&tls, config.get_ref()).map(|inner| Self {
            config: tls,
            context: TlsContext::new(inner),
        })
    }

    /// Returns a [`TlsConnector`] for `config`, reusing the base context when no
    /// context-level options differ.
    pub(crate) fn for_config(
        self: Arc<Self>,
        config: &ConnectConfig,
    ) -> crate::Result<TlsConnector> {
        let options = config.override_if_different(KeyIdentity::same);
        self.context
            .get_or_compile(options, |options| compile(&self.config, Some(options)))
            .map(|inner| TlsConnector {
                inner,
                alpn_enabled: true,
                context: self,
            })
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Builds an [`Ssl`] handle for a connection to `route`.
    ///
    /// Unset or empty request ALPN inherits the client's list. `remote_addr` is the underlying
    /// socket's peer address, used to key RSA session tickets.
    fn ssl_for_connection(
        &self,
        origin: &Uri,
        route: &Uri,
        alpn: Option<AlpnProtocol>,
        remote_addr: Option<IpAddr>,
        config: &ConnectConfig,
    ) -> Result<Ssl, BoxError> {
        let tls = &self.context.config;
        let options = config.get_ref::<TlsOptions>();
        let mut cfg = self.inner.configure()?;

        cfg.set_verify_hostname(tls.verify_hostname);
        cfg.set_use_server_name_indication(tls.sni);

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
                    .chain(config.base_ref::<TlsOptions>())
                    .filter_map(|options| options.alpn_protocols.as_deref())
                    .find(|protocols| !protocols.is_empty())
                    .unwrap_or(&[
                        #[cfg(feature = "http2")]
                        AlpnProtocol::HTTP2,
                        AlpnProtocol::HTTP1,
                    ])
            };
            let protocols = alpn.as_ref().map_or_else(auto, std::slice::from_ref);
            cfg.set_alpn_protos(&AlpnProtocol::encode_sequence(protocols))?;

            // Offer ALPS only for protocols in this ALPN list, in ALPN order;
            // BoringSSL sends every configured ALPS protocol otherwise.
            if let Some(options) = options
                && let Some(ref alps) = options.alps_protocols
            {
                let mut offered = false;
                for (index, protocol) in protocols.iter().enumerate() {
                    let configured = alps.iter().any(|alps| alps.as_bytes() == protocol.0);
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
            let target = Target::new(&tls.tickets, origin, route, config, remote_addr)?;
            if let Some(session) = target.take(&tls.tickets) {
                // The key covers the TLS peer, request TLS options, proxy, and socket bindings;
                // btls checks the domain and client scope. HTTP-only options and ALPN do not
                // affect resumption without early data, which is never enabled.
                cfg.set_client_session(session);
            }
            cfg.set_ex_data(IDX.clone()?, target);
        }

        // Convert the configured context into an SSL object for the handshake.
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
    #[must_use]
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
        self.context.config.tls_info
    }

    /// Runs a TLS handshake against `route` (either the origin or a proxy hop).
    ///
    /// `remote_addr` is the underlying socket's peer address, even inside a CONNECT tunnel.
    pub(crate) async fn handshake<IO>(
        &self,
        io: IO,
        origin: &Uri,
        route: &Uri,
        alpn: Option<AlpnProtocol>,
        remote_addr: Option<IpAddr>,
        config: &ConnectConfig,
    ) -> Result<SslStream<IO>, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self.ssl_for_connection(origin, route, alpn, remote_addr, config)?;
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
        cx: &mut task::Context<'_>,
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
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(cx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
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
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }
}

// ===== impl Target =====

impl Target {
    /// Builds a session key for the given origin, peer, and socket address.
    fn new(
        tickets: &Tickets,
        origin: &Uri,
        peer: &Uri,
        config: &ConnectConfig,
        remote_ip: Option<IpAddr>,
    ) -> Result<Self, ErrorStack> {
        tickets
            .key::<TlsOptions, ClientSession>(origin, peer, config)
            .map(|key| Self { key, remote_ip })
    }

    /// Pops a matching session, falling back to the IP-bound RSA key.
    #[must_use]
    fn take(&self, tickets: &Tickets) -> Option<ClientSession> {
        let native = |ticket| match ticket {
            Ticket::Native(session) => Some(session),
            Ticket::Opaque { .. } => None,
        };
        tickets
            .pop(&self.key)
            .and_then(native)
            .or_else(|| tickets.pop(&self.rsa_key()?).and_then(native))
    }

    /// Stores a session under the key required by its negotiated key exchange.
    fn put(&self, tickets: &Tickets, session: ClientSession) {
        let kx = session
            .session()
            .cipher()
            .and_then(SslCipherRef::cipher_kx_nid);
        if let Some(key) = self.key_for(kx) {
            tickets.put(key, Ticket::Native(session));
        }
    }

    #[must_use]
    fn rsa_key(&self) -> Option<Key> {
        self.remote_ip.map(|ip| self.key.with_remote_ip(ip))
    }

    #[must_use]
    fn key_for(&self, kx: Option<Nid>) -> Option<Key> {
        if kx == Some(Nid::KX_RSA) {
            self.rsa_key()
        } else {
            Some(self.key.clone())
        }
    }
}

/// Compiles an [`SslConnector`] from client settings and optional [`TlsOptions`].
///
/// ALPN is configured per connection rather than on the shared context.
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
        set_hello_options!(all, opts, &mut builder);
    }

    // Register session storage callbacks only when resumption is enabled.
    if opts.is_some_and(|opts| opts.pre_shared_key) {
        config.enable_resumption(&mut builder)?;
        builder
            .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        let tickets = Arc::downgrade(&config.tickets);
        builder.set_client_session_callback(move |ssl, session| {
            if let Some(tickets) = tickets.upgrade()
                && let Ok(Some(target)) = IDX.clone().map(|idx| ssl.ex_data(idx))
            {
                target.put(&tickets, session);
            }
        });
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_exchange_sessions_are_keyed_by_remote_ip() {
        let tickets = Tickets::new(None);
        let connect_config = ConnectConfig::default();
        let origin = Uri::from_static("https://example.com/");
        let target = |ip| Target::new(&tickets, &origin, &origin, &connect_config, ip).unwrap();
        let known = target(Some(IpAddr::from([192, 0, 2, 1])));

        let rsa = known.key_for(Some(Nid::KX_RSA)).unwrap();
        assert!(rsa != known.key);
        for kx in [Some(Nid::KX_ECDHE), Some(Nid::KX_ANY), None] {
            assert!(known.key_for(kx).is_some_and(|key| key == known.key));
        }
        assert!(target(None).key_for(Some(Nid::KX_RSA)).is_none());
    }
}
