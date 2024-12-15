#[cfg(feature = "boring-tls")]
use self::boring_tls_conn::BoringTlsConn;
#[cfg(feature = "boring-tls")]
use crate::tls::{BoringTlsConnector, MaybeHttpsStream};
#[cfg(feature = "boring-tls")]
use http::header::HeaderValue;
use http::uri::{Authority, Scheme};
use http::Uri;
use hyper::client::connect::{Connected, Connection};
use hyper::ext::PoolKeyExt;
use hyper::service::Service;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use pin_project_lite::pin_project;
use std::borrow::Cow;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::dns::DynResolver;
use crate::error::BoxError;
use crate::proxy::{Proxy, ProxyScheme};

pub(crate) type HttpConnector = hyper::client::HttpConnector<DynResolver>;

#[derive(Clone)]
pub(crate) struct Connector {
    inner: Inner,
    proxies: Arc<Vec<Proxy>>,
    verbose: verbose::Wrapper,
    timeout: Option<Duration>,
    #[cfg(feature = "boring-tls")]
    nodelay: bool,
    #[cfg(feature = "boring-tls")]
    tls_info: bool,
    pool_key_ext: Option<PoolKeyExt>,
}

#[derive(Clone)]
enum Inner {
    #[cfg(not(feature = "boring-tls"))]
    Http(HttpConnector),
    #[cfg(feature = "boring-tls")]
    BoringTls {
        http: HttpConnector,
        tls: BoringTlsConnector,
    },
}

impl Connector {
    #[cfg(not(feature = "boring-tls"))]
    pub fn new(
        mut http: HttpConnector,
        proxies: Arc<Vec<Proxy>>,
        local_addr_v4: Option<Ipv4Addr>,
        local_addr_v6: Option<Ipv6Addr>,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        interface: Option<std::borrow::Cow<'static, str>>,
        nodelay: bool,
    ) -> Connector {
        match (local_addr_v4, local_addr_v6) {
            (Some(v4), Some(v6)) => http.set_local_addresses(v4, v6),
            (Some(v4), None) => http.set_local_address(Some(IpAddr::from(v4))),
            (None, Some(v6)) => http.set_local_address(Some(IpAddr::from(v6))),
            _ => {}
        }
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref interface) = interface {
            http.set_interface(interface.clone());
        }
        http.set_nodelay(nodelay);

        let mut connector = Connector {
            inner: Inner::Http(http),
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            pool_key_ext: None,
        };

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        connector.set_pool_key_ext(local_addr_v4.map(IpAddr::V4), local_addr_v6.map(IpAddr::V6));

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        connector.set_pool_key_ext(
            local_addr_v4.map(IpAddr::V4),
            local_addr_v6.map(IpAddr::V6),
            interface,
        );

        connector
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "boring-tls")]
    pub(crate) fn new_boring_tls(
        mut http: HttpConnector,
        tls: BoringTlsConnector,
        proxies: Arc<Vec<Proxy>>,
        local_addr_v4: Option<Ipv4Addr>,
        local_addr_v6: Option<Ipv6Addr>,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        interface: Option<std::borrow::Cow<'static, str>>,
        nodelay: bool,
        tls_info: bool,
    ) -> Connector {
        match (local_addr_v4, local_addr_v6) {
            (Some(v4), Some(v6)) => http.set_local_addresses(v4, v6),
            (Some(v4), None) => http.set_local_address(Some(IpAddr::from(v4))),
            (None, Some(v6)) => http.set_local_address(Some(IpAddr::from(v6))),
            _ => {}
        }
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref interface) = interface {
            http.set_interface(interface.clone());
        }
        http.enforce_http(false);

        let mut connector = Connector {
            inner: Inner::BoringTls { http, tls },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info,
            pool_key_ext: None,
        };

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        connector.set_pool_key_ext(local_addr_v4.map(IpAddr::V4), local_addr_v6.map(IpAddr::V6));

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        connector.set_pool_key_ext(
            local_addr_v4.map(IpAddr::V4),
            local_addr_v6.map(IpAddr::V6),
            interface,
        );

        connector
    }

    #[inline]
    pub(crate) fn set_keepalive(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(http) => http.set_keepalive(dur),
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, .. } => http.set_keepalive(dur),
        }
    }

    #[inline]
    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    #[inline]
    pub(crate) fn set_verbose(&mut self, enabled: bool) {
        self.verbose.0 = enabled;
    }

    #[inline]
    pub(crate) fn get_proxies(&self) -> &[Proxy] {
        self.proxies.as_ref()
    }

    #[inline]
    pub(crate) fn set_proxies(&mut self, proxies: Cow<'static, [Proxy]>) -> Vec<Proxy> {
        std::mem::replace(self.proxies_mut(), proxies.into_owned())
    }

    #[inline]
    pub(crate) fn append_proxies(&mut self, proxies: Cow<'static, [Proxy]>) {
        self.proxies_mut().extend(proxies.into_owned());
    }

    #[inline]
    pub(crate) fn clear_proxies(&mut self) {
        self.proxies_mut().clear();
    }

    #[inline]
    fn proxies_mut(&mut self) -> &mut Vec<Proxy> {
        Arc::make_mut(&mut self.proxies)
    }

    #[inline]
    pub(crate) fn set_local_address(&mut self, addr: Option<IpAddr>) {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        self.set_pool_key_ext(addr, None, None);

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        self.set_pool_key_ext(addr, None);

        match &mut self.inner {
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(http) => http.set_local_address(addr),
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, .. } => http.set_local_address(addr),
        }
    }

    #[inline]
    pub(crate) fn set_local_addresses(&mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        self.set_pool_key_ext(IpAddr::V4(addr_ipv4), IpAddr::V6(addr_ipv6), None);

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        self.set_pool_key_ext(IpAddr::V4(addr_ipv4), IpAddr::V6(addr_ipv6));

        match &mut self.inner {
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(http) => http.set_local_addresses(addr_ipv4, addr_ipv6),
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, .. } => http.set_local_addresses(addr_ipv4, addr_ipv6),
        }
    }

    #[inline]
    fn set_pool_key_ext(
        &mut self,
        addr_ipv4: impl Into<Option<IpAddr>>,
        addr_ipv6: impl Into<Option<IpAddr>>,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        interface: impl Into<Option<std::borrow::Cow<'static, str>>>,
    ) {
        if self.proxies.is_empty() {
            let ipv4 = addr_ipv4.into();
            let ipv6 = addr_ipv6.into();
            match (&ipv4, &ipv6) {
                (Some(_), Some(_)) | (None, Some(_)) | (Some(_), None) => {
                    self.pool_key_ext = Some(PoolKeyExt::Address(ipv4, ipv6));
                }
                _ =>
                {
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    if let Some(interface) = interface.into() {
                        self.pool_key_ext = Some(PoolKeyExt::Interface(interface));
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline]
    pub(crate) fn set_interface(&mut self, interface: std::borrow::Cow<'static, str>) {
        if self.proxies.is_empty() {
            self.pool_key_ext = Some(PoolKeyExt::Interface(interface.clone()));
        }

        match &mut self.inner {
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(http) => http.set_interface(interface),
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, .. } => http.set_interface(interface),
        };
    }

    #[cfg(feature = "boring-tls")]
    #[inline]
    pub(crate) fn set_connector(&mut self, connector: BoringTlsConnector) {
        match &mut self.inner {
            Inner::BoringTls { tls, .. } => *tls = connector,
        }
    }

    #[inline]
    pub(crate) fn pool_key_extension(&self, uri: &Uri) -> Option<PoolKeyExt> {
        for proxy in self.proxies.as_ref() {
            if let Some(proxy_scheme) = proxy.intercept(uri) {
                let ext = match proxy_scheme {
                    ProxyScheme::Http { host, auth } => PoolKeyExt::Http(Scheme::HTTP, host, auth),
                    ProxyScheme::Https { host, auth } => {
                        PoolKeyExt::Http(Scheme::HTTPS, host, auth)
                    }
                    #[cfg(feature = "socks")]
                    ProxyScheme::Socks4 { addr } => PoolKeyExt::Socks4(addr, None),
                    #[cfg(feature = "socks")]
                    ProxyScheme::Socks5 { addr, auth, .. } => PoolKeyExt::Socks5(addr, auth),
                };
                return Some(ext);
            }
        }

        self.pool_key_ext.clone()
    }

    #[cfg(feature = "socks")]
    async fn connect_socks(&self, mut dst: Uri, proxy: ProxyScheme) -> Result<Conn, BoxError> {
        let dns = match proxy {
            ProxyScheme::Socks4 { .. } => socks::DnsResolve::Local,
            ProxyScheme::Socks5 {
                remote_dns: false, ..
            } => socks::DnsResolve::Local,
            ProxyScheme::Socks5 {
                remote_dns: true, ..
            } => socks::DnsResolve::Proxy,
            ProxyScheme::Http { .. } | ProxyScheme::Https { .. } => {
                unreachable!("connect_socks is only called for socks proxies");
            }
        };

        let ws = maybe_websocket_uri(&mut dst)?;

        match &self.inner {
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, tls, .. } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    let host = dst.host().ok_or(error::uri_bad_host())?;
                    let conn = socks::connect(proxy, dst.clone(), dns).await?;
                    let connector = tls.create_connector(http.clone(), ws).await;
                    let setup_ssl = connector.setup_ssl(&dst, host)?;
                    let io = tokio_boring::SslStreamBuilder::new(setup_ssl, conn)
                        .connect()
                        .await?;
                    return Ok(Conn {
                        inner: self.verbose.wrap(BoringTlsConn { inner: io }),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    });
                }
            }
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(_) => (),
        }

        socks::connect(proxy, dst, dns).await.map(|tcp| Conn {
            inner: self.verbose.wrap(tcp),
            is_proxy: false,
            tls_info: false,
        })
    }

    async fn connect_with_maybe_proxy(
        self,
        mut dst: Uri,
        is_proxy: bool,
    ) -> Result<Conn, BoxError> {
        let _ws = maybe_websocket_uri(&mut dst)?;
        match self.inner {
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(mut http) => {
                let io = http.call(dst).await?;
                Ok(Conn {
                    inner: self.verbose.wrap(io),
                    is_proxy,
                    tls_info: false,
                })
            }
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, tls } => {
                let mut http = http.clone();

                // Disable Nagle's algorithm for TLS handshake
                //
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
                    http.set_nodelay(true);
                }

                let mut http = tls.create_connector(http, _ws).await;
                let io = http.call(dst).await?;

                if let MaybeHttpsStream::Https(stream) = io {
                    if !self.nodelay {
                        let stream_ref = stream.get_ref();
                        stream_ref.set_nodelay(false)?;
                    }
                    Ok(Conn {
                        inner: self.verbose.wrap(BoringTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                }
            }
        }
    }

    async fn connect_via_proxy(
        self,
        mut dst: Uri,
        proxy_scheme: ProxyScheme,
    ) -> Result<Conn, BoxError> {
        log::debug!("proxy({:?}) intercepts '{:?}'", proxy_scheme, dst);

        let (proxy_dst, _auth) = match proxy_scheme {
            ProxyScheme::Http { host, auth } => (into_uri(Scheme::HTTP, host)?, auth),
            ProxyScheme::Https { host, auth } => (into_uri(Scheme::HTTPS, host)?, auth),
            #[cfg(feature = "socks")]
            ProxyScheme::Socks4 { .. } => return self.connect_socks(dst, proxy_scheme).await,
            #[cfg(feature = "socks")]
            ProxyScheme::Socks5 { .. } => return self.connect_socks(dst, proxy_scheme).await,
        };

        #[cfg(feature = "boring-tls")]
        let auth = _auth;

        let _ws = maybe_websocket_uri(&mut dst)?;

        match &self.inner {
            #[cfg(feature = "boring-tls")]
            Inner::BoringTls { http, tls } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    let host = dst.host().ok_or(crate::error::uri_bad_host())?;
                    let port = dst.port().map(|p| p.as_u16()).unwrap_or(443);

                    let mut http = tls.create_connector(http.clone(), _ws).await;
                    let conn = http.call(proxy_dst).await?;
                    log::trace!("tunneling HTTPS over proxy");
                    let tunneled = tunnel(conn, host, port, auth).await?;

                    let ssl = http.setup_ssl(&dst, host)?;
                    let io = tokio_boring::SslStreamBuilder::new(ssl, tunneled)
                        .connect()
                        .await?;

                    return Ok(Conn {
                        inner: self.verbose.wrap(BoringTlsConn { inner: io }),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    });
                }
            }
            #[cfg(not(feature = "boring-tls"))]
            Inner::Http(_) => (),
        }

        self.connect_with_maybe_proxy(proxy_dst, true).await
    }
}

/// Checks if the given URI is a WebSocket (ws or wss) URI and, if so,
/// converts it into an HTTP or HTTPS URI.
///
/// This function modifies the provided URI (`dst`) if it detects a WebSocket scheme.
/// If the scheme is "ws", it changes the URI scheme to HTTP.
/// If the scheme is "wss", it changes the URI scheme to HTTPS.
///
/// Returns `true` if the URI was modified, meaning it originally had a "ws" or "wss" scheme.
/// Returns `false` if the URI is not a WebSocket URI.
///
/// # Parameters:
/// - `dst`: A mutable reference to a `Uri` that may be modified if it is a WebSocket URI.
///
/// # Returns:
/// - `true`: if the URI was a WebSocket URI and was modified.
/// - `false`: if the URI was not a WebSocket URI.
///
/// # Conditional compilation:
/// This function only works if the "websocket" feature is enabled.
#[inline]
fn maybe_websocket_uri(dst: &mut Uri) -> Result<bool, BoxError> {
    let ok = match (dst.scheme_str(), dst.authority()) {
        #[cfg(feature = "websocket")]
        (Some("ws"), Some(host)) => {
            *dst = into_uri(Scheme::HTTP, host.clone())?;
            true
        }
        #[cfg(feature = "websocket")]
        (Some("wss"), Some(host)) => {
            *dst = into_uri(Scheme::HTTPS, host.clone())?;
            true
        }
        _ => false,
    };

    Ok(ok)
}

fn into_uri(scheme: Scheme, host: Authority) -> Result<Uri, BoxError> {
    // TODO: Should the `http` crate get `From<(Scheme, Authority)> for Uri`?
    Uri::builder()
        .scheme(scheme)
        .authority(host)
        .path_and_query(http::uri::PathAndQuery::from_static("/"))
        .build()
        .map_err(From::from)
}

async fn with_timeout<T, F>(f: F, timeout: Option<Duration>) -> Result<T, BoxError>
where
    F: Future<Output = Result<T, BoxError>>,
{
    if let Some(to) = timeout {
        match tokio::time::timeout(to, f).await {
            Err(_elapsed) => Err(Box::new(crate::error::TimedOut) as BoxError),
            Ok(Ok(try_res)) => Ok(try_res),
            Ok(Err(e)) => Err(e),
        }
    } else {
        f.await
    }
}

impl Service<Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        log::debug!("starting new connection: {:?}", dst);
        let timeout = self.timeout;
        for prox in self.proxies.iter() {
            if let Some(proxy_scheme) = prox.intercept(&dst) {
                return Box::pin(with_timeout(
                    self.clone().connect_via_proxy(dst, proxy_scheme),
                    timeout,
                ));
            }
        }

        Box::pin(with_timeout(
            self.clone().connect_with_maybe_proxy(dst, false),
            timeout,
        ))
    }
}

#[cfg(feature = "boring-tls")]
trait TlsInfoFactory {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo>;
}

#[cfg(feature = "boring-tls")]
impl TlsInfoFactory for BoringTlsConn<tokio::net::TcpStream> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .inner
            .ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "boring-tls")]
impl TlsInfoFactory for MaybeHttpsStream<tokio::net::TcpStream> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => {
                let peer_certificate = tls.ssl().peer_certificate().and_then(|c| c.to_der().ok());
                Some(crate::tls::TlsInfo { peer_certificate })
            }
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "boring-tls")]
impl TlsInfoFactory for BoringTlsConn<MaybeHttpsStream<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self.inner.get_ref() {
            MaybeHttpsStream::Https(ref tls) => {
                let peer_certificate = tls.ssl().peer_certificate().and_then(|c| c.to_der().ok());
                Some(crate::tls::TlsInfo { peer_certificate })
            }
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "boring-tls")]
impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

pub(crate) trait AsyncConn:
    AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}

#[cfg(feature = "boring-tls")]
trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}
#[cfg(not(feature = "boring-tls"))]
trait AsyncConnWithInfo: AsyncConn {}

#[cfg(feature = "boring-tls")]
impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}
#[cfg(not(feature = "boring-tls"))]
impl<T: AsyncConn> AsyncConnWithInfo for T {}

type BoxConn = Box<dyn AsyncConnWithInfo>;

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells hyper whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub(crate) struct Conn {
        #[pin]
        inner: BoxConn,
        is_proxy: bool,
        // Only needed for __boring, but #[cfg()] on fields breaks pin_project!
        tls_info: bool,
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let connected = self.inner.connected().proxy(self.is_proxy);
        #[cfg(feature = "boring-tls")]
        if self.tls_info {
            if let Some(tls_info) = self.inner.tls_info() {
                connected.extra(tls_info)
            } else {
                connected
            }
        } else {
            connected
        }
        #[cfg(not(feature = "boring-tls"))]
        connected
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        AsyncRead::poll_read(this.inner, cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_shutdown(this.inner, cx)
    }
}

pub(crate) type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

#[cfg(feature = "boring-tls")]
async fn tunnel<T>(
    mut conn: T,
    host: &str,
    port: u16,
    auth: Option<HeaderValue>,
) -> Result<T, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = format!(
        "\
         CONNECT {0}:{1} HTTP/1.1\r\n\
         Host: {0}:{1}\r\n\
         ",
        host, port
    )
    .into_bytes();

    // user-agent
    buf.extend_from_slice(b"User-Agent: ");
    buf.extend_from_slice(env!("CARGO_PKG_NAME").as_bytes());
    buf.extend_from_slice(b"/");
    buf.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
    buf.extend_from_slice(b"\r\n");

    // proxy-authorization
    if let Some(value) = auth {
        log::debug!("tunnel to {}:{} using basic auth", host, port);
        buf.extend_from_slice(b"Proxy-Authorization: ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    conn.write_all(&buf).await?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = conn.read(&mut buf[pos..]).await?;

        if n == 0 {
            return Err(tunnel_eof());
        }
        pos += n;

        let recvd = &buf[..pos];
        if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
            if recvd.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err("proxy headers too long for tunnel".into());
            }
            // else read more
        } else if recvd.starts_with(b"HTTP/1.1 407") {
            return Err("proxy authentication required".into());
        } else {
            return Err("unsuccessful tunnel".into());
        }
    }
}

#[cfg(feature = "boring-tls")]
fn tunnel_eof() -> BoxError {
    "unexpected eof while tunneling".into()
}

#[cfg(feature = "boring-tls")]
mod boring_tls_conn {
    use hyper::client::connect::{Connected, Connection};
    use pin_project_lite::pin_project;
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_boring::SslStream;

    pin_project! {
        pub(super) struct BoringTlsConn<T> {
            #[pin] pub(super) inner: SslStream<T>,
        }
    }

    impl<T: Connection + AsyncRead + AsyncWrite + Unpin> Connection for BoringTlsConn<T> {
        fn connected(&self) -> Connected {
            if self.inner.ssl().selected_alpn_protocol() == Some(b"h2") {
                self.inner.get_ref().connected().negotiated_h2()
            } else {
                self.inner.get_ref().connected()
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for BoringTlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            AsyncRead::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for BoringTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            AsyncWrite::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_shutdown(this.inner, cx)
        }
    }
}

#[cfg(feature = "socks")]
mod socks {
    use std::io;
    use std::net::ToSocketAddrs;

    use http::Uri;
    use tokio::net::TcpStream;
    use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

    use super::{BoxError, Scheme};
    use crate::proxy::ProxyScheme;

    pub(super) enum DnsResolve {
        Local,
        Proxy,
    }

    pub(super) async fn connect(
        proxy: ProxyScheme,
        dst: Uri,
        dns: DnsResolve,
    ) -> Result<TcpStream, BoxError> {
        let https = dst.scheme() == Some(&Scheme::HTTPS);
        let original_host = dst
            .host()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no host in url"))?;
        let mut host = original_host.to_owned();
        let port = match dst.port() {
            Some(p) => p.as_u16(),
            None if https => 443u16,
            _ => 80u16,
        };

        if let DnsResolve::Local = dns {
            let maybe_new_target = (host.as_str(), port).to_socket_addrs()?.next();
            if let Some(new_target) = maybe_new_target {
                host = new_target.ip().to_string();
            }
        }

        match proxy {
            ProxyScheme::Socks4 { addr } => {
                let stream = Socks4Stream::connect(addr, (host.as_str(), port))
                    .await
                    .map_err(|e| format!("socks connect error: {e}"))?;
                Ok(stream.into_inner())
            }
            ProxyScheme::Socks5 { addr, ref auth, .. } => {
                let stream = if let Some((username, password)) = auth {
                    Socks5Stream::connect_with_password(
                        addr,
                        (host.as_str(), port),
                        &username,
                        &password,
                    )
                    .await
                    .map_err(|e| format!("socks connect error: {e}"))?
                } else {
                    Socks5Stream::connect(addr, (host.as_str(), port))
                        .await
                        .map_err(|e| format!("socks connect error: {e}"))?
                };

                Ok(stream.into_inner())
            }
            _ => unreachable!(),
        }
    }
}

mod verbose {
    use hyper::client::connect::{Connected, Connection};
    use std::cmp::min;
    use std::fmt;
    use std::io::{self, IoSlice};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub(super) const OFF: Wrapper = Wrapper(false);

    #[derive(Clone, Copy)]
    pub(super) struct Wrapper(pub(super) bool);

    impl Wrapper {
        pub(super) fn wrap<T: super::AsyncConnWithInfo>(&self, conn: T) -> super::BoxConn {
            if self.0 && log::log_enabled!(log::Level::Trace) {
                Box::new(Verbose {
                    // truncate is fine
                    id: crate::util::fast_random() as u32,
                    inner: conn,
                })
            } else {
                Box::new(conn)
            }
        }
    }

    struct Verbose<T> {
        id: u32,
        inner: T,
    }

    impl<T: Connection + AsyncRead + AsyncWrite + Unpin> Connection for Verbose<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Verbose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    log::trace!("{:08x} read: {:?}", self.id, Escape(buf.filled()));
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Verbose<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    log::trace!("{:08x} write: {:?}", self.id, Escape(&buf[..n]));
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
                Poll::Ready(Ok(nwritten)) => {
                    log::trace!(
                        "{:08x} write (vectored): {:?}",
                        self.id,
                        Vectored { bufs, nwritten }
                    );
                    Poll::Ready(Ok(nwritten))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "boring-tls")]
    impl<T: super::TlsInfoFactory> super::TlsInfoFactory for Verbose<T> {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }

    struct Escape<'a>(&'a [u8]);

    impl fmt::Debug for Escape<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "b\"")?;
            for &c in self.0 {
                // https://doc.rust-lang.org/reference.html#byte-escapes
                if c == b'\n' {
                    write!(f, "\\n")?;
                } else if c == b'\r' {
                    write!(f, "\\r")?;
                } else if c == b'\t' {
                    write!(f, "\\t")?;
                } else if c == b'\\' || c == b'"' {
                    write!(f, "\\{}", c as char)?;
                } else if c == b'\0' {
                    write!(f, "\\0")?;
                    // ASCII printable
                } else if (0x20..0x7f).contains(&c) {
                    write!(f, "{}", c as char)?;
                } else {
                    write!(f, "\\x{:02x}", c)?;
                }
            }
            write!(f, "\"")?;
            Ok(())
        }
    }

    struct Vectored<'a, 'b> {
        bufs: &'a [IoSlice<'b>],
        nwritten: usize,
    }

    impl fmt::Debug for Vectored<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut left = self.nwritten;
            for buf in self.bufs.iter() {
                if left == 0 {
                    break;
                }
                let n = min(left, buf.len());
                Escape(&buf[..n]).fmt(f)?;
                left -= n;
            }
            Ok(())
        }
    }
}
