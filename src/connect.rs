use self::tls_conn::BoringTlsConn;
use crate::tls::{BoringTlsConnector, HttpsConnector, MaybeHttpsStream};
use crate::util::client::connect::{Connected, Connection};
use crate::util::client::Dst;
use crate::util::rt::TokioIo;
use crate::util::{self, into_uri};
use antidote::RwLock;
use http::uri::Scheme;
use hyper2::rt::{Read, ReadBufCursor, Write};
use pin_project_lite::pin_project;
use sealed::{Conn, Unnameable};
use tokio_boring::SslStream;
use tower::util::{BoxCloneSyncServiceLayer, MapRequestLayer};
use tower::{timeout::TimeoutLayer, util::BoxCloneSyncService, ServiceBuilder};
use tower_service::Service;

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::dns::DynResolver;
use crate::error::{cast_to_internal_error, BoxError};
use crate::proxy::ProxyScheme;

pub(crate) type HttpConnector = util::client::connect::HttpConnector<DynResolver>;

pub(crate) type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

pub(crate) type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

pub(crate) struct ConnectorBuilder {
    http: HttpConnector,
    tls: BoringTlsConnector,
    verbose: verbose::Wrapper,
    timeout: Option<Duration>,
    nodelay: bool,
    tls_info: bool,
}

impl ConnectorBuilder {
    pub(crate) fn build(self, layers: Vec<BoxedConnectorLayer>) -> Connector {
        if layers.is_empty() {
            // we have no user-provided layers, only use concrete types
            let base_service = ConnectorService {
                http: self.http,
                tls: InnerTLS::Simple(self.tls),
                verbose: self.verbose,
                nodelay: self.nodelay,
                tls_info: self.tls_info,
                timeout: self.timeout,
            };
            return Connector::Simple(base_service);
        }

        let inner_tls = InnerTLS::WithSharedState(Arc::new(RwLock::new(self.tls)));
        let mut base_service = ConnectorService {
            http: self.http,
            tls: inner_tls.clone(),
            verbose: self.verbose,
            nodelay: self.nodelay,
            tls_info: self.tls_info,
            timeout: self.timeout,
        };

        // If layers is empty, we have no timeout
        let timeout = base_service.timeout.take();

        // otherwise we have user provided layers
        // so we need type erasure all the way through
        // as well as mapping the unnameable type of the layers back to Dst for the inner service
        let unnameable_service = ServiceBuilder::new()
            .layer(MapRequestLayer::new(|request: Unnameable| request.0))
            .service(base_service);
        let mut service = BoxCloneSyncService::new(unnameable_service);
        for layer in layers {
            service = ServiceBuilder::new().layer(layer).service(service);
        }

        // now we handle the concrete stuff - any `connect_timeout`,
        // plus a final map_err layer we can use to cast default tower layer
        // errors to internal errors
        match timeout {
            Some(timeout) => {
                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(timeout))
                    .service(service);
                let service = ServiceBuilder::new()
                    .map_err(cast_to_internal_error)
                    .service(service);
                let service = BoxCloneSyncService::new(service);
                Connector::WithLayers { inner_tls, service }
            }
            None => {
                // no timeout, but still map err
                // no named timeout layer but we still map errors since
                // we might have user-provided timeout layer
                let service = ServiceBuilder::new().service(service);
                let service = ServiceBuilder::new()
                    .map_err(cast_to_internal_error)
                    .service(service);
                let service = BoxCloneSyncService::new(service);
                Connector::WithLayers { inner_tls, service }
            }
        }
    }

    pub(crate) fn new(
        mut http: HttpConnector,
        tls: BoringTlsConnector,
        nodelay: bool,
        tls_info: bool,
    ) -> ConnectorBuilder {
        http.enforce_http(false);
        ConnectorBuilder {
            http,
            tls,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info,
        }
    }

    #[inline]
    pub(crate) fn set_keepalive(&mut self, dur: Option<Duration>) {
        self.http.set_keepalive(dur);
    }

    #[inline]
    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    #[inline]
    pub(crate) fn set_verbose(&mut self, enabled: bool) {
        self.verbose.0 = enabled;
    }
}

#[derive(Clone)]
pub(crate) enum Connector {
    // base service, with or without an embedded timeout
    Simple(ConnectorService),
    // at least one custom layer along with maybe an outer timeout layer
    // from `builder.connect_timeout()`
    WithLayers {
        inner_tls: InnerTLS,
        service: BoxedConnectorService,
    },
}

impl Connector {
    #[inline]
    pub(crate) fn set_connector(&mut self, connector: BoringTlsConnector) {
        match self {
            Connector::Simple(service) => {
                service.tls = InnerTLS::Simple(connector);
            }
            Connector::WithLayers { inner_tls, .. } => {
                if let InnerTLS::WithSharedState(tls) = inner_tls {
                    *tls.write() = connector;
                }
            }
        }
    }
}

impl Service<Dst> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Connector::Simple(service) => service.poll_ready(cx),
            Connector::WithLayers { service, .. } => service.poll_ready(cx),
        }
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(dst),
            Connector::WithLayers { service, .. } => service.call(Unnameable(dst)),
        }
    }
}

#[derive(Clone)]
pub(crate) enum InnerTLS {
    Simple(BoringTlsConnector),
    WithSharedState(Arc<RwLock<BoringTlsConnector>>),
}

impl InnerTLS {
    fn get_tls(&self) -> BoringTlsConnector {
        match self {
            InnerTLS::Simple(tls) => tls.clone(),
            InnerTLS::WithSharedState(tls) => tls.read().clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectorService {
    http: HttpConnector,
    tls: InnerTLS,
    verbose: verbose::Wrapper,
    /// When there is a single timeout layer and no other layers,
    /// we embed it directly inside our base Service::call().
    /// This lets us avoid an extra `Box::pin` indirection layer
    /// since `tokio::time::Timeout` is `Unpin`
    timeout: Option<Duration>,
    nodelay: bool,
    tls_info: bool,
}

impl ConnectorService {
    #[cfg(feature = "socks")]
    async fn connect_socks(&self, mut dst: Dst, proxy: ProxyScheme) -> Result<Conn, BoxError> {
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

        if dst.scheme() == Some(&Scheme::HTTPS) {
            let http = HttpsConnector::builder(self.http.clone())
                .with_version_pref(dst.version_pref())
                .with_iface(dst.take_iface())
                .build(self.tls.get_tls());

            log::trace!("socks HTTPS over proxy");
            let host = dst.host().ok_or(crate::error::uri_bad_host())?;
            let conn = socks::connect(proxy, &dst, dns).await?;

            let io = http.connect(&dst, host, TokioIo::new(conn)).await?;

            return Ok(Conn {
                inner: self.verbose.wrap(BoringTlsConn {
                    inner: TokioIo::new(io),
                }),
                is_proxy: false,
                tls_info: self.tls_info,
            });
        }

        socks::connect(proxy, &dst, dns).await.map(|tcp| Conn {
            inner: self.verbose.wrap(TokioIo::new(tcp)),
            is_proxy: false,
            tls_info: false,
        })
    }

    async fn connect_with_maybe_proxy(
        self,
        mut dst: Dst,
        is_proxy: bool,
    ) -> Result<Conn, BoxError> {
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
            http.set_nodelay(true);
        }

        log::trace!("connect with maybe proxy");
        let mut http = HttpsConnector::builder(http)
            .with_version_pref(dst.version_pref())
            .with_iface(dst.take_iface())
            .build(self.tls.get_tls());
        let io = http.call(dst.into()).await?;

        if let MaybeHttpsStream::Https(stream) = io {
            if !self.nodelay {
                stream
                    .inner()
                    .get_ref()
                    .inner()
                    .inner()
                    .set_nodelay(false)?;
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

    async fn connect_via_proxy(
        self,
        mut dst: Dst,
        proxy_scheme: ProxyScheme,
    ) -> Result<Conn, BoxError> {
        log::debug!("proxy({:?}) intercepts '{:?}'", proxy_scheme, dst);

        let (proxy_dst, auth) = match proxy_scheme {
            ProxyScheme::Http { host, auth } => (into_uri(Scheme::HTTP, host)?, auth),
            ProxyScheme::Https { host, auth } => (into_uri(Scheme::HTTPS, host)?, auth),
            #[cfg(feature = "socks")]
            ProxyScheme::Socks4 { .. } | ProxyScheme::Socks5 { .. } => {
                return self.connect_socks(dst, proxy_scheme).await;
            }
        };

        if dst.scheme() == Some(&Scheme::HTTPS) {
            let mut http = HttpsConnector::builder(self.http.clone())
                .with_version_pref(dst.version_pref())
                .with_iface(dst.take_iface())
                .build(self.tls.get_tls());

            let host = dst.host().ok_or(crate::error::uri_bad_host())?;
            let port = dst.port_u16().unwrap_or(443);

            log::trace!("tunneling HTTPS over proxy");
            let conn = http.call(proxy_dst).await?;
            let tunneled = tunnel::connect(conn, host, port, auth).await?;

            let io = http.connect(&dst, host, tunneled).await?;

            return Ok(Conn {
                inner: self.verbose.wrap(BoringTlsConn {
                    inner: TokioIo::new(io),
                }),
                is_proxy: false,
                tls_info: self.tls_info,
            });
        }

        dst.set_dst(proxy_dst);

        self.connect_with_maybe_proxy(dst, true).await
    }
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

impl Service<Dst> for ConnectorService {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut dst: Dst) -> Self::Future {
        log::debug!("starting new connection: {:?}", dst);

        if let Some(proxy_scheme) = dst.take_proxy() {
            return Box::pin(with_timeout(
                self.clone().connect_via_proxy(dst, proxy_scheme),
                self.timeout,
            ));
        }

        Box::pin(with_timeout(
            self.clone().connect_with_maybe_proxy(dst, false),
            self.timeout,
        ))
    }
}

trait TlsInfoFactory {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo>;
}

impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.inner().tls_info()
    }
}

impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

impl TlsInfoFactory for SslStream<TokioIo<TokioIo<tokio::net::TcpStream>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok())
            .map(|c| crate::tls::TlsInfo {
                peer_certificate: Some(c),
            })
    }
}

impl TlsInfoFactory for SslStream<TokioIo<MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok())
            .map(|c| crate::tls::TlsInfo {
                peer_certificate: Some(c),
            })
    }
}

impl TlsInfoFactory for MaybeHttpsStream<TokioIo<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls
                .inner()
                .ssl()
                .peer_certificate()
                .and_then(|c| c.to_der().ok())
                .map(|c| crate::tls::TlsInfo {
                    peer_certificate: Some(c),
                }),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

pub(crate) trait AsyncConn:
    Read + Write + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: Read + Write + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}

trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}

impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}

type BoxConn = Box<dyn AsyncConnWithInfo>;

pub(crate) mod sealed {
    use super::*;

    #[derive(Debug)]
    pub struct Unnameable(pub(super) Dst);

    pin_project! {
        /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
        /// This tells hyper whether the URI should be written in
        /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
        /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
        #[allow(missing_debug_implementations)]
        pub struct Conn {
            #[pin]
            pub(super)inner: BoxConn,
            pub(super) is_proxy: bool,
            // Only needed for __tls, but #[cfg()] on fields breaks pin_project!
            pub(super) tls_info: bool,
        }
    }

    impl Connection for Conn {
        fn connected(&self) -> Connected {
            let connected = self.inner.connected().proxy(self.is_proxy);

            if self.tls_info {
                if let Some(tls_info) = self.inner.tls_info() {
                    connected.extra(tls_info)
                } else {
                    connected
                }
            } else {
                connected
            }
        }
    }

    impl Read for Conn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl Write for Conn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }
}

pub(crate) type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

mod tls_conn {
    use super::TlsInfoFactory;
    use crate::{
        tls::MaybeHttpsStream,
        util::{
            client::connect::{Connected, Connection},
            rt::TokioIo,
        },
    };
    use hyper2::rt::{Read, ReadBufCursor, Write};
    use pin_project_lite::pin_project;
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpStream,
    };
    use tokio_boring::SslStream;

    pin_project! {
        pub(super) struct BoringTlsConn<T> {
            #[pin] pub(super) inner: TokioIo<SslStream<T>>,
        }
    }

    impl Connection for BoringTlsConn<TokioIo<TokioIo<TcpStream>>> {
        fn connected(&self) -> Connected {
            let connected = self.inner.inner().get_ref().connected();
            if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                connected.negotiated_h2()
            } else {
                connected
            }
        }
    }

    impl Connection for BoringTlsConn<TokioIo<MaybeHttpsStream<TokioIo<TcpStream>>>> {
        fn connected(&self) -> Connected {
            let connected = self.inner.inner().get_ref().connected();
            if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                connected.negotiated_h2()
            } else {
                connected
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Read for BoringTlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Write for BoringTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }

    impl<T> TlsInfoFactory for BoringTlsConn<T>
    where
        TokioIo<SslStream<T>>: TlsInfoFactory,
    {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }
}

mod tunnel {
    use super::BoxError;
    use crate::util::rt::TokioIo;
    use http::HeaderValue;
    use hyper2::rt::{Read, Write};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(super) async fn connect<T>(
        mut conn: T,
        host: &str,
        port: u16,
        auth: Option<HeaderValue>,
    ) -> Result<T, BoxError>
    where
        T: Read + Write + Unpin,
    {
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

        let mut tokio_conn = TokioIo::new(&mut conn);

        tokio_conn.write_all(&buf).await?;

        let mut buf = [0; 8192];
        let mut pos = 0;

        loop {
            let n = tokio_conn.read(&mut buf[pos..]).await?;

            if n == 0 {
                return Err("unexpected eof while tunneling".into());
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
        dst: &Uri,
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
    use crate::util::client::connect::{Connected, Connection};
    use hyper2::rt::{Read, ReadBufCursor, Write};
    use std::cmp::min;
    use std::fmt;
    use std::io::{self, IoSlice};
    use std::pin::Pin;
    use std::task::{Context, Poll};

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

    impl<T: Connection + Read + Write + Unpin> Connection for Verbose<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }

    impl<T: Read + Write + Unpin> Read for Verbose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            mut buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            // TODO: This _does_ forget the `init` len, so it could result in
            // re-initializing twice. Needs upstream support, perhaps.
            // SAFETY: Passing to a ReadBuf will never de-initialize any bytes.
            let mut vbuf = hyper2::rt::ReadBuf::uninit(unsafe { buf.as_mut() });
            match Pin::new(&mut self.inner).poll_read(cx, vbuf.unfilled()) {
                Poll::Ready(Ok(())) => {
                    log::trace!("{:08x} read: {:?}", self.id, Escape(vbuf.filled()));
                    let len = vbuf.filled().len();
                    // SAFETY: The two cursors were for the same buffer. What was
                    // filled in one is safe in the other.
                    unsafe {
                        buf.advance(len);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: Read + Write + Unpin> Write for Verbose<T> {
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
