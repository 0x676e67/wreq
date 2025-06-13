use std::{
    future::Future,
    io::{self, IoSlice},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::uri::Scheme;
use pin_project_lite::pin_project;
use sealed::{Conn, Unnameable};
use tokio_boring2::SslStream;
use tower::{
    ServiceBuilder,
    timeout::TimeoutLayer,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapRequestLayer},
};
use tower_service::Service;

use self::tls_conn::BoringTlsConn;
use crate::{
    core::{
        client::{
            Dst,
            connect::{Connected, Connection, proxy::Tunnel},
        },
        rt::{Read, ReadBufCursor, TokioIo, Write},
    },
    dns::DynResolver,
    error::{BoxError, cast_timeout_to_error},
    proxy::{Intercepted, Matcher as ProxyMatcher},
    tls::{HttpsConnector, MaybeHttpsStream, TlsConnector},
};

pub(crate) type HttpConnector = crate::core::client::connect::HttpConnector<DynResolver>;

pub(crate) type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

pub(crate) type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

pub(crate) struct ConnectorBuilder(ConnectorService);

impl ConnectorBuilder {
    pub(crate) fn build(self, layers: Option<Vec<BoxedConnectorLayer>>) -> Connector {
        if let Some(layers) = layers {
            let timeout = self.0.timeout;

            // otherwise we have user provided layers
            // so we need type erasure all the way through
            // as well as mapping the unnameable type of the layers back to Dst for the inner
            // service
            let service = layers.into_iter().fold(
                BoxCloneSyncService::new(
                    ServiceBuilder::new()
                        .layer(MapRequestLayer::new(|request: Unnameable| request.0))
                        .service(self.0),
                ),
                |service, layer| ServiceBuilder::new().layer(layer).service(service),
            );

            // now we handle the concrete stuff - any `connect_timeout`,
            // plus a final map_err layer we can use to cast default tower layer
            // errors to internal errors
            match timeout {
                Some(timeout) => {
                    let service = ServiceBuilder::new()
                        .layer(TimeoutLayer::new(timeout))
                        .service(service);
                    let service = ServiceBuilder::new()
                        .map_err(cast_timeout_to_error)
                        .service(service);
                    let service = BoxCloneSyncService::new(service);
                    Connector::WithLayers(service)
                }
                None => {
                    // no timeout, but still map err
                    // no named timeout layer but we still map errors since
                    // we might have user-provided timeout layer
                    let service = ServiceBuilder::new()
                        .map_err(cast_timeout_to_error)
                        .service(service);
                    let service = BoxCloneSyncService::new(service);
                    Connector::WithLayers(service)
                }
            }
        } else {
            // we have no user-provided layers, only use concrete types
            Connector::Simple(self.0)
        }
    }

    #[inline(always)]
    pub(crate) fn keepalive(mut self, dur: Option<Duration>) -> ConnectorBuilder {
        self.0.http.set_keepalive(dur);
        self
    }

    #[inline(always)]
    pub(crate) fn tcp_keepalive_interval(mut self, dur: Option<Duration>) -> ConnectorBuilder {
        self.0.http.set_keepalive_interval(dur);
        self
    }

    #[inline(always)]
    pub(crate) fn tcp_keepalive_retries(mut self, retries: Option<u32>) -> ConnectorBuilder {
        self.0.http.set_keepalive_retries(retries);
        self
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline(always)]
    pub(crate) fn tcp_user_timeout(mut self, dur: Option<Duration>) -> ConnectorBuilder {
        self.0.http.set_tcp_user_timeout(dur);
        self
    }

    #[inline(always)]
    pub(crate) fn timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
        self.0.timeout = timeout;
        self.0.http.set_connect_timeout(timeout);
        self
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[inline(always)]
    pub(crate) fn interface(
        mut self,
        iface: Option<std::borrow::Cow<'static, str>>,
    ) -> ConnectorBuilder {
        self.0.http.set_interface(iface);
        self
    }

    #[inline(always)]
    pub(crate) fn local_addresses(
        mut self,
        local_ipv4_address: Option<Ipv4Addr>,
        local_ipv6_address: Option<Ipv6Addr>,
    ) -> ConnectorBuilder {
        match (local_ipv4_address, local_ipv6_address) {
            (Some(ipv4), None) => self.0.http.set_local_address(Some(IpAddr::from(ipv4))),
            (None, Some(ipv6)) => self.0.http.set_local_address(Some(IpAddr::from(ipv6))),
            (Some(ipv4), Some(ipv6)) => {
                self.0.http.set_local_addresses(ipv4, ipv6);
            }
            (None, None) => {}
        }

        self
    }

    #[inline(always)]
    pub(crate) fn verbose(mut self, enabled: bool) -> ConnectorBuilder {
        self.0.verbose.0 = enabled;
        self
    }
}

#[derive(Clone)]
pub(crate) enum Connector {
    // base service, with or without an embedded timeout
    Simple(ConnectorService),
    // at least one custom layer along with maybe an outer timeout layer
    // from `builder.connect_timeout()`
    WithLayers(BoxedConnectorService),
}

impl Connector {
    pub(crate) fn builder(
        mut http: HttpConnector,
        tls: TlsConnector,
        proxies: Arc<Vec<ProxyMatcher>>,
        nodelay: bool,
        tls_info: bool,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> ConnectorBuilder {
        http.enforce_http(false);
        ConnectorBuilder(ConnectorService {
            http,
            tls,
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info,
            #[cfg(feature = "socks")]
            resolver,
        })
    }
}

impl Service<Dst> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Connector::Simple(service) => service.poll_ready(cx),
            Connector::WithLayers(service) => service.poll_ready(cx),
        }
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(dst),
            Connector::WithLayers(service) => service.call(Unnameable(dst)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectorService {
    http: HttpConnector,
    tls: TlsConnector,
    proxies: Arc<Vec<ProxyMatcher>>,
    verbose: verbose::Wrapper,
    /// When there is a single timeout layer and no other layers,
    /// we embed it directly inside our base Service::call().
    /// This lets us avoid an extra `Box::pin` indirection layer
    /// since `tokio::time::Timeout` is `Unpin`
    timeout: Option<Duration>,
    nodelay: bool,
    tls_info: bool,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

impl ConnectorService {
    #[cfg(feature = "socks")]
    async fn connect_socks(&self, mut dst: Dst, proxy: Intercepted) -> Result<Conn, BoxError> {
        use crate::core::client::connect::proxy::Socks;

        let uri = dst.uri().clone();

        let mut socks = Socks::new_with_resolver(
            self.http.clone(),
            self.resolver.clone(),
            proxy.uri().clone(),
            proxy.raw_auth(),
        );

        if uri.scheme() == Some(&Scheme::HTTPS) {
            let http = HttpsConnector::new(self.http.clone(), self.tls.clone(), &mut dst);

            trace!("socks HTTPS over proxy");
            let conn = socks.call(uri.clone()).await?;

            let host = uri.host().ok_or(crate::error::uri_bad_host())?;
            let io = http.connect(&uri, host, conn).await?;

            return Ok(Conn {
                inner: self.verbose.wrap(BoringTlsConn {
                    inner: TokioIo::new(io),
                }),
                is_proxy: false,
                tls_info: self.tls_info,
            });
        }

        socks
            .call(uri)
            .await
            .map(|tcp| Conn {
                inner: self.verbose.wrap(tcp),
                is_proxy: false,
                tls_info: false,
            })
            .map_err(Into::into)
    }

    async fn connect_with_maybe_proxy(
        self,
        mut dst: Dst,
        is_proxy: bool,
    ) -> Result<Conn, BoxError> {
        let uri = dst.uri().clone();
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if !self.nodelay && (uri.scheme() == Some(&Scheme::HTTPS)) {
            http.set_nodelay(true);
        }

        trace!("connect with maybe proxy");
        let mut http = HttpsConnector::new(http, self.tls, &mut dst);
        let io = http.call(uri).await?;

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

    async fn connect_via_proxy(self, mut dst: Dst, proxy: Intercepted) -> Result<Conn, BoxError> {
        let uri = dst.uri().clone();
        debug!("proxy({:?}) intercepts '{:?}'", proxy, dst);

        #[cfg(feature = "socks")]
        if let Some("socks4" | "socks4a" | "socks5" | "socks5h") = proxy.uri().scheme_str() {
            return self.connect_socks(dst, proxy).await;
        }

        let proxy_dst = proxy.uri().clone();
        let auth = proxy.basic_auth().cloned();

        if uri.scheme() == Some(&Scheme::HTTPS) {
            trace!("tunneling HTTPS over proxy");
            let http = HttpsConnector::new(self.http.clone(), self.tls, &mut dst);

            let mut tunnel = Tunnel::new(proxy_dst, http.clone());
            if let Some(auth) = auth {
                tunnel = tunnel.with_auth(auth);
            }

            if let Some(headers) = proxy.custom_headers() {
                tunnel = tunnel.with_headers(headers.clone());
            }

            let host = uri.host().ok_or(crate::error::uri_bad_host())?;

            // We don't wrap this again in an HttpsConnector since that uses Maybe,
            // and we know this is definitely HTTPS.
            let tunneled = tunnel.call(uri.clone()).await?;
            let io = http.connect(&uri, host, tunneled).await?;

            return Ok(Conn {
                inner: self.verbose.wrap(BoringTlsConn {
                    inner: TokioIo::new(io),
                }),
                is_proxy: false,
                tls_info: self.tls_info,
            });
        }

        dst.set_uri(proxy_dst);

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
        debug!("starting new connection: {:?}", dst.uri());

        if let Some(proxy_scheme) = dst.take_proxy_intercepted() {
            return Box::pin(with_timeout(
                self.clone().connect_via_proxy(dst, proxy_scheme),
                self.timeout,
            ));
        } else {
            for prox in self.proxies.iter() {
                if let Some(intercepted) = prox.intercept(dst.uri()) {
                    return Box::pin(with_timeout(
                        self.clone().connect_via_proxy(dst, intercepted),
                        self.timeout,
                    ));
                }
            }
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

impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.inner().tls_info()
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
        self.get_ref().inner().tls_info()
    }
}

impl TlsInfoFactory for MaybeHttpsStream<TokioIo<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.inner().tls_info(),
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
        pub struct Conn {
            #[pin]
            pub(super) inner: BoxConn,
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
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };

    use pin_project_lite::pin_project;
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpStream,
    };
    use tokio_boring2::SslStream;

    use super::TlsInfoFactory;
    use crate::{
        core::{
            client::connect::{Connected, Connection},
            rt::{Read, ReadBufCursor, TokioIo, Write},
        },
        tls::MaybeHttpsStream,
    };

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

mod verbose {
    use super::{AsyncConnWithInfo, BoxConn};

    pub(super) const OFF: Wrapper = Wrapper(false);

    #[derive(Clone, Copy)]
    pub(super) struct Wrapper(pub(super) bool);

    impl Wrapper {
        #[cfg_attr(not(feature = "tracing"), inline(always))]
        pub(super) fn wrap<T: AsyncConnWithInfo>(&self, conn: T) -> BoxConn {
            #[cfg(feature = "tracing")]
            {
                if self.0 {
                    return Box::new(sealed::Verbose {
                        // truncate is fine
                        id: crate::util::fast_random() as u32,
                        inner: conn,
                    });
                }
            }

            Box::new(conn)
        }
    }

    #[cfg(feature = "tracing")]
    mod sealed {
        use std::{
            fmt,
            io::{self, IoSlice},
            pin::Pin,
            task::{Context, Poll},
        };

        use super::super::TlsInfoFactory;
        use crate::{
            core::{
                client::connect::{Connected, Connection},
                rt::{Read, ReadBufCursor, Write},
            },
            tls::TlsInfo,
        };

        pub(super) struct Verbose<T> {
            pub(super) id: u32,
            pub(super) inner: T,
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
                let mut vbuf = crate::core::rt::ReadBuf::uninit(unsafe { buf.as_mut() });
                match Pin::new(&mut self.inner).poll_read(cx, vbuf.unfilled()) {
                    Poll::Ready(Ok(())) => {
                        trace!("{:08x} read: {:?}", self.id, Escape(vbuf.filled()));
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
                        trace!("{:08x} write: {:?}", self.id, Escape(&buf[..n]));
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
                        trace!(
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

        impl<T: TlsInfoFactory> TlsInfoFactory for Verbose<T> {
            fn tls_info(&self) -> Option<TlsInfo> {
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
                    let n = std::cmp::min(left, buf.len());
                    Escape(&buf[..n]).fmt(f)?;
                    left -= n;
                }
                Ok(())
            }
        }
    }
}
