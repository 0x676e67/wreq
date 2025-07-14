use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::uri::Scheme;
use pin_project_lite::pin_project;
use tls_conn::TlsConn;
use tokio::net::TcpStream;
use tokio_boring2::SslStream;
use tower::{
    Service, ServiceBuilder,
    timeout::TimeoutLayer,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapRequestLayer},
};

pub(crate) use self::conn::{Conn, Unnameable};
use crate::{
    core::{
        client::{
            ConnRequest,
            connect::{self, Connected, Connection, proxy},
        },
        rt::{Read, ReadBufCursor, TokioIo, Write},
    },
    dns::DynResolver,
    error::{BoxError, TimedOut, map_timeout_to_connector_error},
    proxy::{Intercepted, Matcher as ProxyMatcher},
    tls::{
        EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector, TlsConnectorBuilder,
        TlsInfo, TlsOptions,
    },
};

type BoxConn = Box<dyn AsyncConnWithInfo>;

type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

pub(crate) type HttpConnector = connect::HttpConnector<DynResolver>;

pub(crate) type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

pub(crate) type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

pub(crate) struct ConnectorBuilder {
    http: HttpConnector,
    proxies: Arc<Vec<ProxyMatcher>>,
    verbose: verbose::Wrapper,
    /// When there is a single timeout layer and no other layers,
    /// we embed it directly inside our base Service::call().
    /// This lets us avoid an extra `Box::pin` indirection layer
    /// since `tokio::time::Timeout` is `Unpin`
    timeout: Option<Duration>,
    tcp_nodelay: bool,
    #[cfg(feature = "socks")]
    resolver: DynResolver,

    tls_info: bool,
    tls_builder: TlsConnectorBuilder,
}

impl ConnectorBuilder {
    /// Set the HTTP connector to use.
    #[inline]
    pub(crate) fn with_http<F>(mut self, call: F) -> ConnectorBuilder
    where
        F: FnOnce(&mut HttpConnector),
    {
        call(&mut self.http);
        self
    }

    /// Set the TLS connector builder to use.
    #[inline]
    pub(crate) fn with_tls<F>(mut self, call: F) -> ConnectorBuilder
    where
        F: FnOnce(TlsConnectorBuilder) -> TlsConnectorBuilder,
    {
        self.tls_builder = call(self.tls_builder);
        self
    }

    /// Set the connect timeout.
    ///
    /// If a domain resolves to multiple IP addresses, the timeout will be
    /// evenly divided across them.
    #[inline]
    pub(crate) fn connect_timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
        self.timeout = timeout;
        self
    }

    /// Set connecting verbose mode.
    #[inline(always)]
    pub(crate) fn verbose(mut self, enabled: bool) -> ConnectorBuilder {
        self.verbose.0 = enabled;
        self
    }

    /// Sets the TLS info flag.
    #[inline(always)]
    pub(crate) fn tls_info(mut self, enabled: bool) -> ConnectorBuilder {
        self.tls_info = enabled;
        self
    }

    /// Builds the connector with the provided  TLS options configuration and optional layers.
    pub(crate) fn build(
        self,
        opts: TlsOptions,
        layers: Option<Vec<BoxedConnectorLayer>>,
    ) -> crate::Result<Connector> {
        let mut service = ConnectorService {
            http: self.http,
            tls: self.tls_builder.build(opts)?,
            proxies: self.proxies,
            verbose: self.verbose,
            // The timeout is initially set to None and will be reassigned later
            // based on the presence or absence of user-provided layers.
            timeout: None,
            tcp_nodelay: self.tcp_nodelay,
            #[cfg(feature = "socks")]
            resolver: self.resolver,
            tls_info: self.tls_info,
            tls_builder: Arc::new(self.tls_builder),
        };

        if let Some(layers) = layers {
            // otherwise we have user provided layers
            // so we need type erasure all the way through
            // as well as mapping the unnameable type of the layers back to ConnectRequest for the
            // inner service
            let service = layers.into_iter().fold(
                BoxCloneSyncService::new(
                    ServiceBuilder::new()
                        .layer(MapRequestLayer::new(|request: Unnameable| request.0))
                        .service(service),
                ),
                |service, layer| ServiceBuilder::new().layer(layer).service(service),
            );

            // now we handle the concrete stuff - any `connect_timeout`,
            // plus a final map_err layer we can use to cast default tower layer
            // errors to internal errors
            match self.timeout {
                Some(timeout) => {
                    let service = ServiceBuilder::new()
                        .layer(TimeoutLayer::new(timeout))
                        .service(service);
                    let service = ServiceBuilder::new()
                        .map_err(map_timeout_to_connector_error)
                        .service(service);
                    let service = BoxCloneSyncService::new(service);
                    Ok(Connector::WithLayers(service))
                }
                None => {
                    // no timeout, but still map err
                    // no named timeout layer but we still map errors since
                    // we might have user-provided timeout layer
                    let service = ServiceBuilder::new()
                        .map_err(map_timeout_to_connector_error)
                        .service(service);
                    let service = BoxCloneSyncService::new(service);
                    Ok(Connector::WithLayers(service))
                }
            }
        } else {
            // we have no user-provided layers, only use concrete types
            service.timeout = self.timeout;
            Ok(Connector::Simple(service))
        }
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
        proxies: Arc<Vec<ProxyMatcher>>,
        resolver: DynResolver,
    ) -> ConnectorBuilder {
        ConnectorBuilder {
            #[cfg(feature = "socks")]
            resolver: resolver.clone(),
            http: {
                let mut http = HttpConnector::new_with_resolver(resolver);
                http.enforce_http(false);
                http
            },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            tcp_nodelay: false,
            tls_info: false,
            tls_builder: TlsConnector::builder(),
        }
    }
}

impl Service<ConnRequest> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Connector::Simple(service) => service.poll_ready(cx),
            Connector::WithLayers(service) => service.poll_ready(cx),
        }
    }

    #[inline(always)]
    fn call(&mut self, req: ConnRequest) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(req),
            Connector::WithLayers(service) => service.call(Unnameable(req)),
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
    tcp_nodelay: bool,
    #[cfg(feature = "socks")]
    resolver: DynResolver,

    //  TLS options configuration
    // Note: these are not used in the `TlsConnectorBuilder` but rather
    // in the `TlsConnector` that is built from it.
    tls_info: bool,
    tls_builder: Arc<TlsConnectorBuilder>,
}

impl ConnectorService {
    /// Constructs an HTTPS connector by wrapping an `HttpConnector`
    fn build_tls_connector(
        &self,
        mut http: HttpConnector,
        req: &ConnRequest,
    ) -> Result<HttpsConnector<HttpConnector>, BoxError> {
        let ex_data = req.ex_data();
        http.set_connect_options(ex_data.tcp_connect_options().cloned());
        let tls = match ex_data.tls_options() {
            Some(opts) => self.tls_builder.build(opts)?,
            None => self.tls.clone(),
        };
        Ok(HttpsConnector::with_connector(http, tls))
    }

    /// Establishes a direct connection to the target URI without using a proxy.
    /// May perform a plain TCP or a TLS handshake depending on the URI scheme.
    async fn connect_direct(self, req: ConnRequest, is_proxy: bool) -> Result<Conn, BoxError> {
        trace!("connect with maybe proxy: {:?}", is_proxy);

        let uri = req.uri().clone();
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if !self.tcp_nodelay && (uri.scheme() == Some(&Scheme::HTTPS)) {
            http.set_nodelay(true);
        }

        let mut connector = self.build_tls_connector(http, &req)?;
        let io = connector.call(req).await?;

        // If the connection is HTTPS, wrap the TLS stream in a TlsConn for unified handling.
        // For plain HTTP, use the stream directly without additional wrapping.
        let inner = if let MaybeHttpsStream::Https(stream) = io {
            if !self.tcp_nodelay {
                stream.get_ref().set_nodelay(false)?;
            }
            self.verbose.wrap(TlsConn {
                inner: TokioIo::new(stream),
            })
        } else {
            self.verbose.wrap(io)
        };

        Ok(Conn {
            inner,
            is_proxy,
            tls_info: self.tls_info,
        })
    }

    /// Establishes a connection through a specified proxy.
    /// Supports both SOCKS and HTTP tunneling proxies.
    async fn connect_with_proxy(
        self,
        mut req: ConnRequest,
        proxy: Intercepted,
    ) -> Result<Conn, BoxError> {
        let uri = req.uri().clone();
        let proxy_uri = proxy.uri().clone();

        #[cfg(feature = "socks")]
        {
            use proxy::{DnsResolve, Socks, SocksVersion};

            if let Some((version, dns_resolve)) = match proxy.uri().scheme_str() {
                Some("socks4") => Some((SocksVersion::V4, DnsResolve::Local)),
                Some("socks4a") => Some((SocksVersion::V4, DnsResolve::Remote)),
                Some("socks5") => Some((SocksVersion::V5, DnsResolve::Local)),
                Some("socks5h") => Some((SocksVersion::V5, DnsResolve::Remote)),
                _ => None,
            } {
                trace!("connecting via SOCKS proxy: {:?}", proxy_uri);

                let mut socks = Socks::new_with_resolver(
                    self.http.clone(),
                    self.resolver.clone(),
                    proxy_uri.clone(),
                )
                .with_auth(proxy.raw_auth())
                .with_version(version)
                .with_local_dns(dns_resolve);

                let conn = socks.call(uri.clone()).await?;

                return if uri.scheme() == Some(&Scheme::HTTPS) {
                    trace!("socks HTTPS over proxy");
                    let mut connector = self.build_tls_connector(self.http.clone(), &req)?;
                    let established_conn = EstablishedConn::new(req, conn);
                    let io = connector.call(established_conn).await?;

                    Ok(Conn {
                        inner: self.verbose.wrap(TlsConn {
                            inner: TokioIo::new(io),
                        }),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(conn),
                        is_proxy: false,
                        tls_info: false,
                    })
                };
            }
        }

        // Handle HTTPS proxy tunneling connection
        if uri.scheme() == Some(&Scheme::HTTPS) {
            trace!("tunneling HTTPS over HTTP proxy: {:?}", proxy_uri);
            let mut connector = self.build_tls_connector(self.http.clone(), &req)?;

            let mut tunnel = proxy::Tunnel::new(proxy_uri, connector.clone());
            if let Some(auth) = proxy.basic_auth() {
                tunnel = tunnel.with_auth(auth.clone());
            }

            if let Some(headers) = proxy.custom_headers() {
                tunnel = tunnel.with_headers(headers.clone());
            }

            // We don't wrap this again in an HttpsConnector since that uses Maybe,
            // and we know this is definitely HTTPS.
            let tunneled = tunnel.call(uri).await?;
            let tunneled = TokioIo::new(tunneled);
            let tunneled = TokioIo::new(tunneled);
            let established_conn = EstablishedConn::new(req, tunneled);
            let io = connector.call(established_conn).await?;

            return Ok(Conn {
                inner: self.verbose.wrap(TlsConn {
                    inner: TokioIo::new(io),
                }),
                is_proxy: false,
                tls_info: self.tls_info,
            });
        }

        *req.uri_mut() = proxy_uri;
        self.connect_direct(req, true).await
    }

    /// Automatically selects between a direct or proxied connection
    /// based on the request and configured proxy matchers.
    /// Applies a timeout if configured.
    async fn connect_auto(self, req: ConnRequest) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", req.uri());

        let intercepted = req
            .ex_data()
            .proxy_matcher()
            .and_then(|scheme| scheme.intercept(req.uri()))
            .or_else(|| {
                self.proxies
                    .iter()
                    .find_map(|prox| prox.intercept(req.uri()))
            });

        let timeout = self.timeout;
        let fut = async {
            if let Some(intercepted) = intercepted {
                self.connect_with_proxy(req, intercepted).await
            } else {
                self.connect_direct(req, false).await
            }
        };

        if let Some(to) = timeout {
            tokio::time::timeout(to, fut)
                .await
                .map_err(|_| BoxError::from(TimedOut))?
        } else {
            fut.await
        }
    }
}

impl Service<ConnRequest> for ConnectorService {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, req: ConnRequest) -> Self::Future {
        Box::pin(self.clone().connect_auto(req))
    }
}

trait TlsInfoFactory {
    fn tls_info(&self) -> Option<TlsInfo>;
}

impl TlsInfoFactory for TcpStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner().tls_info()
    }
}

impl TlsInfoFactory for SslStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok())
            .map(|c| TlsInfo {
                peer_certificate: Some(c),
            })
    }
}

impl TlsInfoFactory for MaybeHttpsStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

impl TlsInfoFactory for SslStream<TokioIo<MaybeHttpsStream<TcpStream>>> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok())
            .map(|c| TlsInfo {
                peer_certificate: Some(c),
            })
    }
}

pub(crate) trait AsyncConn:
    Read + Write + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: Read + Write + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}

trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}

impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}

mod conn {
    use super::*;

    #[derive(Debug)]
    pub struct Unnameable(pub(super) ConnRequest);

    pin_project! {
        /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
        /// This tells core whether the URI should be written in
        /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
        /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
        pub struct Conn {
            #[pin]
            pub(super) inner: BoxConn,
            pub(super) is_proxy: bool,
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

    use super::{TlsInfo, TlsInfoFactory};
    use crate::{
        core::{
            client::connect::{Connected, Connection},
            rt::{Read, ReadBufCursor, TokioIo, Write},
        },
        tls::MaybeHttpsStream,
    };

    pin_project! {
        pub(super) struct TlsConn<T> {
            #[pin]
            pub(super) inner: TokioIo<SslStream<T>>,
        }
    }

    impl Connection for TlsConn<TcpStream> {
        fn connected(&self) -> Connected {
            let connected = self.inner.inner().get_ref().connected();
            if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                connected.negotiated_h2()
            } else {
                connected
            }
        }
    }

    impl Connection for TlsConn<TokioIo<MaybeHttpsStream<TcpStream>>> {
        fn connected(&self) -> Connected {
            let connected = self.inner.inner().get_ref().connected();
            if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                connected.negotiated_h2()
            } else {
                connected
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Read for TlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Write for TlsConn<T> {
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

    impl<T> TlsInfoFactory for TlsConn<T>
    where
        TokioIo<SslStream<T>>: TlsInfoFactory,
    {
        fn tls_info(&self) -> Option<TlsInfo> {
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
            util::Escape,
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
                        trace!("{:08x} read: {:?}", self.id, Escape::new(vbuf.filled()));
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
                        trace!("{:08x} write: {:?}", self.id, Escape::new(&buf[..n]));
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
                    Escape::new(&buf[..n]).fmt(f)?;
                    left -= n;
                }
                Ok(())
            }
        }
    }
}
