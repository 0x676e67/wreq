//! QUIC dialing, socket bindings, TLS handshakes and endpoint reuse.
//! The proxy layer supplies tunnel sockets; this transport authenticates the
//! target over them using the original request's configuration and token scope.

use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    num::NonZeroUsize,
    pin::pin,
    sync::Arc,
    task::{Context, Poll},
};

use ::quic::{AsyncUdpSocket, Connecting, Connection, Endpoint, EndpointConfig, TokenStore};
use bytes::Bytes;
use futures_util::future::{self, BoxFuture, Either};
use http::Uri;
use lru::LruCache;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Notify;
use tower::{BoxError, Service};

use super::{BindOptions, ConnectError, ConnectOptions, resolve};
use crate::{
    conn::{
        Conn, Connected, HttpInfo, TlsInfoFactory,
        request::{ConnectRequest, ConnectionKey},
    },
    dns::{DynResolver, SocketAddrs},
    rt::{RuntimeHandle, Timer},
    sync::Mutex,
    tls::quic::{QuicConfig, TlsConfig},
};

/// Connects one HTTP/3 origin using the selected runtime and TLS policy.
/// Client socket bindings share one endpoint per address family; request-local
/// bindings retain their endpoints with the resulting pooled connection.
#[derive(Clone)]
pub(crate) struct QuicConnector {
    runtime: RuntimeHandle,
    resolver: DynResolver,
    tls: TlsConfig,
    tls_info: bool,
    connect_options: ConnectOptions,
    bind_options: BindOptions,
    endpoints: Arc<Endpoints>,
    tokens: Arc<Tokens>,
}

/// Configures QUIC transport before attaching a resolver.
/// Building creates shared endpoint and token stores without opening sockets.
#[must_use]
pub(crate) struct QuicConnectorBuilder {
    runtime: RuntimeHandle,
    tls: TlsConfig,
    tls_info: bool,
    bind_options: BindOptions,
    connect_options: ConnectOptions,
}

/// Lazily binds each address family independently, allowing fallback if one fails.
/// Replaces endpoints whose driver has stopped, including after their runtime shuts down.
#[derive(Default)]
struct Endpoints {
    ipv4: Mutex<Option<Endpoint>>,
    ipv6: Mutex<Option<Endpoint>>,
}

/// Address validation tokens from NEW_TOKEN frames, kept per pool key.
///
/// A token links the connection that received it to the one presenting it, so only connections
/// that may share a pool entry share tokens
/// ([RFC 9000 Section 8.1.3](https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3)).
struct Tokens(Mutex<LruCache<ConnectionKey, VecDeque<Bytes>>>);

/// The token store of one connection attempt, scoped to its pool key.
struct ScopedTokens {
    tokens: Arc<Tokens>,
    key: ConnectionKey,
}

/// UDP payload a tunnel must carry for QUIC, which pads client Initial datagrams to 1200 bytes
/// ([RFC 9000 Section 14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1)).
pub(crate) const TUNNEL_MTU: u16 = 1200;

const TOKEN_KEYS: NonZeroUsize =
    NonZeroUsize::new(256).expect("token key capacity must be non-zero");
const TOKENS_PER_KEY: usize = 2;

// ===== impl QuicConnector =====

impl QuicConnector {
    /// Starts configuring a transport with its runtime, TLS and connection policy.
    pub(crate) fn builder(
        runtime: RuntimeHandle,
        tls: TlsConfig,
        tls_info: bool,
    ) -> QuicConnectorBuilder {
        QuicConnectorBuilder {
            runtime,
            tls,
            tls_info,
            bind_options: BindOptions::default(),
            connect_options: ConnectOptions::default(),
        }
    }

    /// Opens a UDP endpoint for the address family of `remote`.
    fn open(&self, options: &BindOptions, remote: SocketAddr) -> Result<Endpoint, ConnectError> {
        Endpoint::new(
            EndpointConfig::default(),
            None,
            self.bind_socket(options, remote)?,
            self.runtime.quic(),
        )
        .map_err(ConnectError::m("quic endpoint error"))
    }

    /// Binds the physical socket before registering it with the selected runtime.
    fn bind_socket(
        &self,
        options: &BindOptions,
        remote: SocketAddr,
    ) -> Result<UdpSocket, ConnectError> {
        let address = match remote {
            SocketAddr::V4(_) => {
                SocketAddr::from((options.ipv4_address.unwrap_or(Ipv4Addr::UNSPECIFIED), 0))
            }
            SocketAddr::V6(_) => {
                SocketAddr::from((options.ipv6_address.unwrap_or(Ipv6Addr::UNSPECIFIED), 0))
            }
        };
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .map_err(ConnectError::m("quic open error"))?;
        socket
            .set_nonblocking(true)
            .map_err(ConnectError::m("quic set_nonblocking error"))?;
        if address.is_ipv6() {
            socket
                .set_only_v6(true)
                .map_err(ConnectError::m("quic set_only_v6 error"))?;
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
        if let Some(interface) = &options.interface {
            super::bind_interface(&socket, address, interface)
                .map_err(ConnectError::m("quic bind interface error"))?;
        }
        socket
            .bind(&address.into())
            .map_err(ConnectError::m("quic bind local error"))?;
        Ok(socket.into())
    }

    /// Opens a relay socket with the same binding policy as direct QUIC.
    #[cfg(feature = "socks")]
    pub(crate) fn udp_socket(
        &self,
        request: &ConnectRequest,
        remote: SocketAddr,
    ) -> Result<Box<dyn AsyncUdpSocket>, BoxError> {
        let options = self.bind_options(request);
        if matches!(
            (options.ipv4_address, options.ipv6_address, remote),
            (Some(_), None, SocketAddr::V6(_)) | (None, Some(_), SocketAddr::V4(_))
        ) {
            return Err("relay address does not match local bindings".into());
        }
        Ok(self
            .runtime
            .udp_socket(self.bind_socket(&options, remote)?)?)
    }

    /// Merges request bindings over the client's per field, as TCP connections do.
    fn bind_options(&self, request: &ConnectRequest) -> BindOptions {
        let mut options = self.bind_options.clone();
        if let Some(request) = request.bind_options() {
            options.merge(request);
        }
        options
    }

    /// Opens one authenticated connection and retains its UDP endpoint.
    /// Dropping the backend Connecting future cancels that handshake; shared
    /// endpoints remain open for other origins and concurrent connection attempts.
    async fn connect_addr(
        &self,
        endpoints: &Endpoints,
        options: &BindOptions,
        tls: &QuicConfig,
        address: SocketAddr,
        host: &str,
    ) -> Result<(Connection, Endpoint), ConnectError> {
        let slot = if address.is_ipv4() {
            &endpoints.ipv4
        } else {
            &endpoints.ipv6
        };
        let mut endpoint = self.endpoint(slot, options, address)?;
        // The attempt takes its own ticket before entering the endpoint's lock. A retry after
        // a stopped driver offers it again, since that driver never sent it.
        let client = tls.client();
        let connect = |endpoint: &Endpoint| endpoint.connect_with(client.clone(), address, host);
        let mut connecting = connect(&endpoint);
        if driver_stopped(&connecting, tls) {
            (endpoint, connecting) =
                self.reconnect(slot, &endpoint, options, tls, address, connect)?;
        }
        let connection = connecting
            .map_err(|error| ConnectError::new("quic connect error", session_error(error, tls)))?
            .await
            .map_err(ConnectError::m("quic handshake error"))?;
        Ok((connection, endpoint))
    }

    /// Retries on another endpoint after the driver of `stale` stopped.
    ///
    /// Uses the slot's endpoint unless it is `stale` or reports a stopped driver too, and
    /// otherwise replaces it with a fresh one. The slot stays locked, so concurrent retries
    /// share one replacement.
    fn reconnect(
        &self,
        slot: &Mutex<Option<Endpoint>>,
        stale: &Endpoint,
        options: &BindOptions,
        tls: &QuicConfig,
        address: SocketAddr,
        connect: impl Fn(&Endpoint) -> Result<Connecting, ::quic::ConnectError>,
    ) -> Result<(Endpoint, Result<Connecting, ::quic::ConnectError>), ConnectError> {
        let mut slot = slot.lock();
        if let Some(current) = slot.as_ref()
            && !same_socket(current, stale)
        {
            let connecting = connect(current);
            if !driver_stopped(&connecting, tls) {
                return Ok((current.clone(), connecting));
            }
        }
        let fresh = self.open(options, address)?;
        let connecting = connect(&fresh);
        if !driver_stopped(&connecting, tls) {
            *slot = Some(fresh.clone());
        }
        Ok((fresh, connecting))
    }

    /// Returns the endpoint in `slot`, opening one when the slot is empty.
    fn endpoint(
        &self,
        slot: &Mutex<Option<Endpoint>>,
        options: &BindOptions,
        remote: SocketAddr,
    ) -> Result<Endpoint, ConnectError> {
        let mut slot = slot.lock();
        if let Some(endpoint) = slot.as_ref() {
            return Ok(endpoint.clone());
        }
        let endpoint = self.open(options, remote)?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    async fn connect(
        mut self,
        request: ConnectRequest,
        timer: &dyn Timer,
    ) -> Result<Conn, BoxError> {
        let tls = self.config(&request, None)?;
        let options = self.bind_options(&request);
        let (connection, endpoint) = self
            .dial(
                request.route_uri(),
                &options,
                &tls,
                timer,
                options == self.bind_options,
            )
            .await?;
        self.connection(connection, endpoint)
    }

    /// Dials the proxy without using target-scoped address tokens or endpoint slots.
    /// TLS tickets retain the original request identity and the proxy's distinct route.
    pub(crate) async fn connect_proxy(
        &mut self,
        request: &ConnectRequest,
        uri: &Uri,
        timer: &dyn Timer,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let mut tls = self
            .tls
            .config(&request.clone().with_route_uri(uri.clone()), None)?;
        tls.transport_config(self.tls.proxy_transport(request)?);
        let options = self.bind_options(request);
        self.dial(uri, &options, &tls, timer, false).await
    }

    /// Returns the target's configuration over a tunnel, built before the tunnel so a local
    /// configuration error costs no proxy setup.
    pub(crate) fn tunnel_config(&self, request: &ConnectRequest) -> Result<QuicConfig, BoxError> {
        self.config(request, Some(TUNNEL_MTU))
    }

    /// Authenticates the target over an established UDP tunnel and retains its endpoint.
    /// The virtual peer address is local to this endpoint; the tunnel owns UDP routing.
    ///
    /// Once the tunnel ends, the socket signals `ended`, drops sends and leaves receives pending:
    /// a socket error would stop the endpoint driver, which logs it at ERROR. A watcher task
    /// closes the endpoint instead; it exits on its own once the endpoint is idle.
    pub(crate) async fn finish_tunnel(
        &self,
        request: &ConnectRequest,
        tls: &QuicConfig,
        socket: impl AsyncUdpSocket,
        remote: SocketAddr,
        ended: Arc<Notify>,
    ) -> Result<Conn, BoxError> {
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Box::new(socket),
            self.runtime.quic(),
        )?;
        let host = crate::util::strip_ipv6_brackets(
            request.route_uri().host().ok_or("HTTP/3 URI has no host")?,
        );
        let connecting = endpoint
            .connect_with(tls.client(), remote, host)
            .map_err(|error| session_error(error, tls))?;

        // Started once the connection exists, so the endpoint is not idle before it ends.
        let watched = endpoint.clone();
        self.runtime.execute(Box::pin(async move {
            let idle = watched.wait_idle();
            if let Either::Left(_) = future::select(pin!(ended.notified()), pin!(idle)).await {
                // H3_NO_ERROR: the tunnel ended without a protocol error.
                // https://www.rfc-editor.org/rfc/rfc9114#section-8.1
                watched.close(0x100u32.into(), b"proxy tunnel closed");
            }
        }));

        let connection = connecting.await?;
        self.connection(connection, endpoint)
    }

    /// Resolves and races physical addresses for either a target or a proxy.
    async fn dial(
        &mut self,
        uri: &Uri,
        options: &BindOptions,
        tls: &QuicConfig,
        timer: &dyn Timer,
        shared: bool,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let host = crate::util::strip_ipv6_brackets(uri.host().ok_or("HTTP/3 URI has no host")?);
        let addresses = resolve(
            &mut self.resolver,
            host,
            uri.port_u16().unwrap_or(443),
            uri.port().is_some(),
        )
        .await?;
        // The IPv6 endpoint is V6ONLY and cannot reach a v4-mapped address, so such an address
        // dials, filters and races as IPv4.
        let addresses = SocketAddrs::new(
            addresses
                .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                .collect(),
        );
        let local_endpoints = Endpoints::default();
        let endpoints = if shared {
            &*self.endpoints
        } else {
            &local_endpoints
        };
        // The outer timeout covers DNS, endpoint setup and every handshake.
        let policy = ConnectOptions {
            timeout: None,
            ..self.connect_options
        };
        Ok(policy
            .connect(
                addresses,
                options,
                |address| {
                    let attempt: BoxFuture<'_, _> =
                        Box::pin(self.connect_addr(endpoints, options, tls, address, host));
                    Ok(attempt)
                },
                |duration| timer.sleep(duration),
            )
            .await?)
    }

    /// Attaches single-use address tokens to the original target's TLS configuration.
    fn config(
        &self,
        request: &ConnectRequest,
        tunnel_mtu: Option<u16>,
    ) -> Result<QuicConfig, BoxError> {
        let mut tls = self.tls.config(request, tunnel_mtu)?;
        tls.token_store(Arc::new(ScopedTokens {
            tokens: self.tokens.clone(),
            key: request.key(),
        }));
        Ok(tls)
    }

    fn connection(&self, connection: Connection, endpoint: Endpoint) -> Result<Conn, BoxError> {
        let mut connected = Connected::new().extra(HttpInfo {
            remote_addr: connection.remote_address(),
            local_addr: endpoint.local_addr()?,
        });
        if self.tls_info
            && let Some(tls_info) = connection.tls_info()
        {
            connected = connected.extra(tls_info);
        }
        Ok(Conn {
            inner: Either::Right((connection, endpoint)),
            connected,
        })
    }
}

/// Compares local addresses; a replacement binds a new port while the old socket is alive.
fn same_socket(left: &Endpoint, right: &Endpoint) -> bool {
    matches!((left.local_addr(), right.local_addr()), (Ok(left), Ok(right)) if left == right)
}

/// Whether `connecting` failed because the endpoint's driver stopped.
/// A session the SSL callback rejected fails the same way; its recorded error tells them apart.
fn driver_stopped(connecting: &Result<Connecting, ::quic::ConnectError>, tls: &QuicConfig) -> bool {
    matches!(connecting, Err(::quic::ConnectError::EndpointStopping)) && tls.rejected().is_none()
}

/// Reports a session the SSL callback rejected with its TLS error, as TCP connections do.
fn session_error(error: ::quic::ConnectError, tls: &QuicConfig) -> BoxError {
    match tls.rejected() {
        Some(rejected) if error == ::quic::ConnectError::EndpointStopping => {
            Box::new(rejected.clone())
        }
        _ => Box::new(error),
    }
}

impl Service<ConnectRequest> for QuicConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        let this = self.clone();
        let timer = this.runtime.timer();
        Box::pin(async move { this.connect(request, &*timer).await })
    }
}

// ===== impl QuicConnectorBuilder =====

impl QuicConnectorBuilder {
    /// Sets the client's local addresses and interface for outbound UDP sockets.
    #[inline]
    pub(crate) fn bind_options(mut self, bind_options: BindOptions) -> Self {
        self.bind_options = bind_options;
        self
    }

    /// Attaches the resolver and creates the shared transport state.
    #[inline]
    pub(crate) fn build(self, resolver: DynResolver) -> QuicConnector {
        QuicConnector {
            runtime: self.runtime,
            resolver,
            tls: self.tls,
            tls_info: self.tls_info,
            connect_options: self.connect_options,
            bind_options: self.bind_options,
            endpoints: Arc::default(),
            tokens: Arc::new(Tokens(Mutex::new(LruCache::sparse(TOKEN_KEYS)))),
        }
    }
}

// ===== impl ScopedTokens =====

impl TokenStore for ScopedTokens {
    fn insert(&self, _server_name: &str, token: Bytes) {
        let mut tokens = self.tokens.0.lock();
        let queue = tokens.get_or_insert_mut(self.key.clone(), VecDeque::new);
        if queue.len() == TOKENS_PER_KEY {
            queue.pop_front();
        }
        queue.push_back(token);
    }

    fn take(&self, _server_name: &str) -> Option<Bytes> {
        let mut tokens = self.tokens.0.lock();
        let queue = tokens.get_mut(&self.key)?;
        let token = queue.pop_back();
        if queue.is_empty() {
            tokens.pop(&self.key);
        }
        token
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, UdpSocket},
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use ::quic::crypto::rustls::QuicServerConfig;
    use http::Uri;
    use tower::{Layer, ServiceExt};

    use super::*;
    use crate::{
        conn::{
            config::ConfigSet,
            layer::{proxy::QuicProxyLayer, timeout::TimeoutLayer},
        },
        dns::{Addrs, Name, Resolve, Resolving},
        rt::tokio::TokioRuntime,
        tls::{config::TlsConnectorBuilder, trust::CertStore},
    };

    struct Resolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    impl Resolve for Resolver {
        fn resolve(&self, name: Name) -> Resolving {
            assert_eq!(name.as_str(), "localhost");
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addresses: Addrs = Box::new(self.addresses.clone().into_iter());
            Box::pin(std::future::ready(Ok(addresses)))
        }
    }

    fn request(uri: Uri, bindings: Option<BindOptions>) -> ConnectRequest {
        ConnectRequest::new(
            &uri,
            None,
            crate::Protocol::Auto,
            ConfigSet::default(),
            &ConfigSet::default(),
            bindings.map(Arc::new),
            &BindOptions::default(),
        )
        .unwrap()
    }

    async fn connect(
        connector: &mut QuicConnector,
        request: ConnectRequest,
        server: &::quic::Endpoint,
    ) -> (Connection, Endpoint, Connection) {
        let uri = request.uri().clone();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(connector.call(request), async {
                server.accept().await.unwrap().await.map_err(BoxError::from)
            })
        })
        .await
        .unwrap_or_else(|error| panic!("connection to {uri} timed out: {error}"))
        .unwrap_or_else(|error| panic!("connection to {uri} failed: {error:?}"));
        let Conn { inner, .. } = connection;
        let Either::Right((connection, endpoint)) = inner else {
            panic!("QUIC connector returned a stream");
        };
        (connection, endpoint, peer)
    }

    /// Returns a QUIC server configuration for `localhost` and its certificate in DER.
    fn server_config() -> (::quic::ServerConfig, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "::ffff:127.0.0.1".into(),
            "::1".into(),
        ])
        .unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config =
            ::quic::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        (config, cert.cert.der().to_vec())
    }

    /// Returns a connector trusting `cert` that resolves names through `resolver`.
    fn connector(resolver: Arc<dyn Resolve>, cert: &[u8]) -> QuicConnector {
        let tls = TlsConnectorBuilder::new()
            .cert_store(CertStore::from_der_certs([cert]).unwrap())
            .build_quic(ConfigSet::default())
            .unwrap();
        QuicConnector::builder(RuntimeHandle::new(TokioRuntime), tls, false)
            .build(DynResolver::new(resolver))
    }

    fn current(slot: &Mutex<Option<Endpoint>>) -> Endpoint {
        slot.lock().clone().unwrap()
    }

    fn ipv6_udp_available() -> bool {
        let probe = || -> std::io::Result<bool> {
            let receiver = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))?;
            receiver.set_read_timeout(Some(Duration::from_millis(250)))?;
            let sender = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
            sender.send_to(b"ipv6", receiver.local_addr()?)?;
            let mut data = [0; 4];
            Ok(receiver.recv_from(&mut data)?.0 == data.len() && &data == b"ipv6")
        };
        probe().unwrap_or(false)
    }

    fn resolving(addresses: Vec<SocketAddr>) -> Arc<Resolver> {
        Arc::new(Resolver {
            addresses,
            calls: AtomicUsize::new(0),
        })
    }

    fn literal(address: SocketAddr) -> ConnectRequest {
        request(format!("https://{address}/").parse().unwrap(), None)
    }

    fn configured<T: crate::conn::config::ConnectConfig>(value: T) -> ConnectRequest {
        let mut config_set = ConfigSet::default();
        config_set.insert(value);
        let uri = Uri::from_static("https://localhost/");
        ConnectRequest::test(uri, Some(crate::Protocol::Http3), config_set)
    }

    #[tokio::test]
    async fn races_families_and_cancels_the_losing_handshake() {
        let (server_config, cert) = server_config();
        let server4 =
            ::quic::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr4 = server4.local_addr().unwrap();
        // Keep the port bound without replying so the first handshake stays pending.
        let blackhole = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let resolver = resolving(vec![blackhole.local_addr().unwrap(), addr4]);
        let mut connector = connector(resolver.clone(), &cert);
        connector.connect_options.happy_eyeballs_timeout = Some(Duration::from_millis(20));
        let localhost = request(Uri::from_static("https://localhost/"), None);
        let (connection, _, _peer) = connect(&mut connector, localhost, &server4).await;
        assert_eq!(connection.remote_address(), addr4);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        let slot = if blackhole.local_addr().unwrap().is_ipv6() {
            &connector.endpoints.ipv6
        } else {
            &connector.endpoints.ipv4
        };
        let pending_endpoint = current(slot);
        let expected_active = usize::from(blackhole.local_addr().unwrap().is_ipv4());
        tokio::time::timeout(Duration::from_secs(5), async {
            while pending_endpoint.open_connections() != expected_active {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("losing handshake must be canceled without closing its endpoint");
        assert!(same_socket(&current(slot), &pending_endpoint));
        connection.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn reuses_family_endpoints_and_isolates_request_bindings() {
        let (server_config, cert) = server_config();
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            if address.is_ipv6() && !ipv6_udp_available() {
                eprintln!("IPv6 UDP loopback is unavailable; skipping IPv6 cases");
                continue;
            }
            let server = Endpoint::server(server_config.clone(), (address, 0).into()).unwrap();
            let remote = server.local_addr().unwrap();
            let resolver = resolving(vec![remote]);
            let mut connector = connector(resolver.clone(), &cert);
            let localhost = request(Uri::from_static("https://localhost/"), None);
            let (first, shared, first_peer) = connect(&mut connector, localhost, &server).await;
            let local = shared.local_addr().unwrap();
            assert_eq!(first.remote_address(), remote);
            assert!(local.ip().is_unspecified());

            // IP literals bypass DNS while reusing the family's socket.
            let (second, reused, second_peer) =
                connect(&mut connector, literal(remote), &server).await;
            assert_eq!(reused.local_addr().unwrap(), local);
            assert_eq!(first_peer.remote_address(), second_peer.remote_address());
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

            // The IPv6 socket is V6ONLY, so a v4-mapped address must use the IPv4 one.
            if let IpAddr::V4(ipv4) = address {
                let mapped = SocketAddr::new(ipv4.to_ipv6_mapped().into(), remote.port());
                let (mapped, reused, _peer) =
                    connect(&mut connector, literal(mapped), &server).await;
                assert_eq!(mapped.remote_address(), remote);
                assert_eq!(reused.local_addr().unwrap(), local);
                mapped.close(0u32.into(), b"done");
            }

            let mut bindings = BindOptions::default();
            bindings.set_local_address(address);
            let localhost = request(Uri::from_static("https://localhost/"), Some(bindings));
            let (bound, isolated, _bound_peer) = connect(&mut connector, localhost, &server).await;
            let isolated = isolated.local_addr().unwrap();
            assert_eq!(isolated.ip(), address);
            assert_ne!(isolated.port(), local.port());
            let slot = if address.is_ipv4() {
                &connector.endpoints.ipv4
            } else {
                &connector.endpoints.ipv6
            };
            assert_eq!(current(slot).local_addr().unwrap(), local);
            for connection in [first, second, bound] {
                connection.close(0u32.into(), b"done");
            }
        }
    }

    #[tokio::test]
    async fn failed_handshakes_keep_the_shared_endpoint() {
        let (server_config, cert) = server_config();
        let server4 =
            ::quic::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr4 = server4.local_addr().unwrap();
        let mut connector = connector(resolving(vec![addr4]), &cert);
        let (first, endpoint4, _first_peer) =
            connect(&mut connector, literal(addr4), &server4).await;

        // Invalid key shares fail in the SSL callback, which the QUIC stack reports like a
        // stopped driver. The TLS error must surface without opening another socket, which a
        // TEST-NET binding refuses (https://www.rfc-editor.org/rfc/rfc5737).
        let invalid = crate::quic::QuicOptions::builder()
            .curves_list("X25519")
            .key_shares(vec![crate::tls::KeyShare::P256])
            .build();
        connector
            .bind_options
            .set_local_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let error = connector.call(configured(invalid)).await.err().unwrap();
        connector.bind_options = BindOptions::default();
        let mut chain = std::iter::successors(
            Some(&*error as &(dyn std::error::Error + 'static)),
            |error| error.source(),
        );
        assert!(
            chain.any(|error| error.is::<btls::error::ErrorStack>()),
            "{error:?}"
        );
        assert!(same_socket(&current(&connector.endpoints.ipv4), &endpoint4));

        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let timed_out =
            TimeoutLayer::new(connector.runtime.clone(), Some(Duration::from_millis(30)))
                .layer(connector.clone())
                .oneshot(literal(blackhole.local_addr().unwrap()))
                .await
                .err()
                .unwrap();
        assert!(timed_out.is::<crate::error::TimedOut>());
        assert!(first.close_reason().is_none());

        let (after, reused4, _after_peer) = connect(&mut connector, literal(addr4), &server4).await;
        assert_eq!(
            reused4.local_addr().unwrap(),
            endpoint4.local_addr().unwrap()
        );
        for connection in [first, after] {
            connection.close(0u32.into(), b"done");
        }
    }

    #[test]
    fn replaces_an_endpoint_whose_runtime_stopped() {
        /// Hides its address once `hidden` is set, as a custom runtime's socket may after its
        /// reactor stops.
        #[derive(Debug)]
        struct Hidden(Box<dyn AsyncUdpSocket>, Arc<std::sync::atomic::AtomicBool>);

        impl AsyncUdpSocket for Hidden {
            fn create_sender(&self) -> std::pin::Pin<Box<dyn ::quic::UdpSender>> {
                self.0.create_sender()
            }

            fn poll_recv(
                &mut self,
                cx: &mut Context<'_>,
                bufs: &mut [std::io::IoSliceMut<'_>],
                meta: &mut [::quic::udp::RecvMeta],
            ) -> Poll<std::io::Result<usize>> {
                self.0.poll_recv(cx, bufs, meta)
            }

            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                if self.1.load(Ordering::SeqCst) {
                    Err(std::io::ErrorKind::NotConnected.into())
                } else {
                    self.0.local_addr()
                }
            }
        }

        // An endpoint's driver runs on the runtime that opened it; a client outliving that
        // runtime must open a new endpoint instead of failing every later connection.
        let (config, cert) = server_config();
        let (addresses, address) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server =
                    ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
                addresses.send(server.local_addr().unwrap()).unwrap();
                for _ in 0..3 {
                    server.accept().await.unwrap().await.unwrap();
                }
            });
        });
        let connector = connector(resolving(vec![address.recv().unwrap()]), &cert);
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let connect = || {
            let runtime = runtime();
            let mut connector = connector.clone();
            let request = request(Uri::from_static("https://localhost/"), None);
            let Conn { inner, .. } = runtime
                .block_on(async { connector.call(request).await })
                .unwrap();
            let Either::Right((connection, endpoint)) = inner else {
                panic!("QUIC connector returned a stream");
            };
            connection.close(0u32.into(), b"done");
            endpoint.local_addr().unwrap()
        };
        let local = [connect(), connect()];
        assert_ne!(local[0], local[1]);
        assert_eq!(
            current(&connector.endpoints.ipv4).local_addr().unwrap(),
            local[1]
        );

        // The comparison with the slot's endpoint cannot tell a stale endpoint without an
        // address apart, so it must still be replaced rather than retried forever.
        let hidden = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stale = runtime().block_on(async {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            let socket = Hidden(
                connector.runtime.udp_socket(socket).unwrap(),
                hidden.clone(),
            );
            Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                Box::new(socket),
                connector.runtime.quic(),
            )
            .unwrap()
        });
        hidden.store(true, Ordering::SeqCst);
        *connector.endpoints.ipv4.lock() = Some(stale);
        let replaced = connect();
        assert_eq!(
            current(&connector.endpoints.ipv4).local_addr().unwrap(),
            replaced
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn reuses_address_tokens_within_a_pool_key() {
        /// Accepts every token, so the server reports which connections presented one.
        struct AcceptAll;

        impl ::quic::TokenLog for AcceptAll {
            fn check_and_insert(
                &self,
                _nonce: u128,
                _issued: std::time::SystemTime,
                _lifetime: Duration,
            ) -> Result<(), ::quic::TokenReuseError> {
                Ok(())
            }
        }

        let (mut config, cert) = server_config();
        let mut validation = ::quic::ValidationTokenConfig::default();
        validation
            .sent(TOKENS_PER_KEY as u32)
            .log(Arc::new(AcceptAll));
        config.validation_token_config(validation);
        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut connector = connector(resolving(vec![server.local_addr().unwrap()]), &cert);
        let request = |group: &'static str| configured(crate::group::Group::new(group));

        let key = request("first").key();
        let received = |connector: &QuicConnector| {
            connector
                .tokens
                .0
                .lock()
                .peek(&key)
                .map_or(0, VecDeque::len)
        };
        let mut connections = Vec::new();
        for (group, validated) in [("first", false), ("first", true), ("second", false)] {
            if validated {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while received(&connector) < TOKENS_PER_KEY {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the first connection must receive its tokens");
            }
            let attempt = async {
                tokio::join!(connector.call(request(group)), async {
                    let incoming = server.accept().await.unwrap();
                    let presented = incoming.remote_address_validated();
                    (presented, incoming.await.unwrap())
                })
            };
            let (client, (presented, accepted)) =
                tokio::time::timeout(Duration::from_secs(5), attempt)
                    .await
                    .expect("token connection timed out");
            assert_eq!(presented, validated, "{group}");
            connections.push((client.unwrap(), accepted));
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_proxy_routes_before_dns() {
        let resolver = resolving(Vec::new());
        let transport = connector(resolver.clone(), &server_config().1);
        let proxy = || {
            crate::Proxy::all("http://proxy:8080")
                .unwrap()
                .into_matcher()
        };
        #[cfg(feature = "socks")]
        let tcp = crate::conn::transport::TcpConnector::new(transport.runtime.clone())
            .build(transport.resolver.clone());
        let uri = Uri::from_static("https://localhost/");
        for (proxies, request) in [
            (Arc::new(vec![proxy()]), request(uri, None)),
            (Arc::default(), configured(proxy())),
        ] {
            let mut connector = QuicProxyLayer::new(
                transport.runtime.clone(),
                proxies,
                #[cfg(feature = "socks")]
                tcp.clone(),
                #[cfg(feature = "socks")]
                transport.resolver.clone(),
            )
            .layer(transport.clone());
            let error = connector
                .call(request)
                .await
                .err()
                .expect("QUIC must reject a proxy route");
            assert!(error.is::<crate::error::ProxyMismatch>());
            assert_eq!(
                error.to_string(),
                "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature"
            );
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn applies_request_transport_options() {
        let (config, cert) = server_config();
        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut connector = connector(resolving(vec![server.local_addr().unwrap()]), &cert);

        // The negotiated idle timeout is the lower of both peers' values.
        let options = crate::quic::QuicOptions::builder()
            .max_idle_timeout(Duration::from_millis(200))
            .build();
        let (_client, _endpoint, accepted) =
            connect(&mut connector, configured(options), &server).await;
        let error = tokio::time::timeout(Duration::from_secs(5), accepted.closed())
            .await
            .unwrap();
        assert!(
            matches!(error, ::quic::ConnectionError::TimedOut),
            "{error:?}"
        );
    }
}
