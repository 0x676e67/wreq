//! QUIC dialing, TLS handshakes, address tokens and endpoint reuse.
//! Proxy routes supply tunnel sockets; [`Endpoints`] authenticates the
//! target over them using the original request's configuration and token scope.

use std::{
    collections::VecDeque, net::SocketAddr, num::NonZeroUsize, ops::Deref, pin::pin, sync::Arc,
    time::Instant,
};

use ::quic::{
    AsyncUdpSocket, Connecting, Connection, ConnectionError, Endpoint, EndpointConfig, TokenStore,
    TransportConfig, TransportErrorCode,
};
use btls::x509::X509;
use bytes::Bytes;
use futures_util::future::{self, BoxFuture, Either};
use http::Uri;
use lru::LruCache;
use tokio::sync::Notify;
use tower::BoxError;

use crate::{
    config::connect::ConfigSet,
    conn::{
        Conn, Connected, HttpInfo, Transport,
        connected::tls_info,
        dialer::{self, ConnectError, Dialer, race, resolve, within_deadline},
        request::{ConnectRequest, ConnectionKey},
    },
    dns::SocketAddrs,
    quic::QuicOptions,
    rt::Timer as _,
    sync::Mutex,
    tls::quic::{QuicConfig, QuicTls},
};

/// Dials QUIC connections with the client's TLS, transports and address tokens.
/// Client socket bindings share one endpoint per address family; request-local
/// bindings retain their endpoints with the resulting pooled connection.
pub(super) struct Endpoints {
    dialer: Dialer,
    tls: QuicTls,
    direct_transport: Arc<TransportConfig>,
    proxy_transport: Arc<TransportConfig>,
    slots: Slots,
    tokens: Arc<Tokens>,
}

/// The route of one QUIC connection, which selects its transport.
#[derive(Clone, Copy)]
enum Path {
    /// To the origin over UDP.
    Direct,
    /// To a MASQUE proxy, whose Datagrams carry a tunnel.
    Proxy,
    /// To the origin over a proxy tunnel.
    Tunnel,
}

/// Lazily binds each address family independently, allowing fallback if one fails.
/// Replaces endpoints whose driver has stopped, including after their runtime shuts down.
#[derive(Default)]
struct Slots {
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
pub(super) const TUNNEL_MTU: u16 = 1200;

/// Outer MTU fitting a tunneled 1200-byte datagram: QUIC short header (1 + 20-byte CID + 4),
/// AEAD tag (16), DATAGRAM frame (9), Quarter Stream ID (8) and Context ID (1), at most.
const PROXY_MTU: u16 = TUNNEL_MTU + 59;

/// Smallest frame limit a MASQUE proxy connection keeps. The QUIC stack also bounds buffered
/// datagrams by this limit, so it must hold a burst of tunnel packets, not one or two.
const PROXY_DATAGRAM_BUFFER: u64 = 16 * PROXY_MTU as u64;

const TOKEN_KEYS: NonZeroUsize =
    NonZeroUsize::new(256).expect("token key capacity must be non-zero");
const TOKENS_PER_KEY: usize = 2;

// ===== impl Endpoints =====

impl Endpoints {
    /// Creates endpoints dialing through `dialer` with the client's TLS. Builds the client's
    /// transports from its QUIC options and creates the shared endpoint and token stores without
    /// opening sockets.
    pub(super) fn new(dialer: Dialer, tls: QuicTls) -> crate::Result<Self> {
        let options = tls.options();
        let direct_transport = Arc::new(Path::Direct.transport(options)?);
        let proxy_transport = Arc::new(Path::Proxy.transport(options)?);
        Ok(Self {
            dialer,
            tls,
            direct_transport,
            proxy_transport,
            slots: Slots::default(),
            tokens: Arc::new(Tokens(Mutex::new(LruCache::sparse(TOKEN_KEYS)))),
        })
    }

    /// Returns the dialer that resolves, races and binds the sockets of every route.
    #[inline]
    pub(super) fn dialer(&self) -> &Dialer {
        &self.dialer
    }

    /// Opens a UDP endpoint for the address family of `remote`.
    fn open(&self, config_set: &ConfigSet, remote: SocketAddr) -> Result<Endpoint, ConnectError> {
        let dialer = &self.dialer;
        Endpoint::new(
            endpoint_config(),
            None,
            dialer.bind_udp(config_set, remote)?,
            dialer.runtime().quic(),
        )
        .map_err(ConnectError::m("quic endpoint error"))
    }

    /// Opens one authenticated connection and retains its UDP endpoint.
    /// Dropping the backend Connecting future cancels that handshake; shared
    /// endpoints remain open for other origins and concurrent connection attempts.
    async fn connect_addr(
        &self,
        slots: &Slots,
        config_set: &ConfigSet,
        config: &QuicConfig,
        address: SocketAddr,
        host: &str,
    ) -> Result<(Connection, Endpoint), ConnectError> {
        let slot = if address.is_ipv4() {
            &slots.ipv4
        } else {
            &slots.ipv6
        };
        let mut endpoint = self.endpoint(slot, config_set, address)?;
        // The attempt takes its own ticket before entering the endpoint's lock. A retry after
        // a stopped driver offers it again, since that driver never sent it.
        let client = config.client();
        let connect = |endpoint: &Endpoint| endpoint.connect_with(client.clone(), address, host);
        let mut connecting = connect(&endpoint);
        if driver_stopped(&connecting, config) {
            (endpoint, connecting) =
                self.reconnect(slot, &endpoint, config_set, config, address, connect)?;
        }
        let connection = connecting
            .map_err(|error| ConnectError::new("quic connect error", session_error(error, config)))?
            .await
            .map_err(handshake_error("quic handshake error"))?;
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
        config_set: &ConfigSet,
        config: &QuicConfig,
        address: SocketAddr,
        connect: impl Fn(&Endpoint) -> Result<Connecting, ::quic::ConnectError>,
    ) -> Result<(Endpoint, Result<Connecting, ::quic::ConnectError>), ConnectError> {
        let mut slot = slot.lock();
        if let Some(current) = slot.as_ref()
            && !same_socket(current, stale)
        {
            let connecting = connect(current);
            if !driver_stopped(&connecting, config) {
                return Ok((current.clone(), connecting));
            }
        }
        let fresh = self.open(config_set, address)?;
        let connecting = connect(&fresh);
        if !driver_stopped(&connecting, config) {
            *slot = Some(fresh.clone());
        }
        Ok((fresh, connecting))
    }

    /// Returns the endpoint in `slot`, opening one when the slot is empty.
    fn endpoint(
        &self,
        slot: &Mutex<Option<Endpoint>>,
        config_set: &ConfigSet,
        remote: SocketAddr,
    ) -> Result<Endpoint, ConnectError> {
        let mut slot = slot.lock();
        if let Some(endpoint) = slot.as_ref() {
            return Ok(endpoint.clone());
        }
        let endpoint = self.open(config_set, remote)?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Connects to the request's route directly and retains the connection's endpoint.
    pub(super) async fn connect(&self, request: &ConnectRequest) -> Result<Conn, BoxError> {
        let config = self.config(request, Path::Direct)?;
        let (connection, endpoint) = self
            .dial(
                request.uri(),
                request.config_set(),
                &config,
                dialer::uses_client_bindings(request.config_set(), self.dialer.config_set()),
            )
            .await?;
        self.connection(connection, endpoint)
    }

    /// Dials the proxy until `deadline`, without using target-scoped address tokens or
    /// endpoint slots. TLS tickets retain the original request identity and the proxy's
    /// distinct route.
    pub(super) async fn connect_proxy(
        &self,
        request: &ConnectRequest,
        uri: &Uri,
        deadline: Option<Instant>,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let mut config = self.tls.config(request, uri)?;
        config.transport_config(self.transport(request, Path::Proxy)?);
        let dial = self.dial(uri, request.config_set(), &config, false);
        within_deadline(deadline, self.dialer.runtime(), dial).await
    }

    /// Returns the target's configuration over a tunnel, built before the tunnel so a local
    /// configuration error costs no proxy setup.
    pub(super) fn tunnel_config(&self, request: &ConnectRequest) -> Result<QuicConfig, BoxError> {
        self.config(request, Path::Tunnel)
    }

    /// Authenticates the target over an established UDP tunnel and retains its endpoint.
    /// The virtual peer address is local to this endpoint; the tunnel owns UDP routing.
    ///
    /// Once the tunnel ends, the socket signals `ended`, drops sends and leaves receives pending:
    /// a socket error would stop the endpoint driver, which logs it at ERROR. A watcher task
    /// closes the endpoint instead; it exits on its own once the endpoint is idle.
    pub(super) async fn finish_tunnel(
        &self,
        request: &ConnectRequest,
        config: &QuicConfig,
        socket: impl AsyncUdpSocket,
        remote: SocketAddr,
        ended: Arc<Notify>,
    ) -> Result<Conn, BoxError> {
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            Box::new(socket),
            self.dialer.runtime().quic(),
        )?;
        let host =
            crate::util::strip_ipv6_brackets(request.uri().host().ok_or("HTTP/3 URI has no host")?);
        let connecting = endpoint
            .connect_with(config.client(), remote, host)
            .map_err(|error| session_error(error, config))?;

        // Started once the connection exists, so the endpoint is not idle before it ends.
        let watched = endpoint.clone();
        self.dialer.runtime().execute(Box::pin(async move {
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
        &self,
        uri: &Uri,
        config_set: &ConfigSet,
        config: &QuicConfig,
        shared: bool,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let dialer = &self.dialer;
        let host = crate::util::strip_ipv6_brackets(uri.host().ok_or("HTTP/3 URI has no host")?);
        let addresses = resolve(
            host,
            uri.port_u16().unwrap_or(443),
            uri.port().is_some(),
            |name| dialer.resolver().resolve(name),
        )
        .await?;
        // The IPv6 endpoint is V6ONLY and cannot reach a v4-mapped address, so such an address
        // dials, filters and races as IPv4.
        let addresses = SocketAddrs::new(
            addresses
                .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                .collect(),
        );
        let local = Slots::default();
        let slots = if shared { &self.slots } else { &local };
        Ok(race(
            addresses,
            dialer::local_addresses(config_set, dialer.config_set()),
            dialer.happy_eyeballs_timeout(),
            |address| {
                let attempt: BoxFuture<'_, _> =
                    Box::pin(self.connect_addr(slots, config_set, config, address, host));
                Ok(attempt)
            },
            |duration| dialer.runtime().sleep(duration),
        )
        .await?)
    }

    /// Attaches the transport of `path` and single-use address tokens to the original
    /// target's TLS configuration.
    fn config(&self, request: &ConnectRequest, path: Path) -> Result<QuicConfig, BoxError> {
        let mut config = self.tls.config(request, request.uri())?;
        config.transport_config(self.transport(request, path)?);
        config.token_store(Arc::new(ScopedTokens {
            tokens: self.tokens.clone(),
            key: request.key(),
        }));
        Ok(config)
    }

    /// Returns the transport of `path` for `request`. The client's is reused unless the
    /// request changes transport options; a tunnel's is built for each connection.
    fn transport(
        &self,
        request: &ConnectRequest,
        path: Path,
    ) -> crate::Result<Arc<TransportConfig>> {
        let client = self.tls.options();
        let requested = request
            .config_override::<QuicOptions>()
            .filter(|requested| !client.is_some_and(|client| requested.same_transport(client)));
        match (path, requested) {
            (Path::Direct, None) => Ok(self.direct_transport.clone()),
            (Path::Proxy, None) => Ok(self.proxy_transport.clone()),
            (path, requested) => path.transport(requested.or(client)).map(Arc::new),
        }
    }

    fn connection(&self, connection: Connection, endpoint: Endpoint) -> Result<Conn, BoxError> {
        let mut connected = Connected::new().extra(HttpInfo {
            remote_addr: connection.remote_address(),
            local_addr: endpoint.local_addr()?,
        });
        if self.tls.tls_info()
            && let Some(chain) = connection
                .peer_identity()
                .and_then(|identity| identity.downcast::<Vec<X509>>().ok())
        {
            connected = connected.extra(tls_info(
                chain.first().map(Deref::deref),
                Some(chain.iter().map(Deref::deref)),
            ));
        }
        Ok(Conn {
            transport: Transport::Quic {
                connection,
                endpoint,
            },
            connected,
        })
    }
}

/// Endpoint settings with a BoringSSL stateless-reset key. `EndpointConfig::default` would pick
/// another crypto provider that feature unification enables, as dev-dependencies do in tests.
fn endpoint_config() -> EndpointConfig {
    EndpointConfig::new(Arc::new(::quic::crypto::btls::HmacKey::sha256()))
}

/// Compares local addresses; a replacement binds a new port while the old socket is alive.
fn same_socket(left: &Endpoint, right: &Endpoint) -> bool {
    matches!((left.local_addr(), right.local_addr()), (Ok(left), Ok(right)) if left == right)
}

/// Whether `connecting` failed because the endpoint's driver stopped.
/// A session the SSL callback rejected fails the same way; its recorded error tells them apart.
fn driver_stopped(
    connecting: &Result<Connecting, ::quic::ConnectError>,
    config: &QuicConfig,
) -> bool {
    matches!(connecting, Err(::quic::ConnectError::EndpointStopping)) && config.rejected().is_none()
}

/// Reports a session the SSL callback rejected with its TLS error, as TCP connections do.
fn session_error(error: ::quic::ConnectError, config: &QuicConfig) -> BoxError {
    match config.rejected() {
        Some(rejected) if error == ::quic::ConnectError::EndpointStopping => {
            Box::new(rejected.clone())
        }
        _ => Box::new(error),
    }
}

/// Labels a failed handshake; one the peer answered and refused ends the address race.
///
/// Another address of the host would refuse it too, so QUIC reports it once, as TLS over TCP
/// does after the TCP race. A refusal is a TLS alert from either side, carried as a
/// CRYPTO_ERROR code ([RFC 9000 Section 20.1], [RFC 9001 Section 4.8]), or a Version
/// Negotiation packet without a supported version ([RFC 9000 Section 6.2]). Timeouts, resets
/// and other closes, such as a busy or draining server's, advance the race.
///
/// [RFC 9000 Section 20.1]: https://www.rfc-editor.org/rfc/rfc9000#section-20.1
/// [RFC 9001 Section 4.8]: https://www.rfc-editor.org/rfc/rfc9001#section-4.8
/// [RFC 9000 Section 6.2]: https://www.rfc-editor.org/rfc/rfc9000#section-6.2
pub(super) fn handshake_error<E: Into<BoxError>>(
    msg: &'static str,
) -> impl FnOnce(E) -> ConnectError {
    move |cause| {
        let cause = cause.into();
        let crypto = |code: TransportErrorCode| (0x100..0x200).contains(&u64::from(code));
        let terminal = match cause.downcast_ref() {
            Some(ConnectionError::VersionMismatch) => true,
            Some(ConnectionError::TransportError(error)) => crypto(error.code),
            Some(ConnectionError::ConnectionClosed(close)) => crypto(close.error_code),
            _ => false,
        };
        ConnectError {
            terminal,
            ..ConnectError::new(msg, cause)
        }
    }
}

// ===== impl Path =====

impl Path {
    /// Builds this path's transport from the QUIC options in effect.
    fn transport(self, options: Option<&QuicOptions>) -> crate::Result<TransportConfig> {
        match self {
            Path::Direct => {
                options.map_or_else(|| Ok(TransportConfig::default()), QuicOptions::transport)
            }
            Path::Proxy => proxy_transport(options),
            Path::Tunnel => {
                let mut transport = Path::Direct.transport(options)?;
                // The tunnel's outer path owns MTU discovery; preserve other transport options.
                transport
                    .initial_mtu(TUNNEL_MTU)
                    .min_mtu(TUNNEL_MTU)
                    .mtu_discovery_config(None);
                Ok(transport)
            }
        }
    }
}

/// Builds a MASQUE proxy transport from client options. Its Datagrams carry the tunnel and
/// cannot be fragmented, so the path MTU starts at and never drops below one that fits them,
/// even after a black hole reset
/// ([RFC 9298 Section 6.1](https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1)); a frame
/// limit too small for a burst of them falls back to the default.
fn proxy_transport(options: Option<&QuicOptions>) -> crate::Result<TransportConfig> {
    let mut options = options.cloned().unwrap_or_default();
    if options
        .max_datagram_frame_size
        .is_some_and(|size| size < PROXY_DATAGRAM_BUFFER)
    {
        options.max_datagram_frame_size = None;
    }
    let mut transport = options.transport()?;
    // The initial MTU is raised to this floor as well.
    transport.min_mtu(PROXY_MTU);
    Ok(transport)
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

/// Returns a QUIC server configuration for `localhost` and the loopback addresses, with its
/// certificate in DER.
#[cfg(test)]
pub(crate) fn test_server_config() -> (::quic::ServerConfig, Vec<u8>) {
    use ::quic::crypto::rustls::QuicServerConfig;

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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
        time::Duration,
    };

    use http::Uri;
    use tower::{Layer, ServiceExt, service_fn};

    use super::*;
    use crate::{
        conn::{dialer::tcp, layer::deadline::DeadlineLayer, svc::TransportRequest},
        dns::{Addrs, DynResolver, Name, Resolve, Resolving},
        rt::{DynRuntime, tokio::TokioRuntime},
        tls::{self, trust::CertStore},
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

    fn request(uri: Uri, config_set: ConfigSet) -> ConnectRequest {
        ConnectRequest::new(
            &uri,
            None,
            crate::Protocol::Auto,
            config_set,
            &ConfigSet::default(),
        )
        .unwrap()
    }

    async fn connect(
        endpoints: &Endpoints,
        request: ConnectRequest,
        server: &::quic::Endpoint,
    ) -> (Connection, Endpoint, Connection) {
        let uri = request.uri().clone();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(endpoints.connect(&request), async {
                server.accept().await.unwrap().await.map_err(BoxError::from)
            })
        })
        .await
        .unwrap_or_else(|error| panic!("connection to {uri} timed out: {error}"))
        .unwrap_or_else(|error| panic!("connection to {uri} failed: {error:?}"));
        let (connection, endpoint) = connection.transport.into_quic().unwrap();
        (connection, endpoint, peer)
    }

    /// Returns endpoints trusting `cert` that resolve names through `resolver`, with the
    /// client's bindings and Happy Eyeballs delay.
    fn endpoints_with(
        resolver: Arc<dyn Resolve>,
        cert: &[u8],
        config_set: ConfigSet,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Endpoints {
        let tls = tls::Config {
            cert_store: Some(CertStore::from_der_certs([cert]).unwrap()),
            ..Default::default()
        };
        let dialer = Dialer::new(
            DynRuntime::new(TokioRuntime),
            DynResolver::new(resolver),
            tcp::Config::default(),
            config_set,
            happy_eyeballs_timeout,
        );
        Endpoints::new(dialer, tls.quic(&ConfigSet::default()).unwrap()).unwrap()
    }

    /// Returns endpoints trusting `cert` that resolve names through `resolver`. Its tests
    /// resolve one address, so no delay applies.
    fn endpoints(resolver: Arc<dyn Resolve>, cert: &[u8]) -> Endpoints {
        endpoints_with(resolver, cert, ConfigSet::default(), None)
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
        request(
            format!("https://{address}/").parse().unwrap(),
            ConfigSet::default(),
        )
    }

    fn configured<T: crate::config::connect::ConnectConfig>(value: T) -> ConnectRequest {
        let mut config_set = ConfigSet::default();
        config_set.insert(value);
        let uri = Uri::from_static("https://localhost/");
        ConnectRequest::test(uri, Some(crate::Protocol::Http3), config_set)
    }

    #[tokio::test]
    async fn races_families_and_cancels_the_losing_handshake() {
        let (server_config, cert) = test_server_config();
        let server4 =
            ::quic::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr4 = server4.local_addr().unwrap();
        // Keep the port bound without replying so the first handshake stays pending.
        let blackhole = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let resolver = resolving(vec![blackhole.local_addr().unwrap(), addr4]);
        let endpoints = endpoints_with(
            resolver.clone(),
            &cert,
            ConfigSet::default(),
            Some(Duration::from_millis(20)),
        );
        let localhost = request(Uri::from_static("https://localhost/"), ConfigSet::default());
        let (connection, _, _peer) = connect(&endpoints, localhost, &server4).await;
        assert_eq!(connection.remote_address(), addr4);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        let slot = if blackhole.local_addr().unwrap().is_ipv6() {
            &endpoints.slots.ipv6
        } else {
            &endpoints.slots.ipv4
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
    async fn a_refused_handshake_ends_the_race() {
        let (server_config, _) = test_server_config();
        // The client trusts another certificate, so it rejects each server's.
        let (_, cert) = test_server_config();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let mut addresses = Vec::new();
        for _ in 0..2 {
            let server =
                Endpoint::server(server_config.clone(), (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
            addresses.push(server.local_addr().unwrap());
            let handshakes = handshakes.clone();
            tokio::spawn(async move {
                while let Some(incoming) = server.accept().await {
                    handshakes.fetch_add(1, Ordering::SeqCst);
                    let _ = incoming.await;
                }
            });
        }
        // Sequential and staggered attempts both stop at the first refusal.
        for happy_eyeballs_timeout in [None, Some(Duration::from_secs(5))] {
            handshakes.store(0, Ordering::SeqCst);
            let endpoints = endpoints_with(
                resolving(addresses.clone()),
                &cert,
                ConfigSet::default(),
                happy_eyeballs_timeout,
            );
            let localhost = request(Uri::from_static("https://localhost/"), ConfigSet::default());
            let error = tokio::time::timeout(Duration::from_secs(5), endpoints.connect(&localhost))
                .await
                .unwrap()
                .err()
                .unwrap()
                .downcast::<ConnectError>()
                .unwrap();
            assert_eq!(error.addr, Some(addresses[0]));
            assert_eq!(handshakes.load(Ordering::SeqCst), 1, "{error:?}");
            // unknown_ca (https://www.rfc-editor.org/rfc/rfc8446#section-6.2)
            std::assert_matches!(
                error.cause.as_deref().and_then(|cause| cause.downcast_ref()),
                Some(ConnectionError::TransportError(alert))
                    if alert.code == TransportErrorCode::crypto(48),
                "{error:?}"
            );
        }
    }

    #[tokio::test]
    async fn reuses_family_endpoints_and_isolates_request_bindings() {
        let (server_config, cert) = test_server_config();
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
            let endpoints = endpoints(resolver.clone(), &cert);
            let localhost = request(Uri::from_static("https://localhost/"), ConfigSet::default());
            let (first, shared, first_peer) = connect(&endpoints, localhost, &server).await;
            let local = shared.local_addr().unwrap();
            assert_eq!(first.remote_address(), remote);
            assert!(local.ip().is_unspecified());

            // IP literals bypass DNS while reusing the family's socket.
            let (second, reused, second_peer) = connect(&endpoints, literal(remote), &server).await;
            assert_eq!(reused.local_addr().unwrap(), local);
            assert_eq!(first_peer.remote_address(), second_peer.remote_address());
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

            // The IPv6 socket is V6ONLY, so a v4-mapped address must use the IPv4 one.
            if let IpAddr::V4(ipv4) = address {
                let mapped = SocketAddr::new(ipv4.to_ipv6_mapped().into(), remote.port());
                let (mapped, reused, _peer) = connect(&endpoints, literal(mapped), &server).await;
                assert_eq!(mapped.remote_address(), remote);
                assert_eq!(reused.local_addr().unwrap(), local);
                mapped.close(0u32.into(), b"done");
            }

            let mut bindings = ConfigSet::default();
            dialer::set_local_address(&mut bindings, Some(address));
            let localhost = request(Uri::from_static("https://localhost/"), bindings);
            let (bound, isolated, _bound_peer) = connect(&endpoints, localhost, &server).await;
            let isolated = isolated.local_addr().unwrap();
            assert_eq!(isolated.ip(), address);
            assert_ne!(isolated.port(), local.port());
            let slot = if address.is_ipv4() {
                &endpoints.slots.ipv4
            } else {
                &endpoints.slots.ipv6
            };
            assert_eq!(current(slot).local_addr().unwrap(), local);
            for connection in [first, second, bound] {
                connection.close(0u32.into(), b"done");
            }
        }
    }

    #[tokio::test]
    async fn bindings_merged_to_the_client_share_its_endpoints() {
        let (server_config, cert) = test_server_config();
        let server = Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut client = ConfigSet::default();
        dialer::set_local_addresses(
            &mut client,
            Some(Ipv4Addr::LOCALHOST),
            Some(Ipv6Addr::LOCALHOST),
        );
        let endpoints = endpoints_with(
            resolving(vec![server.local_addr().unwrap()]),
            &cert,
            client.clone(),
            None,
        );
        let uri = Uri::from_static("https://localhost/");
        let request = |config_set: ConfigSet| {
            ConnectRequest::new(&uri, None, crate::Protocol::Auto, config_set, &client).unwrap()
        };
        let (first, shared, _peer) =
            connect(&endpoints, request(ConfigSet::default()), &server).await;
        assert_eq!(shared.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);

        let mut partial = ConfigSet::default();
        partial.insert(Ipv4Addr::LOCALHOST);
        let partial = request(partial);
        assert!(dialer::uses_client_bindings(partial.config_set(), &client));
        let (second, reused, _peer) = connect(&endpoints, partial, &server).await;
        assert!(same_socket(&reused, &shared));
        // Changing only IPv6 still isolates an IPv4 dial from the client's endpoint.
        let mut other_family = ConfigSet::default();
        other_family.insert(Ipv6Addr::UNSPECIFIED);
        let (third, isolated, _peer) = connect(&endpoints, request(other_family), &server).await;
        assert!(!same_socket(&isolated, &shared));
        assert_eq!(isolated.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        assert!(same_socket(&current(&endpoints.slots.ipv4), &shared));
        for connection in [first, second, third] {
            connection.close(0u32.into(), b"done");
        }
    }

    #[tokio::test]
    async fn failed_handshakes_keep_the_shared_endpoint() {
        let (server_config, cert) = test_server_config();
        let server4 =
            ::quic::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr4 = server4.local_addr().unwrap();
        let mut endpoints = endpoints(resolving(vec![addr4]), &cert);
        let (first, endpoint4, _first_peer) = connect(&endpoints, literal(addr4), &server4).await;

        // Invalid key shares fail in the SSL callback, which the QUIC stack reports like a
        // stopped driver. The TLS error must surface without opening another socket, which a
        // TEST-NET binding refuses (https://www.rfc-editor.org/rfc/rfc5737).
        let invalid = crate::quic::QuicOptions::builder()
            .curves_list("X25519")
            .key_shares(vec![crate::tls::KeyShare::P256])
            .build();
        // Client bindings belong to the dialer, so the attempt runs on one bound to TEST-NET.
        fn rebind(endpoints: &mut Endpoints, config_set: ConfigSet) {
            let dialer = &mut endpoints.dialer;
            *dialer = Dialer::new(
                dialer.runtime().clone(),
                dialer.resolver().clone(),
                tcp::Config::default(),
                config_set,
                None,
            );
        }
        let mut testnet = ConfigSet::default();
        testnet.insert(Ipv4Addr::new(192, 0, 2, 1));
        rebind(&mut endpoints, testnet);
        let error = endpoints.connect(&configured(invalid)).await.err().unwrap();
        rebind(&mut endpoints, ConfigSet::default());
        let mut chain = std::iter::successors(
            Some(&*error as &(dyn std::error::Error + 'static)),
            |error| error.source(),
        );
        assert!(
            chain.any(|error| error.is::<btls::error::ErrorStack>()),
            "{error:?}"
        );
        assert!(same_socket(&current(&endpoints.slots.ipv4), &endpoint4));

        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let timed_out = DeadlineLayer::new(
            Some(Duration::from_millis(30)),
            endpoints.dialer().runtime().clone(),
        )
        .layer(service_fn(|TransportRequest { request, .. }| {
            let endpoints = &endpoints;
            async move { endpoints.connect(&request).await }
        }))
        .oneshot(literal(blackhole.local_addr().unwrap()))
        .await
        .err()
        .unwrap();
        assert!(timed_out.is::<crate::error::TimedOut>());
        assert!(first.close_reason().is_none());

        let (after, reused4, _after_peer) = connect(&endpoints, literal(addr4), &server4).await;
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
        let (config, cert) = test_server_config();
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
        let endpoints = endpoints(resolving(vec![address.recv().unwrap()]), &cert);
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let connect = || {
            let runtime = runtime();
            let request = request(Uri::from_static("https://localhost/"), ConfigSet::default());
            let (connection, endpoint) = runtime
                .block_on(endpoints.connect(&request))
                .unwrap()
                .transport
                .into_quic()
                .unwrap();
            connection.close(0u32.into(), b"done");
            endpoint.local_addr().unwrap()
        };
        let local = [connect(), connect()];
        assert_ne!(local[0], local[1]);
        assert_eq!(
            current(&endpoints.slots.ipv4).local_addr().unwrap(),
            local[1]
        );

        // The comparison with the slot's endpoint cannot tell a stale endpoint without an
        // address apart, so it must still be replaced rather than retried forever.
        let hidden = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stale = runtime().block_on(async {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            let socket = Hidden(
                endpoints.dialer().runtime().udp_socket(socket).unwrap(),
                hidden.clone(),
            );
            Endpoint::new_with_abstract_socket(
                endpoint_config(),
                None,
                Box::new(socket),
                endpoints.dialer().runtime().quic(),
            )
            .unwrap()
        });
        hidden.store(true, Ordering::SeqCst);
        *endpoints.slots.ipv4.lock() = Some(stale);
        let replaced = connect();
        assert_eq!(
            current(&endpoints.slots.ipv4).local_addr().unwrap(),
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

        let (mut config, cert) = test_server_config();
        let mut validation = ::quic::ValidationTokenConfig::default();
        validation
            .sent(TOKENS_PER_KEY as u32)
            .log(Arc::new(AcceptAll));
        config.validation_token_config(validation);
        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let endpoints = endpoints(resolving(vec![server.local_addr().unwrap()]), &cert);
        let request = |group: &'static str| configured(crate::group::Group::new(group));

        let key = request("first").key();
        let received = |endpoints: &Endpoints| {
            endpoints
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
                    while received(&endpoints) < TOKENS_PER_KEY {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the first connection must receive its tokens");
            }
            let target = request(group);
            let attempt = async {
                tokio::join!(endpoints.connect(&target), async {
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
    async fn applies_request_transport_options() {
        let (config, cert) = test_server_config();
        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let endpoints = endpoints(resolving(vec![server.local_addr().unwrap()]), &cert);

        // The negotiated idle timeout is the lower of both peers' values.
        let options = crate::quic::QuicOptions::builder()
            .max_idle_timeout(Duration::from_millis(200))
            .build();
        let (_client, _endpoint, accepted) =
            connect(&endpoints, configured(options), &server).await;
        let error = tokio::time::timeout(Duration::from_secs(5), accepted.closed())
            .await
            .unwrap();
        assert!(
            matches!(error, ::quic::ConnectionError::TimedOut),
            "{error:?}"
        );
    }

    #[test]
    fn path_transports_fit_tunnel_packets() {
        let transport = |path: Path, options: &QuicOptions| {
            format!("{:?}", path.transport(Some(options)).unwrap())
        };
        for (size, advertised) in [(1500, 1_250_000), (65_536, 65_536)] {
            let options = QuicOptions::builder().max_datagram_frame_size(size).build();
            // The proxy's frame limit is advertised as is; only one too small for a burst is
            // replaced. A black hole reset keeps the path MTU large enough for a tunnel packet.
            let proxy = transport(Path::Proxy, &options);
            let datagrams = format!("datagram_receive_buffer_size: Some({advertised})");
            assert!(proxy.contains(&datagrams), "{proxy}");
            assert!(proxy.contains(&format!("min_mtu: {PROXY_MTU},")), "{proxy}");
            // A tunnel fixes its MTU, leaving discovery to the outer path, and keeps the rest.
            let tunnel = transport(Path::Tunnel, &options);
            let datagrams = format!("datagram_receive_buffer_size: Some({size})");
            let mtu = format!(
                "initial_mtu: {TUNNEL_MTU}, min_mtu: {TUNNEL_MTU}, mtu_discovery_config: None,"
            );
            assert!(
                tunnel.contains(&datagrams) && tunnel.contains(&mtu),
                "{tunnel}"
            );
        }
    }
}
