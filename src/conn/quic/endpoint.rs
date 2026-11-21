//! QUIC endpoint management, dialing, TLS handshakes, and address validation tokens.
//!
//! Proxy routes supply virtual tunnel sockets; [`Endpoints`] runs the target QUIC
//! handshake over them using the original request's configuration and token scope.

use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    ops::Deref,
    pin::pin,
    sync::Arc,
};

use ::quic::{
    AsyncUdpSocket, ClientConfig, Connecting, Connection, ConnectionError, Endpoint,
    EndpointConfig, TokenStore, TransportConfig, TransportErrorCode,
};
use btls::x509::X509;
use bytes::Bytes;
use futures_util::future::{self, BoxFuture, Either};
use http::Uri;
use lru::LruCache;
use tower::BoxError;

use super::{Network, TUNNEL_MTU, Tunnel, URI_MISSING_HOST, bind_udp};
use crate::{
    config::ConnectConfig,
    conn::{
        Conn, Connected, HttpInfo, Request, Transport, connected::tls_info, dialer::ConnectError,
    },
    dns::SocketAddrs,
    quic::{QuicOptions, tls},
    reuse,
    rt::DynRuntime,
    sync::Mutex,
};

const ENDPOINT_ERROR: &str = "quic endpoint error";
const CONNECT_ERROR: &str = "quic connect error";
const HANDSHAKE_ERROR: &str = "quic handshake error";

/// Manages QUIC endpoints, TLS contexts, transport configs, and address validation tokens.
///
/// Connections using the client's default socket bindings share one endpoint per address
/// family; request-local bindings own dedicated endpoints kept alive by the pooled connection.
pub(super) struct Endpoints {
    tls: tls::Context,
    tls_info: bool,
    direct_transport: Arc<TransportConfig>,
    proxy_transport: Arc<TransportConfig>,
    slots: Slots,
    tokens: Arc<Tokens>,
}

/// Per-connection QUIC TLS, transport, and token configuration shared across address attempts.
///
/// Constructed once per dial before racing addresses; each attempt derives a fresh
/// [`ClientConfig`] from it so single-use resumption tickets are never shared.
pub(super) struct QuicConfig {
    tls: tls::Config,
    transport: Arc<TransportConfig>,
    tokens: Option<Arc<ScopedTokens>>,
}

/// Route type of a QUIC connection, used to select transport MTU and datagram buffer settings.
///
/// Direct and proxy paths reuse cached client transports when unoverridden; tunnel paths
/// always build a dedicated transport with MTU discovery disabled.
#[derive(Clone, Copy)]
enum Path {
    /// Direct UDP to the origin.
    Direct,
    /// Outer QUIC connection to a MASQUE proxy carrying tunneled datagrams.
    Proxy,
    /// Inner QUIC connection to the origin over a proxy tunnel.
    Tunnel,
}

/// Shared per-family UDP endpoints, bound lazily so IPv4 and IPv6 can fail independently.
///
/// Endpoints whose driver has stopped (e.g. after runtime shutdown) are replaced on demand.
#[derive(Default)]
struct Slots {
    ipv4: Mutex<Option<Endpoint>>,
    ipv6: Mutex<Option<Endpoint>>,
}

/// LRU cache of QUIC `NEW_TOKEN` address validation tokens, keyed by pool identity.
///
/// Tokens are linkable across connections, so they are only shared between requests that
/// could share a pooled connection
/// ([RFC 9000 Section 8.1.3](https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3)).
struct Tokens(Mutex<LruCache<reuse::Key, VecDeque<Bytes>>>);

/// [`TokenStore`] adapter scoped to a single pool identity.
///
/// Passed to the QUIC client config so `NEW_TOKEN` frames are stored and consumed under `key`
/// rather than by raw server hostname.
struct ScopedTokens {
    tokens: Arc<Tokens>,
    key: reuse::Key,
}

/// Outer MTU needed to carry a 1200-byte tunneled datagram: QUIC short header (1 + 20-byte
/// CID + 4), AEAD tag (16), DATAGRAM frame (9), Quarter Stream ID (8), and Context ID (1).
const PROXY_MTU: u16 = TUNNEL_MTU + 59;

/// Minimum datagram buffer for a MASQUE proxy connection (16 full tunnel packets).
///
/// The QUIC stack bounds buffered datagrams by `max_datagram_frame_size`, so a smaller
/// limit would drop bursts of tunneled packets.
const PROXY_DATAGRAM_BUFFER: u64 = 16 * PROXY_MTU as u64;

/// Maximum number of pool identities in the client's address validation token cache.
const TOKEN_KEYS: NonZeroUsize =
    NonZeroUsize::new(256).expect("token key capacity must be non-zero");

/// Maximum number of address validation tokens retained per pool identity.
const TOKENS_PER_KEY: usize = 2;

// ===== impl Endpoints =====

impl Endpoints {
    /// Initializes QUIC TLS contexts and default transport configs without opening sockets.
    pub(super) fn new(
        tls_config: crate::tls::Config,
        connect_config: &ConnectConfig,
    ) -> crate::Result<Self> {
        let tls_info = tls_config.tls_info;
        let tls = tls::Context::new(tls_config, connect_config)?;
        let options = connect_config.get_ref::<QuicOptions>();
        let direct_transport = Arc::new(Path::Direct.transport(options)?);
        let proxy_transport = Arc::new(Path::Proxy.transport(options)?);
        Ok(Self {
            tls,
            tls_info,
            direct_transport,
            proxy_transport,
            slots: Slots::default(),
            tokens: Arc::new(Tokens(Mutex::new(LruCache::sparse(TOKEN_KEYS)))),
        })
    }

    /// Opens a UDP endpoint for the address family of `remote`.
    fn open(
        runtime: &DynRuntime,
        config: &ConnectConfig,
        remote: SocketAddr,
    ) -> Result<Endpoint, ConnectError> {
        Endpoint::new(
            endpoint_config(),
            None,
            bind_udp(config, remote)?,
            runtime.quic(),
        )
        .map_err(ConnectError::m(ENDPOINT_ERROR))
    }

    /// Dials a single resolved address and returns the established connection and endpoint.
    ///
    /// Dropping the future cancels the handshake without closing shared endpoints.
    async fn connect_addr(
        runtime: &DynRuntime,
        slots: &Slots,
        quic_config: &QuicConfig,
        connect_config: &ConnectConfig,
        address: SocketAddr,
        host: &str,
    ) -> Result<(Connection, Endpoint), ConnectError> {
        let slot = if address.is_ipv4() {
            &slots.ipv4
        } else {
            &slots.ipv6
        };
        let mut endpoint = Self::endpoint(runtime, slot, connect_config, address)?;
        // Take a ticket before entering the endpoint lock. If the driver is stopped, retrying
        // reuses the same ticket since the stopped driver never sent it.
        let client = quic_config.client();
        let connect = |endpoint: &Endpoint| endpoint.connect_with(client.clone(), address, host);
        let mut connecting = connect(&endpoint);
        if driver_stopped(&connecting, &quic_config.tls) {
            (endpoint, connecting) = Self::reconnect(
                runtime,
                slot,
                &endpoint,
                connect_config,
                &quic_config.tls,
                address,
                connect,
            )?;
        }
        let connection = connecting
            .map_err(|error| {
                ConnectError::new(CONNECT_ERROR, session_error(error, &quic_config.tls))
            })?
            .await
            .map_err(handshake_error(HANDSHAKE_ERROR))?;
        Ok((connection, endpoint))
    }

    /// Retries a connection after `stale`'s endpoint driver has stopped.
    ///
    /// Reuses a healthy replacement already stored in `slot`, or opens and stores a new
    /// endpoint under the slot lock so concurrent retries share one replacement.
    fn reconnect(
        runtime: &DynRuntime,
        slot: &Mutex<Option<Endpoint>>,
        stale: &Endpoint,
        config: &ConnectConfig,
        tls: &tls::Config,
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
        let fresh = Self::open(runtime, config, address)?;
        let connecting = connect(&fresh);
        if !driver_stopped(&connecting, tls) {
            *slot = Some(fresh.clone());
        }
        Ok((fresh, connecting))
    }

    /// Returns the endpoint in `slot`, opening one when the slot is empty.
    fn endpoint(
        runtime: &DynRuntime,
        slot: &Mutex<Option<Endpoint>>,
        config: &ConnectConfig,
        remote: SocketAddr,
    ) -> Result<Endpoint, ConnectError> {
        let mut slot = slot.lock();
        if let Some(endpoint) = slot.as_ref() {
            return Ok(endpoint.clone());
        }
        let endpoint = Self::open(runtime, config, remote)?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Dials the origin directly over UDP and returns the established [`Conn`].
    pub(super) async fn connect(
        &self,
        network: &Network,
        request: Request<ConnectConfig>,
    ) -> Result<Conn, BoxError> {
        let uri = request.uri();
        let quic_config = self.config(&request, uri, Path::Direct)?;
        let connect_config = request.body();
        let shared = connect_config
            .override_if_different::<Ipv4Addr>(PartialEq::eq)
            .is_none()
            && connect_config
                .override_if_different::<Ipv6Addr>(PartialEq::eq)
                .is_none()
            && connect_config
                .override_if_different::<Arc<str>>(PartialEq::eq)
                .is_none();
        let (connection, endpoint) = self
            .dial(network, uri, shared, &quic_config, connect_config)
            .await?;
        self.connection(connection, endpoint)
    }

    /// Dials a `quic://` proxy without using shared endpoint slots or origin address tokens.
    pub(super) async fn connect_proxy(
        &self,
        network: &Network,
        request: &Request<ConnectConfig>,
        uri: &Uri,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let quic_config = self.config(request, uri, Path::Proxy)?;
        self.dial(network, uri, false, &quic_config, request.body())
            .await
    }

    /// Builds the target's [`QuicConfig`] before opening a proxy tunnel so local config
    /// errors fail fast.
    pub(super) fn tunnel_config(
        &self,
        request: &Request<ConnectConfig>,
    ) -> Result<QuicConfig, BoxError> {
        self.config(request, request.uri(), Path::Tunnel)
    }

    /// Runs the target QUIC handshake over an established UDP tunnel.
    ///
    /// When the tunnel closes, the virtual socket signals `ended`, drops sends, and leaves
    /// receives pending (avoiding driver `ERROR` logs). A background watcher closes the
    /// endpoint cleanly and exits once the endpoint becomes idle.
    pub(super) async fn finish_tunnel(
        &self,
        runtime: &DynRuntime,
        uri: &Uri,
        config: &QuicConfig,
        Tunnel {
            socket,
            remote,
            ended,
        }: Tunnel<impl AsyncUdpSocket>,
    ) -> Result<Conn, BoxError> {
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            Box::new(socket),
            runtime.quic(),
        )?;
        let host = crate::util::strip_ipv6_brackets(uri.host().ok_or(URI_MISSING_HOST)?);
        let connecting = endpoint
            .connect_with(config.client(), remote, host)
            .map_err(|error| session_error(error, &config.tls))?;

        // Started once the connection exists, so the endpoint is not idle before it ends.
        let watched = endpoint.clone();
        runtime.execute(Box::pin(async move {
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
        network: &Network,
        uri: &Uri,
        shared: bool,
        quic_config: &QuicConfig,
        connect_config: &ConnectConfig,
    ) -> Result<(Connection, Endpoint), BoxError> {
        let host = crate::util::strip_ipv6_brackets(uri.host().ok_or(URI_MISSING_HOST)?);
        let addresses = network
            .resolve(host, uri.port_u16().unwrap_or(443), uri.port().is_some())
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
        let local_addresses = (
            connect_config.get_ref::<Ipv4Addr>().copied(),
            connect_config.get_ref::<Ipv6Addr>().copied(),
        );
        Ok(network
            .race(addresses, local_addresses, |address| {
                let attempt: BoxFuture<'_, _> = Box::pin(Self::connect_addr(
                    &network.runtime,
                    slots,
                    quic_config,
                    connect_config,
                    address,
                    host,
                ));
                Ok(attempt)
            })
            .await?)
    }

    /// Builds TLS, transport, and (for origin paths) address token settings before dialing.
    fn config(
        &self,
        request: &Request<ConnectConfig>,
        peer: &Uri,
        path: Path,
    ) -> Result<QuicConfig, BoxError> {
        let origin = request.uri();
        let connect_config = request.body();
        let tls = self.tls.config(origin, peer, connect_config)?;
        let transport = self.transport(connect_config, path)?;
        let tokens = (!matches!(path, Path::Proxy)).then(|| {
            Arc::new(ScopedTokens {
                tokens: self.tokens.clone(),
                key: request.reuse_key(request.protocol()),
            })
        });
        Ok(QuicConfig {
            tls,
            transport,
            tokens,
        })
    }

    /// Selects the [`TransportConfig`] for `path`, reusing the client's cached config unless
    /// transport options are overridden. Tunnel paths always build a dedicated config.
    fn transport(&self, config: &ConnectConfig, path: Path) -> crate::Result<Arc<TransportConfig>> {
        let opts = config.override_if_different(QuicOptions::same_transport);
        match (path, opts) {
            (Path::Direct, None) => Ok(self.direct_transport.clone()),
            (Path::Proxy, None) => Ok(self.proxy_transport.clone()),
            (path, requested) => path
                .transport(requested.map(Arc::as_ref).or_else(|| config.base_ref()))
                .map(Arc::new),
        }
    }

    /// Wraps an established QUIC connection and its endpoint with socket and optional peer TLS
    /// metadata.
    fn connection(&self, connection: Connection, endpoint: Endpoint) -> Result<Conn, BoxError> {
        let mut connected = Connected::new().extra(HttpInfo {
            remote_addr: connection.remote_address(),
            local_addr: endpoint.local_addr()?,
        });
        if self.tls_info
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

// ===== impl QuicConfig =====

impl QuicConfig {
    fn client(&self) -> ClientConfig {
        let mut client = ClientConfig::new(self.tls.attempt());
        client.transport_config(self.transport.clone());
        if let Some(tokens) = &self.tokens {
            client.token_store(tokens.clone());
        }
        client
    }
}

/// Builds an [`EndpointConfig`] with a BoringSSL stateless-reset key.
///
/// Avoids `EndpointConfig::default`, which may pick another crypto provider enabled via
/// feature unification (such as dev-dependencies in tests).
fn endpoint_config() -> EndpointConfig {
    EndpointConfig::new(Arc::new(::quic::crypto::btls::HmacKey::sha256()))
}

/// Compares local addresses; a replacement binds a new port while the old socket is alive.
fn same_socket(left: &Endpoint, right: &Endpoint) -> bool {
    matches!((left.local_addr(), right.local_addr()), (Ok(left), Ok(right)) if left == right)
}

/// Returns `true` if `connecting` failed because the endpoint driver stopped (rather than
/// an SSL callback rejection, which also surfaces as `EndpointStopping`).
fn driver_stopped(
    connecting: &Result<Connecting, ::quic::ConnectError>,
    tls: &tls::Config,
) -> bool {
    matches!(connecting, Err(::quic::ConnectError::EndpointStopping)) && tls.rejected().is_none()
}

/// Unwraps a recorded SSL callback error when `error` is `EndpointStopping`.
fn session_error(error: ::quic::ConnectError, tls: &tls::Config) -> BoxError {
    match tls.rejected() {
        Some(rejected) if error == ::quic::ConnectError::EndpointStopping => {
            Box::new(rejected.clone())
        }
        _ => Box::new(error),
    }
}

/// Maps a QUIC handshake error into a [`ConnectError`], marking peer refusals as terminal
/// so the address race stops immediately.
///
/// Refusals are TLS alerts (`CRYPTO_ERROR`, [RFC 9000 Section 20.1], [RFC 9001 Section 4.8])
/// or Version Negotiation mismatches ([RFC 9000 Section 6.2]). Timeouts, resets, and other
/// closes allow the race to try remaining addresses.
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
        let mut transport = match options {
            Some(options) => {
                // A MASQUE proxy needs enough buffer space for a burst of tunnel datagrams.
                let frame_size = options
                    .max_datagram_frame_size
                    .filter(|&size| !matches!(self, Path::Proxy) || size >= PROXY_DATAGRAM_BUFFER);
                options.transport(frame_size)?
            }
            None => TransportConfig::default(),
        };
        match self {
            Path::Direct => {}
            Path::Proxy => {
                // The initial MTU and black hole recovery must fit a tunnel datagram
                // ([RFC 9298 Section 6.1](https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1)).
                transport.min_mtu(PROXY_MTU);
            }
            Path::Tunnel => {
                // The tunnel's outer path owns MTU discovery; preserve other transport options.
                transport
                    .initial_mtu(TUNNEL_MTU)
                    .min_mtu(TUNNEL_MTU)
                    .mtu_discovery_config(None);
            }
        }
        Ok(transport)
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
        net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
        time::Duration,
    };

    use http::Uri;
    use netty::http3::Http3Options;
    use tower::{Layer, ServiceExt, service_fn};

    use super::{super::State, *};
    use crate::{
        config::ConnectConfig,
        conn::{Unnameable, layer::timeout::TimeoutLayer},
        dns::{Addrs, DynResolver, Name, Resolve, Resolving},
        ext::UriExt,
        protocol::Protocol,
        reuse::Group,
        rt::tokio::TokioRuntime,
        tls::trust::CertStore,
    };

    /// Returns a QUIC server configuration for `localhost` and the loopback addresses, with its
    /// certificate in DER.
    fn test_server_config() -> (::quic::ServerConfig, Vec<u8>) {
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

    fn request(uri: Uri, connect_config: ConnectConfig) -> Request<ConnectConfig> {
        Request::new(uri.origin().unwrap(), Protocol::Http3, connect_config)
    }

    async fn connect(
        state: &Arc<State>,
        request: Request<ConnectConfig>,
        server: &::quic::Endpoint,
    ) -> (Connection, Endpoint, Connection) {
        let uri = request.uri().clone();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(state.clone().connect(request), async {
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
    fn state_with(
        resolver: Arc<dyn Resolve>,
        cert: &[u8],
        config: &ConnectConfig,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Arc<State> {
        let tls = crate::tls::Config {
            cert_store: Some(CertStore::from_der_certs([cert]).unwrap()),
            ..Default::default()
        };
        Arc::new(State {
            endpoints: Endpoints::new(tls, config).unwrap(),
            network: Network {
                runtime: DynRuntime::new(TokioRuntime),
                resolver: DynResolver::new(resolver),
                happy_eyeballs_timeout,
            },
        })
    }

    /// Returns endpoints trusting `cert` that resolve names through `resolver`. Its tests
    /// resolve one address, so no delay applies.
    fn state(resolver: Arc<dyn Resolve>, cert: &[u8]) -> Arc<State> {
        state_with(resolver, cert, &ConnectConfig::default(), None)
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

    fn literal(address: SocketAddr) -> Request<ConnectConfig> {
        request(
            format!("https://{address}/").parse().unwrap(),
            ConnectConfig::default(),
        )
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
        let state = state_with(
            resolver.clone(),
            &cert,
            &ConnectConfig::default(),
            Some(Duration::from_millis(20)),
        );
        let localhost = request(
            Uri::from_static("https://localhost/"),
            ConnectConfig::default(),
        );
        let (connection, _, _peer) = connect(&state, localhost, &server4).await;
        assert_eq!(connection.remote_address(), addr4);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        let slot = if blackhole.local_addr().unwrap().is_ipv6() {
            &state.endpoints.slots.ipv6
        } else {
            &state.endpoints.slots.ipv4
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
            let state = state_with(
                resolving(addresses.clone()),
                &cert,
                &ConnectConfig::default(),
                happy_eyeballs_timeout,
            );
            let localhost = request(
                Uri::from_static("https://localhost/"),
                ConnectConfig::default(),
            );
            let error = tokio::time::timeout(Duration::from_secs(5), state.connect(localhost))
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
            let state = state(resolver.clone(), &cert);
            let localhost = request(
                Uri::from_static("https://localhost/"),
                ConnectConfig::default(),
            );
            let (first, shared, first_peer) = connect(&state, localhost, &server).await;
            let local = shared.local_addr().unwrap();
            assert_eq!(first.remote_address(), remote);
            assert!(local.ip().is_unspecified());

            // IP literals bypass DNS while reusing the family's socket.
            let (second, reused, second_peer) = connect(&state, literal(remote), &server).await;
            assert_eq!(reused.local_addr().unwrap(), local);
            assert_eq!(first_peer.remote_address(), second_peer.remote_address());
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

            // The IPv6 socket is V6ONLY, so a v4-mapped address must use the IPv4 one.
            if let IpAddr::V4(ipv4) = address {
                let mapped = SocketAddr::new(ipv4.to_ipv6_mapped().into(), remote.port());
                let (mapped, reused, _peer) = connect(&state, literal(mapped), &server).await;
                assert_eq!(mapped.remote_address(), remote);
                assert_eq!(reused.local_addr().unwrap(), local);
                mapped.close(0u32.into(), b"done");
            }

            let mut bindings = ConnectConfig::default();
            match address {
                IpAddr::V4(address) => bindings.insert(address),
                IpAddr::V6(address) => bindings.insert(address),
            };
            let localhost = request(Uri::from_static("https://localhost/"), bindings);
            let (bound, isolated, _bound_peer) = connect(&state, localhost, &server).await;
            let isolated = isolated.local_addr().unwrap();
            assert_eq!(isolated.ip(), address);
            assert_ne!(isolated.port(), local.port());
            let slot = if address.is_ipv4() {
                &state.endpoints.slots.ipv4
            } else {
                &state.endpoints.slots.ipv6
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
        let mut connect_config = ConnectConfig::default();
        connect_config
            .insert(Ipv4Addr::LOCALHOST)
            .insert(Ipv6Addr::LOCALHOST);
        let state = state_with(
            resolving(vec![server.local_addr().unwrap()]),
            &cert,
            &connect_config,
            None,
        );
        let uri = Uri::from_static("https://localhost/");
        let request =
            |overrides: ConnectConfig| request(uri.clone(), overrides.with_base(&connect_config));
        let (first, shared, _peer) =
            connect(&state, request(ConnectConfig::default()), &server).await;
        assert_eq!(shared.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);

        let mut partial = ConnectConfig::default();
        partial.insert(Ipv4Addr::LOCALHOST);
        let (second, reused, _peer) = connect(&state, request(partial), &server).await;
        assert!(same_socket(&reused, &shared));
        // Changing only IPv6 still isolates an IPv4 dial from the client's endpoint.
        let mut other_family = ConnectConfig::default();
        other_family.insert(Ipv6Addr::UNSPECIFIED);
        let (third, isolated, _peer) = connect(&state, request(other_family), &server).await;
        assert!(!same_socket(&isolated, &shared));
        assert_eq!(isolated.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        assert!(same_socket(&current(&state.endpoints.slots.ipv4), &shared));
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
        let state = state(resolving(vec![addr4]), &cert);
        let (first, endpoint4, _first_peer) = connect(&state, literal(addr4), &server4).await;

        // Invalid key shares fail in the SSL callback, which the QUIC stack reports like a
        // stopped driver. The TLS error must surface without opening another socket, which a
        // TEST-NET binding refuses (https://www.rfc-editor.org/rfc/rfc5737).
        let invalid = crate::quic::QuicOptions::builder()
            .curves_list("X25519")
            .key_shares(vec![crate::tls::KeyShare::P256])
            .build();
        let mut testnet = ConnectConfig::default();
        testnet.insert(Ipv4Addr::new(192, 0, 2, 1));
        let mut connect_config = ConnectConfig::default().with_base(&testnet);
        connect_config.insert(invalid);
        let invalid = request(Uri::from_static("https://localhost/"), connect_config);
        let error = state.clone().connect(invalid).await.err().unwrap();
        let mut chain = std::iter::successors(
            Some(&*error as &(dyn std::error::Error + 'static)),
            |error| error.source(),
        );
        assert!(
            chain.any(|error| error.is::<btls::error::ErrorStack>()),
            "{error:?}"
        );
        assert!(same_socket(
            &current(&state.endpoints.slots.ipv4),
            &endpoint4
        ));

        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let request = literal(blackhole.local_addr().unwrap());
        let timed_out = TimeoutLayer::new(
            Some(Duration::from_millis(30)),
            state.network.runtime.clone(),
        )
        .layer(service_fn(|Unnameable(request)| {
            state.clone().connect(request)
        }))
        .oneshot(Unnameable(request))
        .await
        .err()
        .unwrap();
        assert!(timed_out.is::<crate::error::TimedOut>());
        assert!(first.close_reason().is_none());

        let (after, reused4, _after_peer) = connect(&state, literal(addr4), &server4).await;
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
        let state = state(resolving(vec![address.recv().unwrap()]), &cert);
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let connect = || {
            let runtime = runtime();
            let request = request(
                Uri::from_static("https://localhost/"),
                ConnectConfig::default(),
            );
            let (connection, endpoint) = runtime
                .block_on(state.clone().connect(request))
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
            current(&state.endpoints.slots.ipv4).local_addr().unwrap(),
            local[1]
        );

        // The comparison with the slot's endpoint cannot tell a stale endpoint without an
        // address apart, so it must still be replaced rather than retried forever.
        let hidden = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stale = runtime().block_on(async {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            let socket = Hidden(
                state.network.runtime.udp_socket(socket).unwrap(),
                hidden.clone(),
            );
            Endpoint::new_with_abstract_socket(
                endpoint_config(),
                None,
                Box::new(socket),
                state.network.runtime.quic(),
            )
            .unwrap()
        });
        hidden.store(true, Ordering::SeqCst);
        *state.endpoints.slots.ipv4.lock() = Some(stale);
        let replaced = connect();
        assert_eq!(
            current(&state.endpoints.slots.ipv4).local_addr().unwrap(),
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
        let state = state(resolving(vec![server.local_addr().unwrap()]), &cert);
        let request = |group, http3| {
            let mut connect_config = ConnectConfig::default();
            connect_config.insert(Group::new(group));
            if let Some(options) = http3 {
                connect_config.insert(options);
            }
            request(Uri::from_static("https://localhost/"), connect_config)
        };

        let first = request("first", None);
        let key = first.reuse_key(first.protocol());
        let received = |state: &State| {
            state
                .endpoints
                .tokens
                .0
                .lock()
                .peek(&key)
                .map_or(0, VecDeque::len)
        };
        let mut connections = Vec::new();
        let http3 = Http3Options::builder().max_field_section_size(1024).build();
        for (group, http3, validated) in [
            ("first", None, false),
            ("first", None, true),
            ("first", Some(http3), false),
            ("second", None, false),
        ] {
            if validated {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while received(&state) < TOKENS_PER_KEY {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the first connection must receive its tokens");
            }
            let has_http3 = http3.is_some();
            let target = request(group, http3);
            let attempt = async {
                tokio::join!(state.clone().connect(target), async {
                    let incoming = server.accept().await.unwrap();
                    let presented = incoming.remote_address_validated();
                    (presented, incoming.await.unwrap())
                })
            };
            let (client, (presented, accepted)) =
                tokio::time::timeout(Duration::from_secs(5), attempt)
                    .await
                    .expect("token connection timed out");
            assert_eq!(
                presented, validated,
                "{group}, HTTP/3 override: {has_http3}"
            );
            connections.push((client.unwrap(), accepted));
        }
    }

    #[tokio::test]
    async fn applies_request_transport_options() {
        let (config, cert) = test_server_config();
        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut connect_config = ConnectConfig::default();
        connect_config.insert(QuicOptions::default());
        let state = state_with(
            resolving(vec![server.local_addr().unwrap()]),
            &cert,
            &connect_config,
            None,
        );
        let uri = Uri::from_static("https://localhost/");
        let request = |options| {
            let mut overrides = ConnectConfig::default().with_base(&connect_config);
            overrides.insert(options);
            request(uri.clone(), overrides)
        };

        let tls_only = request(QuicOptions::builder().curves_list("X25519").build());
        assert!(
            Arc::ptr_eq(
                &state
                    .endpoints
                    .transport(tls_only.body(), Path::Direct)
                    .unwrap(),
                &state.endpoints.direct_transport
            ),
            "TLS options alone must reuse the client's transport"
        );

        // The negotiated idle timeout is the lower of both peers' values.
        let options = QuicOptions::builder()
            .max_idle_timeout(Duration::from_millis(200))
            .build();
        let (_client, _endpoint, accepted) = connect(&state, request(options), &server).await;
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
