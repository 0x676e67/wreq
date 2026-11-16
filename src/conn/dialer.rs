//! The leaf beneath both transport paths: [`Dialer`] resolves names, races addresses and applies
//! local bindings and TCP socket options; it opens TCP and Unix streams and binds the UDP sockets
//! QUIC uses.
//!
//! DNS completes before the [`race()`], and the connector's deadline covers both.

mod race;

pub(crate) mod tcp;

#[cfg(unix)]
use std::path::Path;
use std::{
    borrow::Cow,
    error::Error as StdError,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::Either};
use http::Uri;
#[cfg(feature = "http3")]
use {
    socket2::{Domain, Protocol, Socket, Type},
    std::net::UdpSocket,
};

pub(super) use self::race::race;
use super::request::ConnectRequest;
use crate::{
    config::connect::{ConnectConfig, ConnectConfigRef, impl_connect_extension},
    dns::{self, DynResolver, SocketAddrs},
    error::BoxError,
    ext::UriExt,
    rt::{BoxConnection, DynRuntime, Timer as _},
};

/// Reaches addresses from this host: resolves names, races addresses and applies local
/// bindings and TCP socket options. It also opens Unix streams and binds UDP sockets for QUIC.
#[derive(Clone)]
pub(crate) struct Dialer {
    inner: Arc<Inner>,
}

/// The runtime, resolver and client socket settings every dial shares.
struct Inner {
    runtime: DynRuntime,
    resolver: DynResolver,
    tcp: tcp::Config,
    #[cfg(feature = "http3")]
    bindings: SocketBindings,
    happy_eyeballs_timeout: Option<Duration>,
}

/// Effective local IP addresses and network interface for dialing a socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SocketBindings {
    pub(crate) ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub(crate) interface: Option<Interface>,
}

/// A physical socket destination. TCP settings apply to the dialed hop.
pub(super) enum SocketRequest {
    /// Connects to a TCP host with request-scoped bindings and deadline.
    Tcp {
        /// Target authority and port to resolve and dial.
        uri: Uri,
        /// Keeps TCP_NODELAY enabled through any TLS on this socket, including tunneled TLS.
        secure: bool,
        /// Lets the dial report its own timeout before the outer connector does.
        deadline: Option<Instant>,
        /// Effective socket bindings for this connection.
        bindings: SocketBindings,
    },
    /// Connects directly to a Unix domain socket path.
    #[cfg(unix)]
    Unix(Arc<Path>),
}

/// The interface name participates in reuse identity by value, regardless of ownership.
#[derive(Clone, Debug)]
pub(crate) enum Interface {
    Static(&'static str),
    Shared(Arc<str>),
}

/// Connection failure with an optional attempted address and underlying cause.
pub struct ConnectError {
    pub(crate) msg: &'static str,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) cause: Option<BoxError>,
    pub(super) terminal: bool,
}

/// Resolves one host through `lookup`, preserving custom DNS ports unless the URI supplies a
/// port. IP literals bypass the lookup; brackets are stripped from IPv6 hosts.
pub(super) async fn resolve<F, A, E>(
    host: &str,
    port: u16,
    explicit_port: bool,
    lookup: impl FnOnce(dns::Name) -> F,
) -> Result<SocketAddrs, ConnectError>
where
    F: Future<Output = Result<A, E>>,
    A: Iterator<Item = SocketAddr>,
    E: Into<BoxError>,
{
    let host = crate::util::strip_ipv6_brackets(host);
    if let Some(addrs) = SocketAddrs::try_parse(host, port) {
        return Ok(addrs);
    }

    let addrs = lookup(dns::Name::from(host))
        .await
        .map_err(ConnectError::dns)?;
    Ok(SocketAddrs::new(
        addrs
            .map(|mut addr| {
                if explicit_port || addr.port() == 0 {
                    addr.set_port(port);
                }
                addr
            })
            .collect(),
    ))
}

/// Runs a dial until the connect deadline. Expiry fails the dial itself, so the connector that
/// dialed wraps the timeout like its other errors: a proxy connector reports a proxy failure.
pub(super) fn within_deadline<T, F>(
    deadline: Option<Instant>,
    runtime: &DynRuntime,
    dial: F,
) -> impl Future<Output = Result<T, BoxError>> + use<T, F>
where
    F: Future<Output = Result<T, BoxError>>,
{
    let sleep = deadline.map(|deadline| runtime.sleep_until(deadline));
    async move {
        let Some(sleep) = sleep else {
            return dial.await;
        };
        // The dial is polled first, so one that completes at the deadline still wins.
        match futures_util::future::select(pin!(dial), sleep).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(ConnectError::new(
                "connect timeout",
                io::Error::from(io::ErrorKind::TimedOut),
            )
            .into()),
        }
    }
}

// ===== impl Dialer =====

impl Dialer {
    /// Creates a dialer with the client's socket options and Happy Eyeballs delay.
    /// QUIC uses the client's bindings to decide whether a request can share a UDP socket.
    pub(crate) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        tcp: tcp::Config,
        #[cfg(feature = "http3")] bindings: SocketBindings,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                runtime,
                resolver,
                tcp,
                #[cfg(feature = "http3")]
                bindings,
                happy_eyeballs_timeout,
            }),
        }
    }

    /// Returns whether the client disables Nagle.
    #[inline]
    pub(crate) fn nodelay(&self) -> bool {
        self.inner.tcp.nodelay
    }

    /// Returns the resolver for names that SOCKS routes and QUIC dials resolve locally.
    #[inline]
    #[cfg(any(feature = "socks", feature = "http3"))]
    pub(crate) fn resolver(&self) -> &DynResolver {
        &self.inner.resolver
    }
}

#[cfg(feature = "http3")]
impl Dialer {
    /// Returns the runtime that drives QUIC endpoints, tunnels and timers.
    #[inline]
    pub(crate) fn runtime(&self) -> &DynRuntime {
        &self.inner.runtime
    }

    /// Returns the Happy Eyeballs delay for QUIC and SOCKS5 target races.
    #[inline]
    pub(crate) fn happy_eyeballs_timeout(&self) -> Option<Duration> {
        self.inner.happy_eyeballs_timeout
    }

    /// Returns whether `bindings` matches the client's shared QUIC endpoints.
    /// All fields must match, including the address family this dial does not use.
    #[inline]
    pub(crate) fn uses_client_bindings(&self, bindings: &SocketBindings) -> bool {
        bindings == &self.inner.bindings
    }

    /// Binds a UDP socket for the address family of `remote` before the runtime registers it.
    pub(crate) fn bind_udp(
        &self,
        bindings: &SocketBindings,
        remote: SocketAddr,
    ) -> Result<UdpSocket, ConnectError> {
        let (ipv4, ipv6) = bindings.addresses();
        let interface = bindings.interface();
        let address = match remote {
            SocketAddr::V4(_) => SocketAddr::from((ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)),
            SocketAddr::V6(_) => SocketAddr::from((ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED), 0)),
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
        bind_interface(&socket, address, interface)
            .map_err(ConnectError::m("quic bind interface error"))?;
        socket
            .bind(&address.into())
            .map_err(ConnectError::m("quic bind local error"))?;
        Ok(socket.into())
    }
}

impl Dialer {
    /// Returns a future that owns its dial state and can outlive the dialer borrow.
    /// TCP dials arm the supplied absolute deadline before polling DNS.
    pub(super) fn dial(
        &self,
        request: SocketRequest,
    ) -> impl Future<Output = Result<BoxConnection, BoxError>> + use<> {
        match request {
            SocketRequest::Tcp {
                uri,
                secure,
                deadline,
                bindings,
            } => {
                let dial = self.dial_tcp(uri, secure, deadline, bindings);
                cfg_select! {
                    unix => Either::Left(dial),
                    _ => dial,
                }
            }
            #[cfg(unix)]
            SocketRequest::Unix(path) => {
                Either::Right(self.inner.runtime.connect_unix(path).err_into())
            }
        }
    }

    /// Resolves the host and races its addresses until the request's deadline.
    fn dial_tcp(
        &self,
        uri: Uri,
        secure: bool,
        deadline: Option<Instant>,
        bindings: SocketBindings,
    ) -> impl Future<Output = Result<BoxConnection, BoxError>> + use<> {
        // Disable Nagle during TLS handshakes.
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        let nodelay = secure || self.nodelay();
        let inner = self.inner.clone();
        let dial = async move {
            let (host, port) = tcp::get_host_port(&uri)?;
            let addrs = resolve(host, port, uri.port().is_some(), |name| {
                inner.resolver.resolve(name)
            })
            .await?;
            let addresses = bindings.addresses();
            let interface = bindings.interface();
            let stream = race(
                addrs,
                addresses,
                inner.happy_eyeballs_timeout,
                |addr| {
                    tcp::connect_socket(
                        &addr,
                        &inner.tcp,
                        addresses,
                        interface,
                        nodelay,
                        &inner.runtime,
                    )
                    .map(|future| future.map_err(ConnectError::m("tcp connect error")))
                },
                |duration| inner.runtime.sleep(duration),
            )
            .await?;
            Ok(stream)
        };
        within_deadline(deadline, &self.inner.runtime, dial)
    }
}

// ===== impl SocketRequest =====

impl SocketRequest {
    /// Builds a TCP dial request, keeping `TCP_NODELAY` enabled across any TLS on the
    /// connection or the proxy hop itself.
    pub(super) fn tcp(
        request: &ConnectRequest,
        uri: Uri,
        bindings: SocketBindings,
        deadline: Option<Instant>,
    ) -> Self {
        Self::Tcp {
            secure: request.uri().is_https() || uri.is_https(),
            uri,
            deadline,
            bindings,
        }
    }
}

// ===== impl SocketBindings =====

impl SocketBindings {
    /// Resolves each binding independently. Explicit unspecified addresses still select a family.
    pub(crate) fn from_config(config: ConnectConfigRef<'_>) -> Self {
        Self {
            ipv4: config.get_ref::<Ipv4Addr>().copied(),
            ipv6: config.get_ref::<Ipv6Addr>().copied(),
            interface: config.get_ref::<Interface>().cloned(),
        }
    }

    /// Returns the `(ipv4, ipv6)` local source addresses.
    #[inline]
    pub(crate) fn addresses(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        (self.ipv4, self.ipv6)
    }

    /// Borrows the bound network interface name, if configured.
    #[inline]
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_ref().map(Interface::as_str)
    }
}

// ===== impl Interface =====

impl Interface {
    /// Borrows the interface name as a string slice.
    fn as_str(&self) -> &str {
        match self {
            Self::Static(name) => name,
            Self::Shared(name) => name,
        }
    }
}

impl From<Cow<'static, str>> for Interface {
    fn from(name: Cow<'static, str>) -> Self {
        match name {
            Cow::Borrowed(name) => Self::Static(name),
            Cow::Owned(name) => Self::Shared(Arc::from(name)),
        }
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Interface {}

impl Hash for Interface {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl_connect_extension!(Ipv4Addr, Ipv6Addr, Interface);

/// Sets one local address family without clearing the other.
/// Passing `None` leaves both families unchanged.
pub(crate) fn set_local_address(config: &mut ConnectConfig, address: Option<IpAddr>) {
    match address {
        Some(IpAddr::V4(address)) => {
            config.insert(address);
        }
        Some(IpAddr::V6(address)) => {
            config.insert(address);
        }
        None => {}
    }
}

/// Sets the supplied local address families; each `None` leaves its earlier value intact.
pub(crate) fn set_local_addresses(
    config: &mut ConnectConfig,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) {
    if let Some(address) = ipv4 {
        config.insert(address);
    }
    if let Some(address) = ipv6 {
        config.insert(address);
    }
}

cfg_select! {
    any(
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
    ) => {
        /// Selects the interface name stored in this connection configuration.
        pub(crate) fn set_interface(config: &mut ConnectConfig, interface: Cow<'static, str>) {
            config.insert(Interface::from(interface));
        }

        /// Applies the selected interface before binding or connecting the socket.
        pub(super) fn bind_interface(
            socket: &socket2::Socket,
            address: SocketAddr,
            interface: Option<&str>,
        ) -> io::Result<()> {
            let Some(interface) = interface else {
                return Ok(());
            };
            cfg_select! {
                any(target_os = "android", target_os = "fuchsia", target_os = "linux") => {
                    let _ = address;
                    socket.bind_device(Some(interface.as_bytes()))
                }
                _ => {
                    let interface = std::ffi::CString::new(interface)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                    // SAFETY: the owned CString is NUL-terminated and outlives the call.
                    #[allow(unsafe_code)]
                    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
                    let index =
                        std::num::NonZeroU32::new(index).ok_or_else(io::Error::last_os_error)?;
                    match address {
                        SocketAddr::V4(_) => socket.bind_device_by_index_v4(Some(index)),
                        SocketAddr::V6(_) => socket.bind_device_by_index_v6(Some(index)),
                    }
                }
            }
        }
    }
    _ => {
        /// Unsupported platforms have no public interface selector.
        pub(super) fn bind_interface(
            _socket: &socket2::Socket,
            _address: SocketAddr,
            _interface: Option<&str>,
        ) -> io::Result<()> {
            Ok(())
        }
    }
}

// ===== impl ConnectError =====

impl ConnectError {
    /// Creates a connection error with a static context message and underlying cause.
    pub(crate) fn new<E: Into<BoxError>>(msg: &'static str, cause: E) -> ConnectError {
        ConnectError {
            msg,
            addr: None,
            cause: Some(cause.into()),
            terminal: false,
        }
    }

    /// Wraps a DNS resolution failure as a connection error.
    pub(crate) fn dns<E: Into<BoxError>>(cause: E) -> ConnectError {
        ConnectError::new("dns error", cause)
    }

    /// Returns a closure mapping an error into a [ConnectError] with msg.
    pub(crate) fn m<E: Into<BoxError>>(msg: &'static str) -> impl FnOnce(E) -> ConnectError {
        move |cause| ConnectError::new(msg, cause)
    }

    /// Constructs a NotConnected error when no resolved address can be dialed.
    fn network_unreachable() -> ConnectError {
        ConnectError::new(
            "connect error",
            io::Error::new(io::ErrorKind::NotConnected, "Network unreachable"),
        )
    }

    /// Attaches the peer socket address attempted when the error occurred.
    fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }
}

impl fmt::Debug for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = f.debug_tuple("ConnectError");
        b.field(&self.msg);
        if let Some(ref addr) = self.addr {
            b.field(addr);
        }
        if let Some(ref cause) = self.cause {
            b.field(cause);
        }
        b.finish()
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl StdError for ConnectError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause.as_ref().map(|e| &**e as _)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::ready,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use tower::{Service, service_fn};

    use super::*;

    const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    const V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);

    #[tokio::test]
    async fn resolves_literals_and_preserves_dns_port_contract() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut resolver = service_fn(move |name: dns::Name| {
            observed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name.as_str(), "example.test");
            ready(Ok::<_, io::Error>(
                vec![
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)),
                    SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
                ]
                .into_iter(),
            ))
        });
        for (host, expected) in [("127.0.0.1", V4), ("[::1]", V6)] {
            let addrs = resolve(host, 443, false, |name| resolver.call(name))
                .await
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(addrs, [expected]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for (port, explicit, expected) in [(443, false, [8443, 443]), (444, true, [444, 444])] {
            let ports = resolve("example.test", port, explicit, |name| resolver.call(name))
                .await
                .unwrap()
                .map(|addr| addr.port())
                .collect::<Vec<_>>();
            assert_eq!(ports, expected);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let mut failed = service_fn(|_: dns::Name| {
            ready(Err::<std::vec::IntoIter<SocketAddr>, _>(io::Error::from(
                io::ErrorKind::NotFound,
            )))
        });
        let error = resolve("example.test", 443, false, |name| failed.call(name))
            .await
            .err()
            .unwrap();
        assert_eq!(error.msg, "dns error");
        assert_eq!(
            error.cause.unwrap().downcast::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn bindings_inherit_only_unspecified_fields() {
        let mut client_config = ConnectConfig::default();
        set_local_addresses(
            &mut client_config,
            Some(Ipv4Addr::LOCALHOST),
            Some(Ipv6Addr::LOCALHOST),
        );
        client_config.insert(Interface::Static("lo"));
        let mut request_config = ConnectConfig::default();
        assert_eq!(
            SocketBindings::from_config(ConnectConfigRef::new(&request_config, &client_config))
                .addresses(),
            (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST))
        );
        set_local_address(&mut request_config, Some(Ipv4Addr::UNSPECIFIED.into()));
        set_local_address(&mut request_config, None);
        set_local_addresses(&mut request_config, None, Some(Ipv6Addr::UNSPECIFIED));
        set_local_addresses(&mut request_config, None, None);
        let bindings =
            SocketBindings::from_config(ConnectConfigRef::new(&request_config, &client_config));
        assert_eq!(
            bindings.addresses(),
            (Some(Ipv4Addr::UNSPECIFIED), Some(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(bindings.interface(), Some("lo"));
        request_config.insert(Interface::Static("eth0"));
        assert_eq!(
            SocketBindings::from_config(ConnectConfigRef::new(&request_config, &client_config))
                .interface(),
            Some("eth0")
        );
    }
}
