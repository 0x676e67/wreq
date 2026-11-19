//! Stream dialing resolves names, races addresses and applies local bindings and TCP socket
//! options. This module also provides the socket and address helpers used by QUIC.
//!
//! DNS completes before the [`Race`], and the connector's deadline covers both.

mod race;

pub(crate) mod tcp;

#[cfg(unix)]
use std::path::Path;
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[cfg(unix)]
use futures_util::future::ErrInto;
use futures_util::{
    TryFutureExt,
    future::{BoxFuture, Either, select},
};
use http::{Request, Uri};
use tower::Service;

pub(super) use self::race::Race;
use crate::{
    config::connect::ConnectConfig,
    conn::ConnectRequestExt,
    dns::{self, DynResolver, SocketAddrs},
    error::BoxError,
    rt::{Connection, DynRuntime, Timer as _},
};

const CONNECT_TIMEOUT: &str = "connect timeout";

/// A physical stream dial. Unix dials use the outer connector's deadline.
pub(super) enum Dial {
    Tcp {
        uri: Uri,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        interface: Option<Arc<str>>,
        /// Disables Nagle for this dial even when the client leaves it enabled.
        nodelay: bool,
        deadline: Option<Instant>,
    },
    #[cfg(unix)]
    Unix(Arc<Path>),
}

/// Connection failure with an optional attempted address and underlying cause.
pub(super) struct ConnectError {
    pub(super) msg: &'static str,
    pub(super) addr: Option<SocketAddr>,
    pub(super) cause: Option<BoxError>,
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

/// The runtime, resolver and client socket settings every dial shares.
struct State {
    runtime: DynRuntime,
    resolver: DynResolver,
    tcp: tcp::Config,
    happy_eyeballs_timeout: Option<Duration>,
}

/// Opens TCP and Unix sockets. Clones share the runtime, resolver and socket settings.
#[derive(Clone)]
pub(super) struct Dialer {
    state: Arc<State>,
}

// ===== impl Dial =====

impl Dial {
    /// Prepares the socket dial for `uri`, which may be a proxy rather than the origin.
    pub(super) fn tcp(request: &Request<ConnectConfig>, uri: Uri, nodelay: bool) -> Self {
        let connect_config = request.body();
        Self::Tcp {
            uri,
            addresses: (
                connect_config.get_ref::<Ipv4Addr>().copied(),
                connect_config.get_ref::<Ipv6Addr>().copied(),
            ),
            interface: connect_config.get_ref::<Arc<str>>().cloned(),
            nodelay,
            deadline: request.deadline(),
        }
    }
}

// ===== impl Dialer =====

impl Dialer {
    #[must_use]
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        tcp: tcp::Config,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        Self {
            state: Arc::new(State {
                runtime,
                resolver,
                tcp,
                happy_eyeballs_timeout,
            }),
        }
    }
}

impl Service<Dial> for Dialer {
    type Response = Box<dyn Connection>;
    type Error = BoxError;
    type Future = cfg_select! {
        unix => {
            Either<
                BoxFuture<'static, Result<Self::Response, Self::Error>>,
                ErrInto<crate::rt::Connecting, BoxError>,
            >
        }
        _ => { BoxFuture<'static, Result<Self::Response, Self::Error>> }
    };

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dial: Dial) -> Self::Future {
        match dial {
            Dial::Tcp {
                uri,
                addresses,
                interface,
                deadline,
                nodelay,
            } => {
                let nodelay = nodelay || self.state.tcp.nodelay;
                let state = self.state.clone();
                // Start the TCP connection attempt with Happy Eyeballs and deadline handling.
                let connect = async move {
                    let (host, port) = tcp::get_host_port(&uri)?;
                    let addrs = resolve(host, port, uri.port().is_some(), |name| {
                        state.resolver.resolve(name)
                    })
                    .await?;

                    Race::new(state.happy_eyeballs_timeout, |duration| {
                        state.runtime.sleep(duration)
                    })
                    .run(addrs, addresses, |addr| {
                        tcp::connect_socket(
                            &addr,
                            &state.tcp,
                            addresses,
                            interface.as_deref(),
                            nodelay,
                            &state.runtime,
                        )
                        .map(|future| future.map_err(ConnectError::m("tcp connect error")))
                    })
                    .await
                    .map_err(BoxError::from)
                };

                // Start the deadline timer if a deadline is specified.
                let sleep = deadline.map(|deadline| self.state.runtime.sleep_until(deadline));
                let future = Box::pin(async move {
                    let Some(sleep) = sleep else {
                        return connect.await;
                    };
                    // A dial that completes at the deadline wins.
                    match select(pin!(connect), sleep).await {
                        Either::Left((result, _)) => result,
                        Either::Right(_) => Err(ConnectError::timeout().into()),
                    }
                });

                cfg_select! {
                    unix => Either::Left(future),
                    _ => future,
                }
            }
            #[cfg(unix)]
            Dial::Unix(path) => Either::Right(self.state.runtime.connect_unix(path).err_into()),
        }
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
    #[must_use]
    pub(super) fn new<E: Into<BoxError>>(msg: &'static str, cause: E) -> ConnectError {
        ConnectError {
            msg,
            addr: None,
            cause: Some(cause.into()),
            terminal: false,
        }
    }

    /// Wraps a DNS resolution failure as a connection error.
    #[must_use]
    fn dns<E: Into<BoxError>>(cause: E) -> ConnectError {
        ConnectError::new("dns error", cause)
    }

    #[must_use]
    pub(super) fn timeout() -> Self {
        Self::new(CONNECT_TIMEOUT, io::Error::from(io::ErrorKind::TimedOut))
    }

    /// Returns a closure mapping an error into a [ConnectError] with msg.
    pub(super) fn m<E: Into<BoxError>>(msg: &'static str) -> impl FnOnce(E) -> ConnectError {
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
        let mut connect_config = ConnectConfig::default();
        connect_config
            .insert(Ipv4Addr::LOCALHOST)
            .insert(Ipv6Addr::LOCALHOST)
            .insert(Arc::<str>::from("lo"));
        let mut connect_config = ConnectConfig::default().with_base(&connect_config);
        assert_eq!(
            connect_config.get_ref::<Ipv4Addr>(),
            Some(&Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            connect_config.get_ref::<Ipv6Addr>(),
            Some(&Ipv6Addr::LOCALHOST)
        );
        connect_config
            .insert(Ipv4Addr::UNSPECIFIED)
            .insert_if_some(None::<Ipv6Addr>);
        assert_eq!(
            connect_config.get_ref::<Ipv4Addr>(),
            Some(&Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            connect_config.get_ref::<Ipv6Addr>(),
            Some(&Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            connect_config.get_ref::<Arc<str>>().map(Arc::as_ref),
            Some("lo")
        );
        connect_config
            .insert_if_some(None::<Ipv4Addr>)
            .insert_if_some(Some(Ipv6Addr::UNSPECIFIED))
            .insert(Arc::<str>::from("eth0"));
        assert_eq!(
            connect_config.get_ref::<Ipv4Addr>(),
            Some(&Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            connect_config.get_ref::<Ipv6Addr>(),
            Some(&Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(
            connect_config.get_ref::<Arc<str>>().map(Arc::as_ref),
            Some("eth0")
        );
    }
}
