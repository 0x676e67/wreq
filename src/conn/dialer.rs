//! TCP and Unix socket dialing, DNS resolution, and Happy Eyeballs address racing.
//!
//! Also provides socket binding and address resolution helpers shared with QUIC.

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
    time::Duration,
};

#[cfg(unix)]
use futures_util::future::ErrInto;
use futures_util::{
    TryFutureExt,
    future::{BoxFuture, Either, select},
};
use http::Uri;
use tower::Service;

pub(super) use self::race::Race;
use crate::{
    config::ConnectConfig,
    dns::{self, DynResolver, SocketAddrs},
    error::BoxError,
    rt::{Connection, DynRuntime, Timer as _, deadline_after},
};

const CONNECT_TIMEOUT: &str = "connect timeout";

/// Target and socket options for a TCP or Unix dial.
///
/// Unix dials rely on the outer connector's timeout.
pub(super) enum Dial {
    Tcp {
        uri: Uri,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        interface: Option<Arc<str>>,
        nodelay: bool,
    },
    #[cfg(unix)]
    Unix(Arc<Path>),
}

/// Connection failure carrying a stage label, optional attempted socket address, and cause.
///
/// When `terminal` is set, [`Race`] stops trying remaining addresses and surfaces this error
/// immediately.
pub(super) struct ConnectError {
    pub(super) msg: &'static str,
    pub(super) addr: Option<SocketAddr>,
    pub(super) cause: Option<BoxError>,
    pub(super) terminal: bool,
}

/// Resolves `host` via `lookup`, keeping custom DNS ports unless `explicit_port` is set.
///
/// IP literals bypass DNS lookup; brackets are stripped from IPv6 literals.
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

/// Shared runtime, DNS resolver, TCP socket options, and race timers used by [`Dialer`].
///
/// Constructed once per client and shared across every stream and SOCKS dial attempt.
struct State {
    runtime: DynRuntime,
    resolver: DynResolver,
    config: tcp::Config,
    timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
}

/// Tower [`Service`] that opens TCP and Unix domain sockets.
///
/// Resolves hostnames, applies Happy Eyeballs racing and socket bindings, and shares client
/// dial configuration across clones.
#[derive(Clone)]
pub(super) struct Dialer {
    state: Arc<State>,
}

// ===== impl Dial =====

impl Dial {
    /// Builds a TCP dial using the effective local socket bindings.
    #[must_use]
    pub(super) fn tcp(uri: Uri, config: &ConnectConfig, nodelay: bool) -> Self {
        Self::Tcp {
            uri,
            addresses: (config.get_ref().copied(), config.get_ref().copied()),
            interface: config.get_ref().cloned(),
            nodelay,
        }
    }
}

// ===== impl Dialer =====

impl Dialer {
    /// Creates a dialer with an optional timeout for the entire TCP address race after DNS.
    #[must_use]
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        config: tcp::Config,
        timeout: Option<Duration>,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        Self {
            state: Arc::new(State {
                runtime,
                resolver,
                config,
                timeout,
                happy_eyeballs_timeout,
            }),
        }
    }

    /// Returns the client's TCP_NODELAY setting.
    #[inline]
    #[must_use]
    pub(super) fn nodelay(&self) -> bool {
        self.state.config.nodelay
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
                nodelay,
            } => {
                let nodelay = nodelay || self.state.config.nodelay;
                let state = self.state.clone();
                let future = Box::pin(async move {
                    let (host, port) = tcp::get_host_port(&uri)?;
                    let addrs = resolve(host, port, uri.port().is_some(), |name| {
                        state.resolver.resolve(name)
                    })
                    .await?;

                    let race = Race::new(state.happy_eyeballs_timeout, |duration| {
                        state.runtime.sleep(duration)
                    })
                    .run(addrs, addresses, |addr| {
                        tcp::connect(
                            &addr,
                            &state.config,
                            addresses,
                            interface.as_deref(),
                            nodelay,
                            &state.runtime,
                        )
                        .map(|future| future.map_err(ConnectError::m("tcp connect error")))
                    });

                    let result = match state.timeout {
                        Some(timeout) => {
                            let deadline = deadline_after(state.runtime.now(), timeout);
                            let sleep = state.runtime.sleep_until(deadline);
                            match select(pin!(race), sleep).await {
                                Either::Left((result, _)) => result,
                                Either::Right(_) => Err(ConnectError::timeout()),
                            }
                        }
                        None => race.await,
                    };
                    result.map_err(BoxError::from)
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
    fn timeout() -> Self {
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

    #[cfg(feature = "tokio-rt")]
    #[tokio::test(start_paused = true)]
    async fn tcp_address_race_shares_one_timeout_after_dns() {
        use std::{future::pending, net::TcpStream, sync::Mutex, time::Instant};

        use tower::ServiceExt;

        use crate::rt::{BoxSleep, Connecting, Runtime, Timer, tokio::TokioRuntime};

        const DNS_DELAY: Duration = Duration::from_millis(80);
        const RACE_TIMEOUT: Duration = Duration::from_millis(50);
        const STAGGER: Duration = Duration::from_millis(10);
        const FIRST_FAILURE: Duration = Duration::from_millis(20);
        const SECOND: SocketAddr = SocketAddr::new(V4.ip(), 444);

        struct DelayedResolver;

        impl dns::Resolve for DelayedResolver {
            fn resolve(&self, _: dns::Name) -> dns::Resolving {
                Box::pin(async {
                    tokio::time::sleep(DNS_DELAY).await;
                    Ok(Box::new([V4, SECOND].into_iter()) as dns::Addrs)
                })
            }
        }

        #[derive(Debug, Default)]
        struct PendingTcp(Mutex<Vec<SocketAddr>>);

        impl Timer for PendingTcp {
            fn sleep(&self, duration: Duration) -> BoxSleep {
                assert_eq!(duration, STAGGER, "only the address stagger is relative");
                TokioRuntime.sleep(duration)
            }

            fn sleep_until(&self, deadline: Instant) -> BoxSleep {
                TokioRuntime.sleep_until(deadline)
            }

            fn now(&self) -> Instant {
                TokioRuntime.now()
            }
        }

        impl Runtime for PendingTcp {
            fn execute(&self, future: BoxFuture<'static, ()>) {
                TokioRuntime.execute(future);
            }

            fn resolver(&self) -> Arc<dyn dns::Resolve> {
                Arc::new(DelayedResolver)
            }

            fn connect_tcp(&self, _socket: TcpStream, address: SocketAddr) -> Connecting {
                self.0.lock().unwrap().push(address);
                Box::pin(async move {
                    if address == V4 {
                        tokio::time::sleep(FIRST_FAILURE).await;
                        return Err(io::ErrorKind::ConnectionRefused.into());
                    }
                    pending().await
                })
            }
        }

        for delay in [None, Some(STAGGER)] {
            let runtime = Arc::new(PendingTcp::default());
            let dialer = Dialer::new(
                DynRuntime::new(runtime.clone()),
                DynResolver::new(runtime.resolver()),
                tcp::Config::default(),
                Some(RACE_TIMEOUT),
                delay,
            );
            let started = tokio::time::Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                dialer.oneshot(Dial::Tcp {
                    uri: Uri::from_static("https://example.test/"),
                    addresses: (None, None),
                    interface: None,
                    nodelay: false,
                }),
            )
            .await
            .expect("the dialer must enforce its own timeout");
            let error = result
                .map(drop)
                .expect_err("the address race must time out");
            let error = error.downcast::<ConnectError>().unwrap();
            assert_eq!(error.msg, CONNECT_TIMEOUT);
            assert_eq!(
                error.cause.unwrap().downcast::<io::Error>().unwrap().kind(),
                io::ErrorKind::TimedOut,
            );
            assert_eq!(*runtime.0.lock().unwrap(), [V4, SECOND]);
            assert_eq!(started.elapsed(), DNS_DELAY + RACE_TIMEOUT);
        }
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
