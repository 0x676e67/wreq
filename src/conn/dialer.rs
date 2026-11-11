//! The leaf beneath both transport paths: [`Dialer`] resolves names, races addresses and applies
//! local bindings and TCP socket options; it opens TCP and Unix streams and binds the UDP sockets
//! QUIC uses.
//!
//! DNS completes before racing addresses. With Happy Eyeballs enabled, families
//! alternate and attempts are staggered, with at most six active attempts.
//! If every active attempt fails, the next starts immediately; success drops pending attempts,
//! and so does a failure that every address would repeat, such as a refused QUIC handshake.
//! The connector's deadline covers DNS and the whole race. Disabling racing preserves resolver
//! order.
//!
//! See [RFC 8305 section 5](https://www.rfc-editor.org/rfc/rfc8305#section-5).

mod tcp;

#[cfg(unix)]
use std::path::Path;
use std::{
    borrow::Cow,
    collections::VecDeque,
    error::Error as StdError,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_util::{
    TryFutureExt,
    future::{BoxFuture, Either, ErrInto},
};
use http::Uri;
pub(crate) use tcp::TcpConfig;
use tower::Service;
#[cfg(feature = "http3")]
use {
    super::request::ConnectRequest,
    socket2::{Domain, Protocol, Socket, Type},
    std::net::UdpSocket,
};

use crate::{
    dns::{self, DynResolver, SocketAddrs},
    error::BoxError,
    rt::{BoxConnection, Connecting, DynRuntime, Timer as _},
};

const MAX_PARALLEL_CONNECT_ATTEMPTS: usize = 6;

/// Reaches addresses from this host: resolves names, races addresses and applies local
/// bindings and TCP socket options. As a service it opens the TCP or Unix stream of a
/// [`SocketRequest`]; it also binds the UDP sockets QUIC uses. Clones share one state.
#[derive(Clone)]
pub(crate) struct Dialer {
    inner: Arc<Inner>,
}

/// The runtime, resolver and client socket settings every dial shares.
struct Inner {
    runtime: DynRuntime,
    resolver: DynResolver,
    tcp: TcpConfig,
    bind_options: BindOptions,
    happy_eyeballs_timeout: Option<Duration>,
}

/// A physical socket target and the request's binding policy.
/// Secure connections temporarily disable Nagle during the handshake.
#[derive(Clone)]
pub struct SocketRequest {
    pub(crate) uri: Uri,
    #[cfg(unix)]
    pub(crate) unix: Option<Arc<Path>>,
    pub(crate) bind_options: Option<Arc<BindOptions>>,
    pub(crate) secure: bool,
    /// The connect deadline. The dial fails there itself, so the connector that called it
    /// wraps the timeout like its other errors.
    pub(crate) deadline: Option<Instant>,
}

/// Local addresses and interface selected for an outbound socket.
/// Missing request fields inherit the client's bindings before connection setup.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BindOptions {
    /// Set only where interface binding is supported; see [`BindOptions::bind_interface`].
    pub(crate) interface: Option<Cow<'static, str>>,
    pub(crate) ipv4_address: Option<Ipv4Addr>,
    pub(crate) ipv6_address: Option<Ipv6Addr>,
}

/// Owns the pending candidates and active attempts for one connection race.
/// Dropping it cancels every unfinished attempt, including after a winner is selected.
struct Race<F> {
    addr_families: (SocketAddrs, SocketAddrs),
    next_fallback: bool,
    attempts: VecDeque<Attempt<F>>,
    next_order: usize,
    first_error: Option<(usize, ConnectError)>,
}

/// One active connection attempt and its launch order.
struct Attempt<F> {
    addr: SocketAddr,
    order: usize,
    future: F,
}

/// Connection failure with an optional attempted address and underlying cause.
pub struct ConnectError {
    pub(crate) msg: &'static str,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) cause: Option<BoxError>,
    /// Every other address of the host would fail the same way, so the race ends here.
    pub(super) terminal: bool,
}

enum Event<C> {
    Connected(C),
    Terminal(ConnectError),
    AllAttemptsFailed,
    DelayElapsed,
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

/// Tries candidates using transport-specific setup and the selected clock, staggered by
/// `happy_eyeballs_timeout` or one at a time without it. Bindings of one family drop the
/// other family's candidates. Setup errors and failed futures advance through addresses; a
/// terminal error ends the race at once and cancels the other attempts.
pub(super) async fn race<C, F, S>(
    addrs: SocketAddrs,
    bind_options: &BindOptions,
    happy_eyeballs_timeout: Option<Duration>,
    mut start: impl FnMut(SocketAddr) -> Result<F, ConnectError>,
    sleep: impl Fn(Duration) -> S,
) -> Result<C, ConnectError>
where
    F: Future<Output = Result<C, ConnectError>> + Unpin,
    S: Future<Output = ()>,
{
    let addrs = match (bind_options.ipv4_address, bind_options.ipv6_address) {
        (Some(_), None) => addrs.filter(SocketAddr::is_ipv4),
        (None, Some(_)) => addrs.filter(SocketAddr::is_ipv6),
        _ => addrs,
    };
    // Avoid allocating an active set when no overlapping attempts are needed.
    if happy_eyeballs_timeout.is_none() || addrs.len() <= 1 {
        let mut first_error = None;
        for addr in addrs {
            let result = match start(addr) {
                Ok(future) => future.await,
                Err(error) => Err(error),
            };
            match result {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    let error = error.with_addr(addr);
                    trace!("connect error for {}: {:?}", addr, error);
                    if error.terminal {
                        return Err(error);
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        return Err(first_error.unwrap_or_else(ConnectError::network_unreachable));
    }

    let mut race = Race {
        addr_families: addrs.split_by_preference(None, None),
        next_fallback: false,
        attempts: VecDeque::with_capacity(MAX_PARALLEL_CONNECT_ATTEMPTS),
        next_order: 0,
        first_error: None,
    };
    race.connect(happy_eyeballs_timeout, &mut start, sleep)
        .await
}

// ===== impl Dialer =====

impl Dialer {
    /// Creates a dialer with the client's socket options and bindings, racing addresses
    /// `happy_eyeballs_timeout` apart.
    pub(crate) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        tcp: TcpConfig,
        bind_options: BindOptions,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                runtime,
                resolver,
                tcp,
                bind_options,
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
    #[cfg(any(feature = "socks", feature = "http3"))]
    #[inline]
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

    /// Returns the request's bindings, or the client's when the request inherits them.
    pub(crate) fn bind_options<'a>(&'a self, request: &'a ConnectRequest) -> &'a BindOptions {
        request
            .bind_options()
            .as_deref()
            .unwrap_or(&self.inner.bind_options)
    }

    /// Binds a UDP socket for the address family of `remote` before the runtime registers it.
    pub(crate) fn bind_udp(
        &self,
        bind_options: &BindOptions,
        remote: SocketAddr,
    ) -> Result<UdpSocket, ConnectError> {
        let address = match remote {
            SocketAddr::V4(_) => SocketAddr::from((
                bind_options.ipv4_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
                0,
            )),
            SocketAddr::V6(_) => SocketAddr::from((
                bind_options.ipv6_address.unwrap_or(Ipv6Addr::UNSPECIFIED),
                0,
            )),
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
        bind_options
            .bind_interface(&socket, address)
            .map_err(ConnectError::m("quic bind interface error"))?;
        socket
            .bind(&address.into())
            .map_err(ConnectError::m("quic bind local error"))?;
        Ok(socket.into())
    }
}

impl Service<SocketRequest> for Dialer {
    type Response = BoxConnection;
    type Error = BoxError;
    // A Unix socket keeps the runtime's own boxed future.
    type Future =
        Either<BoxFuture<'static, Result<BoxConnection, BoxError>>, ErrInto<Connecting, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: SocketRequest) -> Self::Future {
        #[cfg(unix)]
        if let Some(path) = req.unix {
            return Either::Right(self.inner.runtime.connect_unix(path).err_into());
        }

        // Disable Nagle during TLS handshakes.
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        let nodelay = req.secure || self.nodelay();
        let deadline = req.deadline;
        let inner = self.inner.clone();
        let dial = async move {
            let (host, port) = tcp::get_host_port(&req.uri)?;
            let addrs = resolve(host, port, req.uri.port().is_some(), |name| {
                inner.resolver.resolve(name)
            })
            .await?;
            // Request bindings of `None` keep the client's.
            let bind_options = req.bind_options.as_deref().unwrap_or(&inner.bind_options);
            let stream = race(
                addrs,
                bind_options,
                inner.happy_eyeballs_timeout,
                |addr| {
                    tcp::connect_socket(&addr, &inner.tcp, bind_options, nodelay, &inner.runtime)
                        .map(|future| future.map_err(ConnectError::m("tcp connect error")))
                },
                |duration| inner.runtime.sleep(duration),
            )
            .await?;
            Ok(stream)
        };
        Either::Left(Box::pin(within_deadline(
            deadline,
            &self.inner.runtime,
            dial,
        )))
    }
}

// ===== impl BindOptions =====

impl BindOptions {
    pub(crate) fn set_local_address<V>(&mut self, address: V)
    where
        V: Into<Option<IpAddr>>,
    {
        match address.into() {
            Some(IpAddr::V4(address)) => self.ipv4_address = Some(address),
            Some(IpAddr::V6(address)) => self.ipv6_address = Some(address),
            None => {}
        }
    }

    pub(crate) fn set_local_addresses<V4, V6>(&mut self, ipv4: V4, ipv6: V6)
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        if let Some(address) = ipv4.into() {
            self.ipv4_address = Some(address);
        }
        if let Some(address) = ipv6.into() {
            self.ipv6_address = Some(address);
        }
    }

    /// Applies specified request fields, preserving inherited values for `None`.
    pub(crate) fn merge(&mut self, overrides: &Self) {
        self.set_local_addresses(overrides.ipv4_address, overrides.ipv6_address);
        if let Some(interface) = &overrides.interface {
            self.interface = Some(interface.clone());
        }
    }
}

// Platforms where socket2 binds a socket to an interface by name or index.
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
        impl BindOptions {
            /// Selects the interface used when opening the outbound socket.
            pub(crate) fn set_interface<I>(&mut self, interface: I) -> &mut Self
            where
                I: Into<Cow<'static, str>>,
            {
                self.interface = Some(interface.into());
                self
            }

            /// Binds a TCP or UDP socket for a peer at `address` to the selected interface, if any.
            fn bind_interface(
                &self,
                socket: &socket2::Socket,
                address: SocketAddr,
            ) -> io::Result<()> {
                let Some(interface) = self.interface.as_deref() else {
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
                        let index = std::num::NonZeroU32::new(index)
                            .ok_or_else(io::Error::last_os_error)?;
                        match address {
                            SocketAddr::V4(_) => socket.bind_device_by_index_v4(Some(index)),
                            SocketAddr::V6(_) => socket.bind_device_by_index_v6(Some(index)),
                        }
                    }
                }
            }
        }
    }
    _ => {
        impl BindOptions {
            /// This platform cannot bind an interface, so none is ever selected.
            #[inline]
            fn bind_interface(
                &self,
                _socket: &socket2::Socket,
                _address: SocketAddr,
            ) -> io::Result<()> {
                Ok(())
            }
        }
    }
}

// ===== impl Race =====

impl<C, F> Race<F>
where
    F: Future<Output = Result<C, ConnectError>> + Unpin,
{
    fn has_remaining(&self) -> bool {
        let (preferred, fallback) = &self.addr_families;
        !preferred.is_empty() || !fallback.is_empty()
    }

    fn next_addr(&mut self) -> Option<SocketAddr> {
        let (preferred, fallback) = &mut self.addr_families;
        let use_fallback = match (
            self.next_fallback,
            !preferred.is_empty(),
            !fallback.is_empty(),
        ) {
            (_, false, false) => return None,
            (true, _, true) | (_, false, true) => true,
            _ => false,
        };
        self.next_fallback = !use_fallback;
        if use_fallback {
            fallback.next()
        } else {
            preferred.next()
        }
    }

    fn record_error(&mut self, order: usize, error: ConnectError) {
        match &self.first_error {
            Some((first_order, _)) if *first_order <= order => {}
            _ => self.first_error = Some((order, error)),
        }
    }

    fn launch_next(
        &mut self,
        start: &mut impl FnMut(SocketAddr) -> Result<F, ConnectError>,
    ) -> bool {
        while let Some(addr) = self.next_addr() {
            let order = self.next_order;
            self.next_order = self.next_order.saturating_add(1);
            match start(addr) {
                Ok(future) => {
                    self.attempts.push_back(Attempt {
                        addr,
                        order,
                        future,
                    });
                    return true;
                }
                Err(error) => self.record_error(order, error.with_addr(addr)),
            }
        }
        false
    }

    fn poll_attempts(&mut self, cx: &mut Context<'_>) -> Poll<Event<C>> {
        let mut index = 0;
        let mut failed = false;
        while let Some(attempt) = self.attempts.get_mut(index) {
            let addr = attempt.addr;
            let order = attempt.order;
            match Pin::new(&mut attempt.future).poll(cx) {
                Poll::Pending => index += 1,
                Poll::Ready(result) => {
                    let _ = self.attempts.remove(index);
                    match result {
                        Ok(connection) => return Poll::Ready(Event::Connected(connection)),
                        Err(error) => {
                            let error = error.with_addr(addr);
                            trace!("connect error for {}: {:?}", addr, error);
                            if error.terminal {
                                return Poll::Ready(Event::Terminal(error));
                            }
                            self.record_error(order, error);
                            failed = true;
                        }
                    }
                }
            }
        }
        if failed && self.attempts.is_empty() {
            Poll::Ready(Event::AllAttemptsFailed)
        } else {
            Poll::Pending
        }
    }

    async fn connect<S: Future<Output = ()>>(
        &mut self,
        delay: Option<Duration>,
        start: &mut impl FnMut(SocketAddr) -> Result<F, ConnectError>,
        sleep: impl Fn(Duration) -> S,
    ) -> Result<C, ConnectError> {
        loop {
            if self.attempts.is_empty() && !self.launch_next(start) {
                return Err(self
                    .first_error
                    .take()
                    .map(|(_, error)| error)
                    .unwrap_or_else(ConnectError::network_unreachable));
            }
            let event = match (delay, self.has_remaining()) {
                (Some(delay), true) => {
                    let mut sleep = pin!(sleep(delay));
                    poll_fn(|cx| match self.poll_attempts(cx) {
                        Poll::Ready(event) => Poll::Ready(event),
                        Poll::Pending => sleep.as_mut().poll(cx).map(|()| Event::DelayElapsed),
                    })
                    .await
                }
                _ => poll_fn(|cx| self.poll_attempts(cx)).await,
            };
            match event {
                Event::Connected(connection) => return Ok(connection),
                Event::Terminal(error) => return Err(error),
                Event::AllAttemptsFailed => {}
                Event::DelayElapsed => {
                    if self.attempts.len() >= MAX_PARALLEL_CONNECT_ATTEMPTS {
                        // Dropping the oldest pending future gives later addresses a slot.
                        self.attempts.pop_front();
                    }
                }
            }
            self.launch_next(start);
        }
    }
}

// ===== impl ConnectError =====

impl ConnectError {
    pub(crate) fn new<E: Into<BoxError>>(msg: &'static str, cause: E) -> ConnectError {
        ConnectError {
            msg,
            addr: None,
            cause: Some(cause.into()),
            terminal: false,
        }
    }

    pub(crate) fn dns<E: Into<BoxError>>(cause: E) -> ConnectError {
        ConnectError::new("dns error", cause)
    }

    pub(crate) fn m<E: Into<BoxError>>(msg: &'static str) -> impl FnOnce(E) -> ConnectError {
        move |cause| ConnectError::new(msg, cause)
    }

    fn network_unreachable() -> ConnectError {
        ConnectError::new(
            "connect error",
            io::Error::new(io::ErrorKind::NotConnected, "Network unreachable"),
        )
    }

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
mod bind_tests {
    use super::*;

    #[test]
    fn bindings_merge_only_specified_fields() {
        let mut bindings = BindOptions::default();
        bindings.set_local_addresses(Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
        bindings.interface = Some("eth0".into());
        let inherited = bindings.clone();

        bindings.merge(&BindOptions::default());
        assert_eq!(bindings, inherited);

        bindings.merge(&BindOptions {
            ipv4_address: Some(Ipv4Addr::UNSPECIFIED),
            ..Default::default()
        });
        assert_eq!(bindings.ipv4_address, Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bindings.ipv6_address, Some(Ipv6Addr::LOCALHOST));
        assert_eq!(bindings.interface, inherited.interface);

        bindings.merge(&BindOptions {
            interface: Some("eth1".into()),
            ..Default::default()
        });
        assert_eq!(bindings.interface.as_deref(), Some("eth1"));
        assert_eq!(bindings.ipv4_address, Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bindings.ipv6_address, Some(Ipv6Addr::LOCALHOST));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{pending, ready},
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use futures_util::{FutureExt, poll};
    use tower::{Service, service_fn};

    use super::*;

    const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    const V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    const DELAY: Duration = Duration::from_millis(10);

    struct Active(Arc<AtomicUsize>);

    impl Active {
        fn new(active: &Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self(active.clone())
        }
    }

    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

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

    #[tokio::test(start_paused = true)]
    async fn races_addresses_with_ordered_pacing_and_bounded_concurrency() {
        let v4: Vec<_> = (1..=6).map(|port| SocketAddr::new(V4.ip(), port)).collect();
        let v6: Vec<_> = (1..=2).map(|port| SocketAddr::new(V6.ip(), port)).collect();
        let interleaved = [v4[0], v6[0], v4[1], v6[1], v4[2], v4[3], v4[4], v4[5]];
        let failed = v6[0];
        let winner = v4[5];
        for happy_eyeballs_timeout in [None, Some(DELAY)] {
            let parallel = happy_eyeballs_timeout.is_some();
            let active = Arc::new(AtomicUsize::new(0));
            let mut launched = Vec::new();
            let mut max_active = 0;
            let started = tokio::time::Instant::now();
            let result = race(
                SocketAddrs::new([v4.as_slice(), v6.as_slice()].concat()),
                &BindOptions::default(),
                happy_eyeballs_timeout,
                |addr| {
                    launched.push(addr);
                    let attempt = Active::new(&active);
                    max_active = max_active.max(active.load(Ordering::SeqCst));
                    Ok(async move {
                        let _attempt = attempt;
                        if addr == winner {
                            Ok(addr)
                        } else if parallel && addr != failed {
                            pending().await
                        } else {
                            tokio::time::sleep(if parallel { DELAY / 10 } else { DELAY / 2 }).await;
                            Err(ConnectError::new(
                                "attempt failed",
                                io::Error::from(io::ErrorKind::ConnectionRefused),
                            ))
                        }
                    }
                    .boxed())
                },
                tokio::time::sleep,
            )
            .await
            .unwrap();
            assert_eq!(result, winner);
            assert_eq!(
                started.elapsed(),
                if parallel { DELAY * 7 } else { DELAY * 5 / 2 }
            );
            assert_eq!(launched, if parallel { &interleaved[..] } else { &v4 });
            assert_eq!(max_active, if parallel { 6 } else { 1 });
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reports_the_error_of_the_first_launched_attempt() {
        let started = tokio::time::Instant::now();
        let error = race(
            SocketAddrs::new(vec![V4, V6]),
            &BindOptions::default(),
            Some(DELAY),
            |addr| {
                Ok(async move {
                    if addr == V4 {
                        tokio::time::sleep(DELAY * 3).await;
                    }
                    Err::<(), _>(ConnectError::new(
                        "attempt failed",
                        io::Error::from(io::ErrorKind::ConnectionRefused),
                    ))
                }
                .boxed())
            },
            tokio::time::sleep,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.addr,
            Some(V4),
            "launch order wins over failure completion order"
        );
        assert_eq!(started.elapsed(), DELAY * 3);
    }

    #[tokio::test(start_paused = true)]
    async fn selects_candidates_and_skips_setup_failures() {
        for happy_eyeballs_timeout in [None, Some(DELAY)] {
            for (ipv4, ipv6, expected) in [
                (None, None, V6),
                (Some(Ipv4Addr::LOCALHOST), None, V4),
                (None, Some(Ipv6Addr::LOCALHOST), V6),
            ] {
                let mut bindings = BindOptions::default();
                bindings.set_local_addresses(ipv4, ipv6);
                let mut launched = Vec::new();
                let started = tokio::time::Instant::now();
                let result = race(
                    SocketAddrs::new(vec![V4, V6]),
                    &bindings,
                    happy_eyeballs_timeout,
                    |addr| {
                        launched.push(addr);
                        if addr == expected {
                            Ok(ready(Ok(addr)))
                        } else {
                            Err(ConnectError::new(
                                "setup failed",
                                io::Error::from(io::ErrorKind::AddrNotAvailable),
                            ))
                        }
                    },
                    tokio::time::sleep,
                )
                .await
                .unwrap();
                assert_eq!(result, expected);
                assert_eq!(started.elapsed(), Duration::ZERO);
                assert_eq!(
                    launched,
                    if ipv4.is_some() || ipv6.is_some() {
                        vec![expected]
                    } else {
                        vec![V4, V6]
                    }
                );
            }
        }

        let error = race(
            SocketAddrs::new(Vec::new()),
            &BindOptions::default(),
            Some(DELAY),
            |addr| Ok(ready(Ok(addr))),
            tokio::time::sleep,
        )
        .await
        .unwrap_err();
        assert_eq!(error.addr, None);
        assert_eq!(
            error.cause.unwrap().downcast::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_race_cancels_pending_attempts() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut launched = 0;
        let bindings = BindOptions::default();
        let mut race = Box::pin(race(
            SocketAddrs::new((1..=4).map(|port| SocketAddr::new(V4.ip(), port)).collect()),
            &bindings,
            Some(DELAY),
            |_| {
                launched += 1;
                let guard = Active::new(&active);
                Ok(async move {
                    let _guard = guard;
                    pending::<Result<(), ConnectError>>().await
                }
                .boxed())
            },
            tokio::time::sleep,
        ));
        assert!(poll!(race.as_mut()).is_pending());
        tokio::time::advance(DELAY).await;
        assert!(poll!(race.as_mut()).is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 2);
        drop(race);
        assert_eq!(launched, 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
