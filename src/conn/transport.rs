//! Shared socket bindings, address resolution and connection scheduling for transports.
//! TCP and Unix open byte streams; QUIC also manages TLS handshakes and endpoints.
//! Proxy handshakes and tunnel sockets live in [`super::layer::proxy`].
//!
//! DNS completes before racing addresses. With Happy Eyeballs enabled, families
//! alternate and attempts are staggered, with at most six active attempts.
//! If every active attempt fails, the next starts immediately; success drops pending attempts.
//! One deadline covers the whole race. Disabling racing preserves resolver order.
//!
//! See [RFC 8305 section 5](https://www.rfc-editor.org/rfc/rfc8305#section-5).

#[cfg(feature = "http3")]
mod quic;
mod socket;
mod tcp;

#[cfg(feature = "http3")]
pub(crate) use quic::{QuicConnector, TUNNEL_MTU};
pub(crate) use socket::{SocketConnector, SocketRequest};
pub(crate) use tcp::TcpConnector;
#[cfg(unix)]
pub use uds::UnixConnector;

#[cfg(unix)]
mod uds;

use std::{
    collections::VecDeque,
    error::Error as StdError,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll},
    time::Duration,
};

use futures_util::future::Either;

use crate::{
    dns::{self, DnsResolver, SocketAddrs},
    error::BoxError,
};

const MAX_PARALLEL_CONNECT_ATTEMPTS: usize = 6;

/// Timing policy shared by TCP and QUIC address attempts.
/// The timeout covers the complete race, never an individual address.
#[derive(Clone, Copy)]
pub(crate) struct ConnectOptions {
    pub(crate) timeout: Option<Duration>,
    pub(crate) happy_eyeballs_timeout: Option<Duration>,
}

/// Local addresses and interface selected for an outbound socket.
/// Missing request fields inherit the client's bindings before connection setup.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BindOptions {
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
    pub(crate) interface: Option<std::borrow::Cow<'static, str>>,
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
}

enum Event<C> {
    Connected(C),
    AllAttemptsFailed,
    DelayElapsed,
}

/// Resolves one host, preserving custom DNS ports unless the URI supplies a port.
/// IP literals bypass the resolver; brackets are stripped from IPv6 hosts.
pub(super) async fn resolve<R: DnsResolver>(
    resolver: &mut R,
    host: &str,
    port: u16,
    explicit_port: bool,
) -> Result<SocketAddrs, ConnectError> {
    let host = crate::util::strip_ipv6_brackets(host);
    if let Some(addrs) = SocketAddrs::try_parse(host, port) {
        return Ok(addrs);
    }

    let addrs = dns::resolve(resolver, dns::Name::from(host))
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

// ===== impl ConnectOptions =====

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            timeout: None,
            happy_eyeballs_timeout: Some(Duration::from_millis(300)),
        }
    }
}

impl ConnectOptions {
    /// Tries candidates using transport-specific setup and the selected clock.
    /// Setup errors and failed futures advance through addresses under one deadline.
    pub(super) async fn connect<C, F, S>(
        self,
        addrs: SocketAddrs,
        bind_options: &BindOptions,
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
        let timeout = self.timeout.map(&sleep);

        // Avoid allocating an active set when no overlapping attempts are needed.
        if self.happy_eyeballs_timeout.is_none() || addrs.len() <= 1 {
            let fut = async {
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
                            first_error.get_or_insert(error);
                        }
                    }
                }
                Err(first_error.unwrap_or_else(ConnectError::network_unreachable))
            };
            return connect_with_timeout(fut, timeout).await;
        }

        let mut race = Race {
            addr_families: addrs.split_by_preference(None, None),
            next_fallback: false,
            attempts: VecDeque::with_capacity(MAX_PARALLEL_CONNECT_ATTEMPTS),
            next_order: 0,
            first_error: None,
        };
        connect_with_timeout(
            race.connect(self.happy_eyeballs_timeout, &mut start, sleep),
            timeout,
        )
        .await
    }
}

// ===== impl BindOptions =====

impl BindOptions {
    /// Selects the interface used when opening the outbound socket.
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
    pub(crate) fn set_interface<I>(&mut self, interface: I) -> &mut Self
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        self.interface = Some(interface.into());
        self
    }

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
        if let Some(interface) = &overrides.interface {
            self.interface = Some(interface.clone());
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

/// Applies one deadline, letting a connection ready at the deadline win the tie.
async fn connect_with_timeout<C, F, S>(future: F, timeout: Option<S>) -> Result<C, ConnectError>
where
    F: Future<Output = Result<C, ConnectError>>,
    S: Future<Output = ()>,
{
    let Some(timeout) = timeout else {
        return future.await;
    };
    match futures_util::future::select(pin!(future), pin!(timeout)).await {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => Err(ConnectError::new(
            "connect timeout",
            io::Error::new(io::ErrorKind::TimedOut, "connect timeout"),
        )),
    }
}

/// Binds TCP or UDP sockets to the selected network interface.
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
pub(super) fn bind_interface(
    socket: &socket2::Socket,
    address: std::net::SocketAddr,
    interface: &str,
) -> std::io::Result<()> {
    cfg_select! {
        any(target_os = "android", target_os = "fuchsia", target_os = "linux") => {
            let _ = address;
            socket.bind_device(Some(interface.as_bytes()))
        }
        _ => {
            let interface = std::ffi::CString::new(interface)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            // SAFETY: the owned CString remains a valid NUL-terminated name for the call.
            #[allow(unsafe_code)]
            let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
            let index =
                std::num::NonZeroU32::new(index).ok_or_else(std::io::Error::last_os_error)?;
            match address {
                std::net::SocketAddr::V4(_) => socket.bind_device_by_index_v4(Some(index)),
                std::net::SocketAddr::V6(_) => socket.bind_device_by_index_v6(Some(index)),
            }
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
        bindings.set_interface("eth0");
        let inherited = bindings.clone();

        bindings.merge(&BindOptions::default());
        assert_eq!(bindings, inherited);

        bindings.merge(&BindOptions {
            ipv4_address: Some(Ipv4Addr::UNSPECIFIED),
            ..Default::default()
        });
        assert_eq!(bindings.ipv4_address, Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bindings.ipv6_address, Some(Ipv6Addr::LOCALHOST));

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
        {
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
    use tower::service_fn;

    use super::*;

    const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    const V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    const DELAY: Duration = Duration::from_millis(10);
    const OPTIONS: ConnectOptions = ConnectOptions {
        timeout: None,
        happy_eyeballs_timeout: Some(DELAY),
    };

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
            let addrs = resolve(&mut resolver, host, 443, false)
                .await
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(addrs, [expected]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for (port, explicit, expected) in [(443, false, [8443, 443]), (444, true, [444, 444])] {
            let ports = resolve(&mut resolver, "example.test", port, explicit)
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
        let error = resolve(&mut failed, "example.test", 443, false)
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
            let result = ConnectOptions {
                happy_eyeballs_timeout,
                ..OPTIONS
            }
            .connect(
                SocketAddrs::new([v4.as_slice(), v6.as_slice()].concat()),
                &BindOptions::default(),
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
        let error = OPTIONS
            .connect(
                SocketAddrs::new(vec![V4, V6]),
                &BindOptions::default(),
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
                let result = ConnectOptions {
                    happy_eyeballs_timeout,
                    ..OPTIONS
                }
                .connect(
                    SocketAddrs::new(vec![V4, V6]),
                    &bindings,
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

        let error = OPTIONS
            .connect(
                SocketAddrs::new(Vec::new()),
                &BindOptions::default(),
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
    async fn dropping_or_timing_out_the_race_cancels_pending_attempts() {
        assert!(
            connect_with_timeout(ready(Ok(())), Some(ready(())))
                .await
                .is_ok(),
            "a ready connection should win a timeout tie"
        );

        for timeout in [None, Some(DELAY * 5 / 2)] {
            let active = Arc::new(AtomicUsize::new(0));
            let mut launched = 0;
            let bindings = BindOptions::default();
            let started = tokio::time::Instant::now();
            let mut race = Box::pin(ConnectOptions { timeout, ..OPTIONS }.connect(
                SocketAddrs::new((1..=4).map(|port| SocketAddr::new(V4.ip(), port)).collect()),
                &bindings,
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
            if let Some(timeout) = timeout {
                let error = race.await.unwrap_err();
                assert_eq!(started.elapsed(), timeout);
                assert_eq!(
                    error.cause.unwrap().downcast::<io::Error>().unwrap().kind(),
                    io::ErrorKind::TimedOut
                );
                assert_eq!(launched, 3);
            } else {
                drop(race);
                assert_eq!(launched, 2);
            }
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }
}
