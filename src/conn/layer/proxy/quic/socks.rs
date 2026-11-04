//! Establishes SOCKS5 UDP associations and carries target QUIC datagrams through them.
//! The control stream remains open for the socket and its senders, as required by
//! [RFC 1928 Section 7](https://www.rfc-editor.org/rfc/rfc1928#section-7).

use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use ::quic::{
    AsyncUdpSocket, UdpSender,
    udp::{RecvMeta, Transmit},
};
use futures_util::future::BoxFuture;
use netty::proxy::socks::udp::{self, Address, AddressRef, UdpAssociation};
use pin_project_lite::pin_project;
use tokio::sync::{Notify, futures::OwnedNotified};
use tower::{BoxError, ServiceExt};

use crate::{
    conn::{
        Conn,
        request::ConnectRequest,
        transport::{self, BindOptions, ConnectError, ConnectOptions, QuicConnector, TcpConnector},
    },
    dns::DynResolver,
    error::ProxyConnect,
    proxy::matcher::Intercept,
    rt::{BoxConnection, Timer},
    sync::Mutex,
};

/// One association exposed as a fixed-peer socket to the inner QUIC endpoint.
/// Only the receive driver polls the control stream, so senders cannot replace its waker.
struct Socket {
    inner: Box<dyn AsyncUdpSocket>,
    shared: Arc<Shared>,
    local: SocketAddr,
    relay: SocketAddr,
    scratch: Vec<u8>,
    received: RecvMeta,
    offset: usize,
}

struct Shared {
    association: Mutex<Option<UdpAssociation<BoxConnection>>>,
    target: Address,
    header: Vec<u8>,
    closed: AtomicBool,
    notify: Arc<Notify>,
}

pin_project! {
    /// Retains one reusable frame and independent UDP readiness and closure registrations.
    struct SocketSender {
        inner: Pin<Box<dyn UdpSender>>,
        shared: Arc<Shared>,
        relay: SocketAddr,
        packet: Vec<u8>,
        #[pin]
        closed: OwnedNotified,
    }
}

/// Resolves SOCKS5 targets locally or delegates SOCKS5h target names to the proxy.
pub(super) async fn connect(
    inner: QuicConnector,
    tcp: TcpConnector<DynResolver>,
    mut resolver: DynResolver,
    timer: Arc<dyn Timer>,
    request: ConnectRequest,
    proxy: Intercept,
) -> Result<Conn, BoxError> {
    let uri = request.route_uri();
    let host = crate::util::strip_ipv6_brackets(uri.host().ok_or("HTTP/3 URI has no host")?);
    let port = uri.port_u16().unwrap_or(443);
    if proxy.uri().scheme_str() == Some("socks5h") {
        let target = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Ip((ip, port).into()),
            Err(_) => Address::Domain(host.into(), port),
        };
        return connect_target(&inner, tcp, &resolver, &request, &proxy, target).await;
    }

    let addresses = transport::resolve(&mut resolver, host, port, uri.port().is_some()).await?;
    // Target families are independent of the physical proxy's bindings.
    Ok(ConnectOptions::default()
        .connect(
            addresses,
            &BindOptions::default(),
            |address| {
                let tcp = tcp.clone();
                let inner = &inner;
                let resolver = &resolver;
                let request = &request;
                let proxy = &proxy;
                let attempt: BoxFuture<'_, _> = Box::pin(async move {
                    connect_target(inner, tcp, resolver, request, proxy, Address::Ip(address))
                        .await
                        .map_err(ConnectError::m("SOCKS5 target handshake error"))
                });
                Ok(attempt)
            },
            |duration| timer.sleep(duration),
        )
        .await?)
}

/// Each candidate owns its association; cancellation closes the control stream and UDP socket.
async fn connect_target(
    inner: &QuicConnector,
    tcp: TcpConnector<DynResolver>,
    resolver: &DynResolver,
    request: &ConnectRequest,
    proxy: &Intercept,
    target: Address,
) -> Result<Conn, BoxError> {
    let connect_proxy = async {
        let io = tcp.oneshot(proxy.uri().clone()).await?;
        let peer = io.peer_addr();
        // The relay's address family is not known until the ASSOCIATE reply.
        let unspecified = match peer {
            Some(SocketAddr::V6(_)) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            _ => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        };
        let auth = proxy.raw_auth();
        let auth = auth
            .as_ref()
            .map(|(user, pass)| {
                Ok::<_, std::str::Utf8Error>((
                    std::str::from_utf8(user)?,
                    std::str::from_utf8(pass)?,
                ))
            })
            .transpose()?;
        let mut association = udp::associate(io, auth, unspecified).await?;
        let (socket, relay) = match association.bound_addr().clone() {
            Address::Ip(bound) => {
                let mut relay = SocketAddr::new(bound.ip().to_canonical(), bound.port());
                if relay.ip().is_unspecified() {
                    relay.set_ip(
                        peer.ok_or("SOCKS5 UDP requires the control connection's peer address")?
                            .ip()
                            .to_canonical(),
                    );
                }
                (inner.udp_socket(request, relay)?, relay)
            }
            Address::Domain(host, port) => {
                let mut resolver = resolver.clone();
                // BND.PORT is authoritative even when the resolver returns another port.
                let mut resolving = pin!(transport::resolve(&mut resolver, &host, port, true));
                let addresses = poll_fn(|cx| {
                    // The association can close while DNS is pending; stop that lookup too.
                    if let Poll::Ready(result) = association.poll_closed(cx) {
                        let error = match result {
                            Ok(()) => io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "SOCKS5 UDP association closed during relay resolution",
                            ),
                            Err(error) => io::Error::new(io::ErrorKind::BrokenPipe, error),
                        };
                        return Poll::Ready(Err::<_, BoxError>(error.into()));
                    }
                    resolving
                        .as_mut()
                        .poll(cx)
                        .map(|result| result.map_err(Into::into))
                })
                .await?
                .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
                .collect::<Vec<_>>();

                // Prefer the control peer's family, then try other locally usable addresses.
                let preferred = |addr: &&SocketAddr| {
                    peer.is_none_or(|peer| peer.ip().to_canonical().is_ipv4() == addr.is_ipv4())
                };
                let mut selected = None;
                let mut first_error = None;
                for &relay in addresses
                    .iter()
                    .filter(preferred)
                    .chain(addresses.iter().filter(|addr| !preferred(addr)))
                {
                    match inner.udp_socket(request, relay) {
                        Ok(socket) => {
                            selected = Some((socket, relay));
                            break;
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                selected.ok_or_else(|| {
                    first_error
                        .unwrap_or_else(|| "SOCKS5 UDP relay resolved to no addresses".into())
                })?
            }
        };
        let socket = Socket::new(socket, association, relay, target)?;
        Ok::<_, BoxError>((socket, relay))
    };
    let (socket, relay) = connect_proxy.await.map_err(ProxyConnect::Source)?;
    inner.finish_tunnel(request, socket, relay).await
}

// ===== impl Socket =====

impl Socket {
    fn new(
        socket: Box<dyn AsyncUdpSocket>,
        association: UdpAssociation<BoxConnection>,
        relay: SocketAddr,
        target: Address,
    ) -> io::Result<Self> {
        let mut header = Vec::with_capacity(udp::header_len(&target));
        udp::encode_header(&target, &mut header)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let local = socket.local_addr()?;
        Ok(Self {
            inner: socket,
            shared: Arc::new(Shared {
                association: Mutex::new(Some(association)),
                target,
                header,
                closed: AtomicBool::new(false),
                notify: Arc::new(Notify::new()),
            }),
            local,
            relay,
            scratch: Vec::new(),
            received: RecvMeta::default(),
            offset: 0,
        })
    }
}

impl AsyncUdpSocket for Socket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        let mut packet = Vec::with_capacity(self.shared.header.len() + 1200);
        packet.extend_from_slice(&self.shared.header);
        Box::pin(SocketSender {
            inner: self.inner.create_sender(),
            shared: self.shared.clone(),
            relay: self.relay,
            packet,
            closed: self.shared.notify.clone().notified_owned(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP receive requires a buffer and metadata slot",
            )));
        };

        // Size for the endpoint's receive limit, which can exceed its 1200-byte send MTU.
        // Include the longest SOCKS header per GRO segment without reducing inner capacity.
        let capacity = buf
            .len()
            .checked_add(262)
            .and_then(|len| len.checked_mul(self.inner.max_receive_segments().max(1)))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP receive size overflow")
            })?
            .max(65_536);

        if capacity > self.scratch.len() {
            self.scratch
                .try_reserve_exact(capacity - self.scratch.len())
                .map_err(io::Error::other)?;
            self.scratch.resize(capacity, 0);
        }

        let mut association = self.shared.association.lock();
        let Some(control) = association.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };

        if let Poll::Ready(result) = control.poll_closed(cx) {
            *association = None;
            self.shared.closed.store(true, Ordering::Release);
            drop(association);
            self.shared.notify.notify_waiters();
            // QUIC ignores ConnectionReset, so closing the association must be terminal.
            return Poll::Ready(Err(match result {
                Ok(()) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "SOCKS5 UDP association closed")
                }
                Err(error) => io::Error::new(io::ErrorKind::BrokenPipe, error),
            }));
        }
        drop(association);

        for _ in 0..32 {
            if self.offset >= self.received.len {
                self.received = RecvMeta::default();
                let count = ready!(self.inner.poll_recv(
                    cx,
                    &mut [IoSliceMut::new(&mut self.scratch)],
                    std::slice::from_mut(&mut self.received),
                ))?;
                self.offset = 0;
                if count == 0
                    || self.received.len == 0
                    || self.received.len > self.scratch.len()
                    || self.received.stride == 0
                    || self.received.addr.port() != self.relay.port()
                    || self.received.addr.ip().to_canonical() != self.relay.ip().to_canonical()
                {
                    self.received.len = 0;
                    continue;
                }
            }

            let end = self
                .offset
                .saturating_add(self.received.stride)
                .min(self.received.len);
            let datagram = &self.scratch[self.offset..end];
            self.offset = end;
            let Ok((source, payload)) = udp::decode_header(datagram) else {
                continue;
            };
            if !matches_target(&self.shared.target, source)
                || payload.is_empty()
                || payload.len() > buf.len()
            {
                continue;
            }
            buf[..payload.len()].copy_from_slice(payload);
            *meta = RecvMeta::default();
            meta.addr = self.relay;
            meta.len = payload.len();
            meta.stride = payload.len();
            meta.dst_ip = self.received.dst_ip;
            return Poll::Ready(Ok(1));
        }

        // Malformed packets and GRO batches have a bounded cost per endpoint poll.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("local", &self.local)
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

// ===== impl SocketSender =====

impl UdpSender for SocketSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.shared.closed.load(Ordering::Acquire) || this.closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if transmit.destination != *this.relay
            || transmit.contents.is_empty()
            || transmit.contents.len() > 1200
            || transmit
                .segment_size
                .is_some_and(|size| size < transmit.contents.len())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP socket requires one datagram of at most 1200 bytes for its target",
            )));
        }
        this.packet.truncate(this.shared.header.len());
        this.packet.extend_from_slice(transmit.contents);
        this.inner.as_mut().poll_send(
            &Transmit {
                destination: *this.relay,
                ecn: None,
                contents: this.packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            },
            cx,
        )
    }
}

impl fmt::Debug for SocketSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketSender")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

/// Checks the target identity while allowing proxy-resolved names to reply from any IP.
fn matches_target(target: &Address, source: AddressRef<'_>) -> bool {
    if target.port() != source.port() {
        return false;
    }
    match (target, source) {
        (Address::Ip(target), AddressRef::Ip(source)) => {
            target.ip().to_canonical() == source.ip().to_canonical()
        }
        (Address::Domain(target, _), AddressRef::Domain(source, _)) => {
            target.eq_ignore_ascii_case(source)
        }
        (Address::Domain(..), AddressRef::Ip(_)) => true,
        (Address::Ip(_), AddressRef::Domain(..)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_sources_allowed_by_the_target() {
        let ip = Address::Ip("192.0.2.1:443".parse().unwrap());
        let name = Address::Domain("origin.test".into(), 443);
        for (source, matches_ip, matches_name) in [
            (AddressRef::from(&ip), true, true),
            (
                AddressRef::Ip("[::ffff:192.0.2.1]:443".parse().unwrap()),
                true,
                true,
            ),
            (
                AddressRef::Ip("192.0.2.2:443".parse().unwrap()),
                false,
                true,
            ),
            (
                AddressRef::Ip("[2001:db8::1]:443".parse().unwrap()),
                false,
                true,
            ),
            (
                AddressRef::Ip("192.0.2.1:444".parse().unwrap()),
                false,
                false,
            ),
            (AddressRef::Domain("ORIGIN.TEST", 443), false, true),
            (AddressRef::Domain("other.test", 443), false, false),
            (AddressRef::Domain("origin.test", 444), false, false),
        ] {
            assert_eq!(
                matches_target(&ip, source),
                matches_ip,
                "IP target: {source:?}"
            );
            assert_eq!(
                matches_target(&name, source),
                matches_name,
                "name target: {source:?}"
            );
        }
    }
}
