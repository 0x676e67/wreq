//! SOCKS5 UDP association adapter for QUIC endpoints.
//!
//! Keeps the TCP control stream open for the lifetime of the socket and its senders
//! ([RFC 1928 Section 7](https://www.rfc-editor.org/rfc/rfc1928#section-7)).

use std::{
    future::{Future, poll_fn},
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
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
use netty::proxy::socks::udp::{self, Address, AddressRef, AssociateError, UdpAssociation};
use pin_project_lite::pin_project;
use tokio::sync::{Notify, futures::OwnedNotified};
use tower::BoxError;

use super::{TUNNEL_MTU, Tunnel};
use crate::{
    conn::dialer::{ConnectError, resolve},
    dns::DynResolver,
    error::ProxyConnect,
    proxy::matcher::Intercept,
    rt::Connection,
    sync::Mutex,
};

static PROXY_CONNECT_ERROR: &str = "SOCKS5 proxy connect error";
static AUTH_ERROR: &str = "SOCKS5 authentication error";
static ASSOCIATE_ERROR: &str = "SOCKS5 UDP ASSOCIATE error";
static RELAY_ERROR: &str = "SOCKS5 UDP relay error";
static PEER_ADDR_REQUIRED: &str = "SOCKS5 UDP requires the control connection's peer address";
static ASSOCIATION_CLOSED: &str = "SOCKS5 UDP association closed during relay resolution";
static NO_RELAY_ADDRESSES: &str = "SOCKS5 UDP relay resolved to no addresses";
static RECV_BUFFER_MISSING: &str = "SOCKS5 UDP receive requires a buffer and metadata slot";
static RECV_SIZE_OVERFLOW: &str = "UDP receive size overflow";
static SEND_TARGET_MISMATCH: &str =
    "SOCKS5 UDP socket requires one datagram of at most 1200 bytes for its target";

/// Adapts a SOCKS5 UDP association into a fixed-peer [`AsyncUdpSocket`] for QUIC.
///
/// Only `poll_recv` polls the TCP control stream, avoiding waker contention with senders.
/// `scratch` buffers the latest UDP receive batch: bytes before `framed` have been unframed,
/// and `payloads` tracks the remaining unframed run of `stride`-spaced datagrams.
#[derive(Debug)]
pub(super) struct Socket {
    inner: Box<dyn AsyncUdpSocket>,
    shared: Arc<Shared>,
    local: SocketAddr,
    relay: SocketAddr,
    scratch: Vec<u8>,
    received: RecvMeta,
    framed: usize,
    payloads: Range<usize>,
    stride: usize,
}

/// Shared SOCKS5 UDP association state held by [`Socket`] and its [`SocketSender`] handles.
///
/// Keeps the TCP control stream and pre-encoded target header alive; `notify` wakes blocked
/// senders when `closed` flips, and `ended` signals the endpoint watcher once.
#[derive(Debug)]
struct Shared {
    association: Mutex<Option<UdpAssociation<Box<dyn Connection>>>>,
    target: Address,
    header: Vec<u8>,
    closed: AtomicBool,
    notify: Arc<Notify>,
    ended: Arc<Notify>,
}

pin_project! {
    /// [`UdpSender`] handle created by [`Socket::create_sender`].
    ///
    /// Reuses a pre-allocated framing buffer (`packet`) prefixed with the SOCKS5 UDP header
    /// and holds its own close notification so senders do not compete over a shared waker.
    #[derive(Debug)]
    struct SocketSender {
        inner: Pin<Box<dyn UdpSender>>,
        shared: Arc<Shared>,
        relay: SocketAddr,
        packet: Vec<u8>,
        #[pin]
        closed: OwnedNotified,
    }
}

/// Establishes a SOCKS5 UDP association and returns a [`Tunnel`] backed by its relay socket.
pub(super) async fn open(
    dial: impl Future<Output = Result<Box<dyn Connection>, BoxError>>,
    proxy: &Intercept,
    target: Address,
    resolver: &DynResolver,
    bind_relay: impl Fn(SocketAddr) -> Result<Box<dyn AsyncUdpSocket>, BoxError>,
) -> Result<Tunnel<Socket>, ConnectError> {
    let io = dial.await.map_err(proxy_error(PROXY_CONNECT_ERROR))?;
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
            Ok::<_, std::str::Utf8Error>((std::str::from_utf8(user)?, std::str::from_utf8(pass)?))
        })
        .transpose()
        .map_err(proxy_error(AUTH_ERROR))?;

    let mut association = udp::associate(io, auth, unspecified)
        .await
        .map_err(|error| {
            let stage = match error {
                AssociateError::InvalidCredentials
                | AssociateError::NoAcceptableAuth
                | AssociateError::AuthFailed => AUTH_ERROR,
                _ => ASSOCIATE_ERROR,
            };
            proxy_error(stage)(error)
        })?;

    let open_relay = async {
        // An unspecified BND.ADDR names the control peer, whose IPv6 scope a link-local relay
        // needs too.
        let relay = match peer {
            Some(peer) => association.relay_addr(peer),
            None => association.bound_addr().clone(),
        };
        let (socket, relay) = match relay {
            Address::Ip(relay) if relay.ip().is_unspecified() => {
                return Err(PEER_ADDR_REQUIRED.into());
            }
            Address::Ip(relay) => (bind_relay(relay)?, relay),
            Address::Domain(host, port) => {
                // BND.PORT is authoritative even when the resolver returns another port.
                let mut resolving = pin!(resolve(&host, port, true, |name| resolver.resolve(name)));
                let addresses = poll_fn(|cx| {
                    // The association can close while DNS is pending; stop that lookup too.
                    if let Poll::Ready(result) = association.poll_closed(cx) {
                        let error = match result {
                            Ok(()) => io::Error::new(io::ErrorKind::BrokenPipe, ASSOCIATION_CLOSED),
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
                    match bind_relay(relay) {
                        Ok(socket) => {
                            selected = Some((socket, relay));
                            break;
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }

                selected.ok_or_else(|| first_error.unwrap_or_else(|| NO_RELAY_ADDRESSES.into()))?
            }
        };

        let socket = Socket::new(socket, association, relay, target)?;
        Ok::<_, BoxError>((socket, relay))
    };

    let (socket, relay) = open_relay.await.map_err(proxy_error(RELAY_ERROR))?;
    let ended = socket.shared.ended.clone();

    Ok(Tunnel {
        socket,
        remote: relay,
        ended,
    })
}

/// Wraps a proxy stage failure as a [`ConnectError`] carrying [`ProxyConnect`].
fn proxy_error<E: Into<BoxError>>(stage: &'static str) -> impl FnOnce(E) -> ConnectError {
    move |error| ConnectError::new(stage, ProxyConnect::Source(error.into()))
}

// ===== impl Socket =====

impl Socket {
    fn new(
        socket: Box<dyn AsyncUdpSocket>,
        association: UdpAssociation<Box<dyn Connection>>,
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
                ended: Arc::new(Notify::new()),
            }),
            local,
            relay,
            scratch: Vec::new(),
            received: RecvMeta::default(),
            framed: 0,
            payloads: 0..0,
            stride: 0,
        })
    }
}

impl AsyncUdpSocket for Socket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        let mut packet = Vec::with_capacity(self.shared.header.len() + usize::from(TUNNEL_MTU));
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
                RECV_BUFFER_MISSING,
            )));
        };

        // Size for the endpoint's receive limit, which can exceed its tunnel send MTU.
        // Include the longest SOCKS header per GRO segment without reducing inner capacity.
        let capacity = buf
            .len()
            .checked_add(262)
            .and_then(|len| len.checked_mul(self.inner.max_receive_segments().max(1)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, RECV_SIZE_OVERFLOW))?
            .max(65_536);

        // Ensure the scratch buffer has enough capacity for the receive operation.
        if capacity > self.scratch.len() {
            self.scratch
                .try_reserve_exact(capacity - self.scratch.len())
                .map_err(io::Error::other)?;
            self.scratch.resize(capacity, 0);
        }
        let mut association = self.shared.association.lock();

        // The watcher closes the endpoint once the association ends.
        let Some(control) = association.as_mut() else {
            return Poll::Pending;
        };

        if let Poll::Ready(_result) = control.poll_closed(cx) {
            *association = None;
            self.shared.closed.store(true, Ordering::Release);
            drop(association);

            self.shared.notify.notify_waiters();
            self.shared.ended.notify_one();

            if let Err(_error) = _result {
                debug!("SOCKS5 control connection error: {_error}");
            }
            return Poll::Pending;
        }
        drop(association);

        for _ in 0..32 {
            if self.payloads.is_empty() {
                if self.framed >= self.received.len {
                    self.received = RecvMeta::default();
                    let count = ready!(self.inner.poll_recv(
                        cx,
                        &mut [IoSliceMut::new(&mut self.scratch)],
                        std::slice::from_mut(&mut self.received),
                    ))?;
                    self.framed = 0;

                    if count == 0 || self.received.len > self.scratch.len() {
                        self.received.len = 0;
                        continue;
                    }
                }

                // Drops the rest of a receive that bypassed the relay or holds no datagram.
                let framed = &mut self.scratch[self.framed..self.received.len];
                let Some(run) =
                    udp::unframe(self.relay, self.received.addr, framed, self.received.stride)
                else {
                    self.framed = self.received.len;
                    continue;
                };

                // Payloads now lead the run's datagrams, ahead of those still framed.
                let start = self.framed;
                self.framed += run.consumed;

                if run.stride > 0 && matches_target(&self.shared.target, (&run.source).into()) {
                    self.payloads = start..start + run.len;
                    self.stride = run.stride;
                }
                continue;
            }

            let end = self
                .payloads
                .start
                .saturating_add(self.stride)
                .min(self.payloads.end);
            let payload = &self.scratch[self.payloads.start..end];
            self.payloads.start = end;

            // Empty UDP payloads contain no QUIC header (RFC 9000 Section 17).
            // https://www.rfc-editor.org/rfc/rfc9000#section-17
            if payload.is_empty() || payload.len() > buf.len() {
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

// ===== impl SocketSender =====

impl UdpSender for SocketSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Once the association ends, packets are lost as on a dead UDP path; a send error would
        // make the connection driver log it as an I/O error.
        if this.shared.closed.load(Ordering::Acquire) || this.closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }

        if transmit.destination != *this.relay
            || transmit.contents.is_empty()
            || transmit.contents.len() > usize::from(TUNNEL_MTU)
            || transmit
                .segment_size
                .is_some_and(|size| size < transmit.contents.len())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                SEND_TARGET_MISMATCH,
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

/// Matches a received SOCKS5 source address against the target, allowing proxy-resolved domains
/// to reply from any IP.
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
