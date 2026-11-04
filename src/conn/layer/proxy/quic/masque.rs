//! Establishes a [CONNECT-UDP] tunnel and carries the target QUIC connection over it.
//! The inner socket and its senders retain the tunnel, outer HTTP/3 driver and endpoint.
//!
//! [CONNECT-UDP]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3

use std::{
    convert::Infallible,
    fmt,
    future::{Future, ready as ready_future},
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker, ready},
};

use ::quic::{
    AsyncUdpSocket, Endpoint, UdpSender,
    udp::{RecvMeta, Transmit},
};
use bytes::{Buf, Bytes};
use futures_util::{
    StreamExt,
    stream::{self, BoxStream},
    task::AtomicWaker,
};
use netty::{
    conn::http3,
    proxy::masque::{ConnectUdp, SendError, Template, UdpTunnel},
    rt::quic::{
        self as rt, Compat, ConnectionError, DatagramConnection, DatagramError, RecvDatagram,
        SendDatagram, StreamError,
    },
};
use tokio::sync::{Notify, futures::OwnedNotified};
use tower::{BoxError, ServiceExt, service_fn};

use crate::{
    Body,
    conn::{Conn, request::ConnectRequest, transport::QuicConnector},
    error::ProxyConnect,
    proxy::matcher::Intercept,
    rt::RuntimeHandle,
    sync::Mutex,
};

/// One CONNECT-UDP tunnel used as an inner QUIC endpoint's socket.
/// The endpoint and its senders retain the outer connection until they are dropped.
struct Socket {
    shared: Arc<Shared>,
    local: SocketAddr,
    remote: SocketAddr,
}

struct Shared {
    state: Mutex<State>,
    ready: Arc<Notify>,
    waker: Waker,
    recv: AtomicWaker,
}

/// Dropping the tunnel aborts CONNECT-UDP before the outer connection is closed.
struct State {
    tunnel: Option<UdpTunnel>,
    _driver: netty::conn::http3::Connection<Connection, Body, RuntimeHandle>,
    _endpoint: Endpoint,
}

struct SocketSender {
    shared: Arc<Shared>,
    remote: SocketAddr,
    waiting: Option<Pin<Box<OwnedNotified>>>,
}

/// Broadcasts tunnel readiness to independently registered QUIC send tasks.
struct SendWake(Arc<Notify>);

/// Owns the outer connection's stream readers and hands out its datagram reader once.
struct Connection {
    inner: Compat<http3_quic::Connection>,
    datagrams: Option<::quic::Connection>,
}

/// Admits complete payloads into QUIC's bounded unreliable send queue.
struct Sender(::quic::Connection);

/// Retains the pending receive operation and its registered wakeup between polls.
struct Receiver(BoxStream<'static, Result<Bytes, ::quic::ConnectionError>>);

/// Opens CONNECT-UDP and authenticates the target; its endpoint retains the outer connection.
pub(super) async fn connect(
    runtime: RuntimeHandle,
    mut inner: QuicConnector,
    request: ConnectRequest,
    proxy: Intercept,
) -> Result<Conn, BoxError> {
    // This scope classifies proxy setup failures separately from target TLS errors.
    let connect_proxy = async {
        // The configured quic:// URI becomes HTTPS on the CONNECT request.
        let template = Template::well_known(
            proxy
                .uri()
                .authority()
                .ok_or("MASQUE proxy has no authority")?,
        )?;

        let timer = runtime.timer();
        let (connection, endpoint) = inner
            .connect_proxy(&request, template.proxy(), &*timer)
            .await?;
        let remote = connection.remote_address();
        let (sender, driver) = http3::Builder::new(runtime)
            .handshake_with_datagrams::<_, Body>(Connection::new(connection))
            .await?;

        // ConnectUdp obtains its sender from a service; reuse this outer connection.
        let mut connect_udp = ConnectUdp::new(
            template,
            service_fn(move |_| ready_future(Ok::<_, Infallible>(sender.clone()))),
        );

        if let Some(auth) = proxy.basic_auth() {
            connect_udp = connect_udp.with_auth(auth.clone());
        }

        if let Some(headers) = proxy.custom_headers() {
            connect_udp = connect_udp.with_headers(headers.clone());
        }

        // The proxy resolves the target; the original request retains its pool identity.
        let tunnel = connect_udp.oneshot(request.route_uri().clone()).await?;

        // The inner endpoint's socket owns the tunnel and its outer connection resources.
        let socket = Socket::new(tunnel, driver, endpoint, remote)?;
        Ok::<_, BoxError>((socket, remote))
    };

    let (socket, remote) = connect_proxy.await.map_err(ProxyConnect::Source)?;
    inner.finish_tunnel(&request, socket, remote).await
}

// ===== impl Socket =====

impl Socket {
    fn new(
        tunnel: UdpTunnel,
        driver: netty::conn::http3::Connection<Connection, Body, RuntimeHandle>,
        endpoint: Endpoint,
        remote: SocketAddr,
    ) -> io::Result<Self> {
        if tunnel.max_payload_size() < 1200 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MASQUE tunnel cannot carry a 1200-byte QUIC datagram",
            ));
        }
        let local = endpoint.local_addr()?;
        let ready = Arc::new(Notify::new());
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    tunnel: Some(tunnel),
                    _driver: driver,
                    _endpoint: endpoint,
                }),
                waker: Waker::from(Arc::new(SendWake(ready.clone()))),
                ready,
                recv: AtomicWaker::new(),
            }),
            local,
            remote,
        })
    }
}

impl AsyncUdpSocket for Socket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(SocketSender {
            shared: self.shared.clone(),
            remote: self.remote,
            waiting: None,
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
                "MASQUE receive requires a buffer and metadata slot",
            )));
        };
        self.shared.recv.register(cx.waker());
        // Invalid or oversized input must not monopolize the endpoint driver.
        for _ in 0..32 {
            let payload = {
                let mut state = self.shared.state.lock();
                let Some(tunnel) = state.tunnel.as_mut() else {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                };
                match ready!(tunnel.poll_recv(cx)) {
                    Ok(Some(payload)) => payload,
                    result => {
                        state.tunnel = None;
                        drop(state);
                        self.shared.ready.notify_waiters();
                        return Poll::Ready(Err(match result {
                            Err(error) => io::Error::other(error),
                            // QUIC ignores ConnectionReset, so EOF must be terminal.
                            _ => io::ErrorKind::BrokenPipe.into(),
                        }));
                    }
                }
            };
            // Empty UDP payloads contain no QUIC header (RFC 9000 Section 17).
            // https://www.rfc-editor.org/rfc/rfc9000#section-17
            if payload.is_empty() || payload.len() > buf.len() {
                continue;
            }
            buf[..payload.len()].copy_from_slice(&payload);
            *meta = RecvMeta::default();
            meta.addr = self.remote;
            meta.len = payload.len();
            meta.stride = payload.len();
            meta.ecn = None;
            meta.dst_ip = Some(self.local.ip());
            return Poll::Ready(Ok(1));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        // The inner connection must not probe beyond the tunnel's payload limit.
        true
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("local", &self.local)
            .field("remote", &self.remote)
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
        let this = self.get_mut();
        if transmit.destination != this.remote
            || transmit
                .segment_size
                .is_some_and(|size| size < transmit.contents.len())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MASQUE socket requires one datagram for its tunnel target",
            )));
        }

        let mut state = this.shared.state.lock();
        let Some(tunnel) = state.tunnel.as_mut() else {
            this.waiting = None;
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        match tunnel.try_send(transmit.contents) {
            Ok(()) => {
                this.waiting = None;
                Poll::Ready(Ok(()))
            }
            Err(SendError::Full) => {
                // Register each sender before checking the shared source of readiness.
                // Dropping a sender removes its notification and task waker.
                let waiting = this
                    .waiting
                    .get_or_insert_with(|| Box::pin(this.shared.ready.clone().notified_owned()));
                if waiting.as_mut().poll(cx).is_pending() {
                    let mut cx = Context::from_waker(&this.shared.waker);
                    match ready!(tunnel.poll_send_ready(&mut cx)) {
                        Ok(()) => {}
                        Err(error) => {
                            state.tunnel = None;
                            drop(state);
                            this.waiting = None;
                            this.shared.ready.notify_waiters();
                            this.shared.recv.wake();
                            return Poll::Ready(Err(io::Error::other(error)));
                        }
                    }
                }
                drop(state);
                this.waiting = None;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => {
                this.waiting = None;
                let kind = if error == SendError::TooLarge {
                    io::ErrorKind::InvalidInput
                } else {
                    state.tunnel = None;
                    io::ErrorKind::BrokenPipe
                };
                drop(state);
                if kind == io::ErrorKind::BrokenPipe {
                    this.shared.ready.notify_waiters();
                    this.shared.recv.wake();
                }
                Poll::Ready(Err(io::Error::new(kind, error)))
            }
        }
    }
}

impl fmt::Debug for SocketSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketSender")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

// ===== impl SendWake =====

impl Wake for SendWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_waiters();
    }
}

// ===== impl Connection =====

impl Connection {
    /// Takes an authenticated connection with no other active datagram reader.
    fn new(connection: ::quic::Connection) -> Self {
        Self {
            datagrams: Some(connection.clone()),
            inner: Compat::new(http3_quic::Connection::new(connection)),
        }
    }
}

impl<B: Buf> rt::Connection<B> for Connection {
    type RecvStream = Compat<http3_quic::RecvStream>;
    type OpenStreams = Compat<http3_quic::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        rt::Connection::<B>::opener(&self.inner)
    }
}

impl<B: Buf> rt::OpenStreams<B> for Connection {
    type SendStream = Compat<http3_quic::SendStream<B>>;
    type BidiStream = Compat<http3_quic::BidiStream<B>>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        rt::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

impl DatagramConnection for Connection {
    type Sender = Sender;
    type Receiver = Receiver;

    fn take_datagrams(&mut self) -> Option<(Sender, Receiver)> {
        let connection = self.datagrams.take()?;
        let receiver = Box::pin(stream::unfold(connection.clone(), |connection| async {
            let payload = connection.read_datagram().await;
            Some((payload, connection))
        }));
        Some((Sender(connection), Receiver(receiver)))
    }
}

// ===== impl Sender =====

impl SendDatagram for Sender {
    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }

    fn poll_send(
        &mut self,
        _: &mut Context<'_>,
        payload: &Bytes,
    ) -> Poll<Result<(), DatagramError>> {
        Poll::Ready(
            self.0
                .send_datagram(payload.clone())
                .map_err(|error| match error {
                    ::quic::SendDatagramError::UnsupportedByPeer
                    | ::quic::SendDatagramError::Disabled => DatagramError::Unavailable,
                    ::quic::SendDatagramError::TooLarge => DatagramError::TooLarge,
                    ::quic::SendDatagramError::ConnectionLost(error) => {
                        DatagramError::Connection(connection_error(error))
                    }
                }),
        )
    }
}

// ===== impl Receiver =====

impl RecvDatagram for Receiver {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, ConnectionError>> {
        Poll::Ready(
            ready!(self.0.poll_next_unpin(cx))
                .transpose()
                .map_err(connection_error),
        )
    }
}

fn connection_error(error: ::quic::ConnectionError) -> ConnectionError {
    match error {
        ::quic::ConnectionError::ApplicationClosed(error) => ConnectionError::ApplicationClose {
            error_code: error.error_code.into_inner(),
        },
        ::quic::ConnectionError::TimedOut => ConnectionError::Timeout,
        error => ConnectionError::Undefined(Arc::new(error)),
    }
}
