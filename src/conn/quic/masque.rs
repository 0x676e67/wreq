//! MASQUE [CONNECT-UDP] tunnel adapter over an outer QUIC connection.
//!
//! [CONNECT-UDP]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3

use std::{
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
};
use http::Uri;
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

use super::{TUNNEL_MTU, Tunnel};
use crate::{
    Body,
    ext::UriExt,
    proxy::matcher::Intercept,
    rt::DynRuntime,
    sync::{Mutex, MutexGuard},
};

static PROXY_MISSING_AUTHORITY: &str = "MASQUE proxy has no authority";
static TARGET_MISSING_HOST: &str = "MASQUE target has no host";
static TUNNEL_MTU_TOO_SMALL: &str = "MASQUE tunnel cannot carry a 1200-byte QUIC datagram";
static RECV_BUFFER_MISSING: &str = "MASQUE receive requires a buffer and metadata slot";
static SEND_TARGET_MISMATCH: &str = "MASQUE socket requires one datagram for its tunnel target";

/// Adapts a CONNECT-UDP tunnel into an [`AsyncUdpSocket`] for the inner QUIC endpoint.
///
/// Keeps the outer HTTP/3 driver and endpoint alive through [`Shared`] until both the socket
/// and all spawned [`SocketSender`] handles are dropped.
pub(super) struct Socket {
    shared: Arc<Shared>,
    local: SocketAddr,
    remote: SocketAddr,
}

/// Shared tunnel state synchronized between [`Socket`] and its [`SocketSender`] handles.
///
/// `ready` broadcasts send readiness to waiting senders; `ended` notifies the inner endpoint
/// watcher once the tunnel closes.
struct Shared {
    state: Mutex<State>,
    ready: Arc<Notify>,
    ended: Arc<Notify>,
    waker: Waker,
}

/// Inner state holding the active [`UdpTunnel`], outer HTTP/3 driver, and outer [`Endpoint`].
///
/// Field order ensures `tunnel` drops first to abort CONNECT-UDP cleanly before closing the
/// outer connection.
struct State {
    tunnel: Option<UdpTunnel>,
    _driver: netty::conn::http3::Connection<OuterConnection, Body, DynRuntime>,
    _endpoint: Endpoint,
}

/// [`UdpSender`] handle created by [`Socket::create_sender`].
///
/// Holds an independent notification slot (`waiting`) so concurrent QUIC send tasks can wait
/// on tunnel capacity without overwriting each other's wakers.
struct SocketSender {
    shared: Arc<Shared>,
    remote: SocketAddr,
    waiting: Option<Pin<Box<OwnedNotified>>>,
}

/// Custom [`Wake`] implementation backed by a [`Notify`].
///
/// Broadcasts tunnel send readiness to every [`SocketSender`] task waiting on `ready`.
struct SendWake(Arc<Notify>);

/// Adapts the outer QUIC [`Connection`](::quic::Connection) for HTTP/3 stream and datagram I/O.
///
/// Delegates stream traits to `http3_quic::Connection` and hands out datagram ownership once
/// via [`DatagramConnection::take_datagrams`].
struct OuterConnection {
    inner: Compat<http3_quic::Connection>,
    datagrams: Option<::quic::Connection>,
}

/// [`SendDatagram`] wrapper over the outer QUIC connection.
///
/// Submits complete datagram payloads into QUIC's unreliable send queue and maps send errors.
struct Sender(::quic::Connection);

/// [`RecvDatagram`] stream adapter around `Connection::read_datagram`.
///
/// Keeps the in-flight receive future and its registered waker alive across repeated polls.
struct Receiver(BoxStream<'static, Result<Bytes, ::quic::ConnectionError>>);

/// Builds the well-known CONNECT-UDP URI template from a `quic://` proxy URI.
pub(super) fn template(proxy: &Intercept) -> Result<Template, BoxError> {
    Ok(Template::well_known(
        proxy.uri().authority().ok_or(PROXY_MISSING_AUTHORITY)?,
    )?)
}

/// Opens a CONNECT-UDP tunnel over the outer proxy connection and returns a [`Tunnel`].
pub(super) async fn open(
    (connection, endpoint): (::quic::Connection, Endpoint),
    runtime: DynRuntime,
    template: Template,
    proxy: &Intercept,
    target: &Uri,
) -> Result<Tunnel<Socket>, BoxError> {
    let remote = connection.remote_address();
    let (sender, driver) = http3::Builder::new(runtime)
        .handshake_with_datagrams::<_, Body>(OuterConnection::new(connection))
        .await?;

    // ConnectUdp obtains its sender from a service; reuse this outer connection.
    let mut connect_udp = ConnectUdp::new(
        template,
        service_fn(move |_| ready_future(Ok::<_, !>(sender.clone()))),
    );
    if let Some(auth) = proxy.basic_auth() {
        connect_udp = connect_udp.with_auth(auth.clone());
    }
    if let Some(headers) = proxy.custom_headers() {
        connect_udp = connect_udp.with_headers(headers.clone());
    }

    let tunnel = connect_udp.oneshot(udp_target(target)?).await?;
    let socket = Socket::new(tunnel, driver, endpoint, remote)?;
    let ended = socket.shared.ended.clone();
    Ok(Tunnel {
        socket,
        remote,
        ended,
    })
}

/// Ensures `uri` has an explicit port for CONNECT-UDP, defaulting to 443.
fn udp_target(uri: &Uri) -> Result<Uri, BoxError> {
    if uri.port().is_some() {
        return Ok(uri.clone());
    }
    let host = uri.host().ok_or(TARGET_MISSING_HOST)?;
    let mut parts = uri.clone().into_parts();
    parts.authority = Some(format!("{host}:{}", uri.port_or_default()).parse()?);
    Ok(Uri::from_parts(parts)?)
}

// ===== impl Socket =====

impl Socket {
    fn new(
        tunnel: UdpTunnel,
        driver: netty::conn::http3::Connection<OuterConnection, Body, DynRuntime>,
        endpoint: Endpoint,
        remote: SocketAddr,
    ) -> io::Result<Self> {
        if tunnel.max_payload_size() < usize::from(TUNNEL_MTU) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                TUNNEL_MTU_TOO_SMALL,
            ));
        }

        let local = endpoint.local_addr()?;
        let ready = Arc::new(Notify::new());

        Ok(Self {
            local,
            remote,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    tunnel: Some(tunnel),
                    _driver: driver,
                    _endpoint: endpoint,
                }),
                waker: Waker::from(Arc::new(SendWake(ready.clone()))),
                ready,
                ended: Arc::new(Notify::new()),
            }),
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
                RECV_BUFFER_MISSING,
            )));
        };

        // Invalid or oversized input must not monopolize the endpoint driver.
        for _ in 0..32 {
            let payload = {
                let mut state = self.shared.state.lock();

                // The watcher closes the endpoint once the tunnel ends.
                let Some(tunnel) = state.tunnel.as_mut() else {
                    return Poll::Pending;
                };

                match ready!(tunnel.poll_recv(cx)) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => {
                        self.shared.close(state);
                        return Poll::Pending;
                    }
                    Err(_error) => {
                        debug!("MASQUE tunnel receive error: {_error}");
                        self.shared.close(state);
                        return Poll::Pending;
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
            // The tunnel does not report which outer address received the payload.
            meta.dst_ip = None;

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
                SEND_TARGET_MISMATCH,
            )));
        }

        // Once the tunnel ends, packets are lost as on a dead UDP path; a send error would
        // make the connection driver log it as an I/O error.
        let mut state = this.shared.state.lock();
        let Some(tunnel) = state.tunnel.as_mut() else {
            this.waiting = None;
            return Poll::Ready(Ok(()));
        };

        match tunnel.try_send(transmit.contents) {
            // An oversized packet is lost, as on UDP; a send error would close the inner
            // connection instead. The outer path MTU never drops below a full tunnel packet.
            // https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1
            Ok(()) | Err(SendError::TooLarge) => {
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

                    if let Err(_error) = ready!(tunnel.poll_send_ready(&mut cx)) {
                        debug!("MASQUE tunnel send error: {_error}");
                        this.waiting = None;
                        this.shared.close(state);
                        return Poll::Ready(Ok(()));
                    }
                }

                drop(state);
                this.waiting = None;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_error) => {
                debug!("MASQUE tunnel send error: {_error}");
                this.waiting = None;
                this.shared.close(state);
                Poll::Ready(Ok(()))
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

// ===== impl Shared =====

impl Shared {
    /// Closes the tunnel, waking any blocked senders and signaling the endpoint watcher.
    fn close(&self, mut state: MutexGuard<'_, State>) {
        state.tunnel = None;
        drop(state);
        self.ready.notify_waiters();
        self.ended.notify_one();
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

// ===== impl OuterConnection =====

impl OuterConnection {
    /// Takes an authenticated connection with no other active datagram reader.
    fn new(connection: ::quic::Connection) -> Self {
        Self {
            datagrams: Some(connection.clone()),
            inner: Compat::new(http3_quic::Connection::new(connection)),
        }
    }
}

impl<B: Buf> rt::Connection<B> for OuterConnection {
    type RecvStream = Compat<http3_quic::RecvStream>;
    type OpenStreams = Compat<http3_quic::OpenStreams>;

    #[inline]
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_recv(&mut self.inner, cx)
    }

    #[inline]
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_bidi(&mut self.inner, cx)
    }

    #[inline]
    fn opener(&self) -> Self::OpenStreams {
        rt::Connection::<B>::opener(&self.inner)
    }
}

impl<B: Buf> rt::OpenStreams<B> for OuterConnection {
    type SendStream = Compat<http3_quic::SendStream<B>>;
    type BidiStream = Compat<http3_quic::BidiStream<B>>;

    #[inline]
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx)
    }

    #[inline]
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    #[inline]
    fn close(&mut self, code: u64, reason: &[u8]) {
        rt::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

impl DatagramConnection for OuterConnection {
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
