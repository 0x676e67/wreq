//! Connection observation checked against local TLS servers that record each layer they see.

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
};
use wreq::{
    Client, ClientBuilder, Proxy,
    observe::{ConnectionEvent, ConnectionId, ConnectionObserver},
    tls::TlsVersion,
};

#[derive(Debug, PartialEq)]
enum Event {
    Handshake(String),
    TlsWrite(Vec<u8>),
    TlsRead(Vec<u8>),
    Connected {
        remote_addr: Option<SocketAddr>,
        alpn: Option<Vec<u8>>,
        tls_version: Option<TlsVersion>,
    },
    Read(Vec<u8>),
    Write(Vec<u8>),
    Closed,
    Other(String),
}

#[derive(Default)]
struct Events(Mutex<Vec<(ConnectionId, Event)>>);

impl ConnectionObserver for Events {
    fn observe(&self, event: ConnectionEvent<'_>) {
        let id = event.id();
        let event = match event {
            ConnectionEvent::TlsHandshake { host, .. } => Event::Handshake(host.to_owned()),
            ConnectionEvent::TlsWrite { bytes, .. } => Event::TlsWrite(bytes.to_vec()),
            ConnectionEvent::TlsRead { bytes, .. } => Event::TlsRead(bytes.to_vec()),
            ConnectionEvent::Connected {
                remote_addr,
                alpn,
                tls_version,
                ..
            } => Event::Connected {
                remote_addr,
                alpn: alpn.map(<[u8]>::to_vec),
                tls_version,
            },
            ConnectionEvent::Read { bytes, .. } => Event::Read(bytes.to_vec()),
            ConnectionEvent::Write { bytes, .. } => Event::Write(bytes.to_vec()),
            ConnectionEvent::Closed { .. } => Event::Closed,
            event => Event::Other(format!("{event:?}")),
        };
        self.0.lock().unwrap().push((id, event));
    }
}

impl Events {
    /// Waits for the connection to close, then returns its events after checking that they all
    /// belong to `id` and that `Closed` arrives exactly once, last.
    async fn closed(&self, id: Option<ConnectionId>) -> Vec<Event> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|(_, event)| *event == Event::Closed)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let events = std::mem::take(&mut *self.0.lock().unwrap());
        let id = id.unwrap_or(events[0].0);
        assert!(events.iter().all(|(event_id, _)| *event_id == id));
        let events: Vec<_> = events.into_iter().map(|(_, event)| event).collect();
        assert_eq!(events.iter().filter(|e| **e == Event::Closed).count(), 1);
        assert_eq!(events.last(), Some(&Event::Closed));
        events
    }
}

fn tls_written(events: &[Event]) -> Vec<u8> {
    concat(events, |event| match event {
        Event::TlsWrite(bytes) => Some(bytes),
        _ => None,
    })
}

fn tls_read(events: &[Event]) -> Vec<u8> {
    concat(events, |event| match event {
        Event::TlsRead(bytes) => Some(bytes),
        _ => None,
    })
}

fn concat(events: &[Event], pick: impl Fn(&Event) -> Option<&Vec<u8>>) -> Vec<u8> {
    events.iter().filter_map(pick).flatten().copied().collect()
}

/// Splits events at `Connected` into handshake records and plaintext.
fn split_at_connected(events: &[Event]) -> (&[Event], &Event, &[Event]) {
    let index = events
        .iter()
        .position(|event| matches!(event, Event::Connected { .. }))
        .unwrap();
    (&events[..index], &events[index], &events[index + 1..])
}

/// Bytes that crossed one layer of a server connection: `(read, written)`.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<(Vec<u8>, Vec<u8>)>>);

impl Seen {
    fn read(&self) -> Vec<u8> {
        self.0.lock().unwrap().0.clone()
    }

    fn written(&self) -> Vec<u8> {
        self.0.lock().unwrap().1.clone()
    }
}

struct Recording<T> {
    io: T,
    seen: Seen,
}

impl<T: AsyncRead + Unpin> AsyncRead for Recording<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let poll = Pin::new(&mut this.io).poll_read(cx, buf);
        this.seen
            .0
            .lock()
            .unwrap()
            .0
            .extend_from_slice(&buf.filled()[filled..]);
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Recording<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            this.seen
                .0
                .lock()
                .unwrap()
                .1
                .extend_from_slice(&buf[..written]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn record<T>(io: T, seen: &Seen) -> Recording<T> {
    Recording {
        io,
        seen: seen.clone(),
    }
}

async fn accept_tls<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    version: SslVersion,
) -> tokio_btls::SslStream<T> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(include_bytes!("support/server.cert")).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(include_bytes!("support/server.key")).unwrap())
        .unwrap();
    acceptor.set_min_proto_version(Some(version)).unwrap();
    acceptor.set_max_proto_version(Some(version)).unwrap();
    acceptor.set_alpn_select_callback(|_, protocols| {
        select_next_proto(b"\x08http/1.1", protocols).ok_or(AlpnError::NOACK)
    });
    let ssl = Ssl::new(acceptor.build().context()).unwrap();
    let mut stream = tokio_btls::SslStream::new(ssl, io).unwrap();
    Pin::new(&mut stream).accept().await.unwrap();
    stream
}

async fn serve(io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) {
    let served = hyper::server::conn::http1::Builder::new()
        .serve_connection(
            TokioIo::new(io),
            hyper::service::service_fn(|_| async {
                Ok::<_, Infallible>(http::Response::new(wreq::Body::from("observed")))
            }),
        )
        .await;
    // Closing TLS inside a tunnel writes after the client has gone, which may fail.
    if let Err(error) = served {
        assert!(error.is_shutdown(), "{error}");
    }
}

fn client(events: &Arc<Events>) -> ClientBuilder {
    Client::builder()
        .tls_cert_verification(false)
        .tls_verify_hostname(false)
        .timeout(Duration::from_secs(5))
        .connection_observer(events.clone())
}

#[tokio::test]
async fn reports_handshake_records_and_plaintext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (raw, plain) = (Seen::default(), Seen::default());
    let server = tokio::spawn({
        let (raw, plain) = (raw.clone(), plain.clone());
        async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = accept_tls(record(socket, &raw), SslVersion::TLS1_3).await;
            serve(record(tls, &plain)).await;
        }
    });

    let events = Arc::new(Events::default());
    let client = client(&events).no_proxy().http1_only().build().unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let response = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .unwrap();
        ids.push(response.extensions().get::<ConnectionId>().copied());
        assert_eq!(response.bytes().await.unwrap(), "observed");
    }
    drop(client);
    server.await.unwrap();

    // Both pooled requests ran on one observed connection.
    assert!(ids[0].is_some());
    assert_eq!(ids[0], ids[1]);
    let events = events.closed(ids[0]).await;
    let (handshake, connected, plaintext) = split_at_connected(&events);
    assert_eq!(handshake[0], Event::Handshake("localhost".to_owned()));
    assert_eq!(
        *connected,
        Event::Connected {
            remote_addr: Some(addr),
            alpn: Some(b"http/1.1".to_vec()),
            tls_version: Some(TlsVersion::TLS_1_3),
        }
    );

    // Records match the wire up to the end of the handshake, starting with the ClientHello
    // record; later records are left to the plaintext layer.
    let (written, read) = (tls_written(handshake), tls_read(handshake));
    assert_eq!(written.first(), Some(&0x16));
    assert!(raw.read().starts_with(&written) && raw.read().len() > written.len());
    assert!(raw.written().starts_with(&read) && raw.written().len() > read.len());

    // Plaintext matches what the server decrypted.
    assert!(
        plaintext
            .iter()
            .all(|event| !matches!(event, Event::TlsWrite(_) | Event::TlsRead(_)))
    );
    let written = concat(plaintext, |event| match event {
        Event::Write(bytes) => Some(bytes),
        _ => None,
    });
    let read = concat(plaintext, |event| match event {
        Event::Read(bytes) => Some(bytes),
        _ => None,
    });
    assert_eq!(written, plain.read());
    assert_eq!(read, plain.written());
}

#[tokio::test]
async fn reports_both_handshakes_through_https_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (raw, tunnel, plain) = (Seen::default(), Seen::default(), Seen::default());
    let server = tokio::spawn({
        let (raw, tunnel, plain) = (raw.clone(), tunnel.clone(), plain.clone());
        async move {
            let (socket, _) = listener.accept().await.unwrap();
            // Different proxy and origin versions show which handshake `Connected` describes.
            let mut proxy = accept_tls(record(socket, &raw), SslVersion::TLS1_2).await;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(proxy.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"CONNECT observer.test:443 HTTP/1.1\r\n"));
            proxy
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let origin = accept_tls(record(proxy, &tunnel), SslVersion::TLS1_3).await;
            serve(record(origin, &plain)).await;
        }
    });

    let events = Arc::new(Events::default());
    let client = client(&events)
        .proxy(Proxy::all(format!("https://{addr}")).unwrap())
        .build()
        .unwrap();
    let response = client.get("https://observer.test/").send().await.unwrap();
    let id = response.extensions().get::<ConnectionId>().copied();
    assert_eq!(response.bytes().await.unwrap(), "observed");
    drop(client);
    server.await.unwrap();

    let events = events.closed(id).await;
    let (handshakes, connected, plaintext) = split_at_connected(&events);
    let origin = handshakes
        .iter()
        .position(|event| *event == Event::Handshake("observer.test".to_owned()))
        .unwrap();
    let (proxy, origin) = handshakes.split_at(origin);
    assert_eq!(proxy[0], Event::Handshake("127.0.0.1".to_owned()));

    // The proxy handshake is on the socket; the origin handshake is inside the tunnel, after a
    // CONNECT exchange that neither layer reports.
    assert!(raw.read().starts_with(&tls_written(proxy)));
    assert!(raw.written().starts_with(&tls_read(proxy)));
    assert!(tunnel.read().starts_with(&tls_written(origin)));
    assert!(tunnel.written().starts_with(&tls_read(origin)));
    assert_eq!(tls_written(origin).first(), Some(&0x16));
    assert_eq!(
        *connected,
        Event::Connected {
            remote_addr: Some(addr),
            alpn: Some(b"http/1.1".to_vec()),
            tls_version: Some(TlsVersion::TLS_1_3),
        }
    );
    let written = concat(plaintext, |event| match event {
        Event::Write(bytes) => Some(bytes),
        _ => None,
    });
    assert_eq!(written, plain.read());
}

#[tokio::test]
async fn closes_attempts_that_fail_during_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Reject the ClientHello by closing the connection.
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = socket.read(&mut [0; 1024]).await.unwrap();
    });

    let events = Arc::new(Events::default());
    let client = client(&events).no_proxy().build().unwrap();
    assert!(
        client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .is_err()
    );
    server.await.unwrap();

    let events = events.closed(None).await;
    assert_eq!(events[0], Event::Handshake("localhost".to_owned()));
    assert!(!tls_written(&events).is_empty());
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Connected { .. }))
    );
}
