mod v4;
mod v5;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use http::Uri;
use pin_project_lite::pin_project;
use tower_service::Service;
use v4::{SocksV4, SocksV4Error};
use v5::{SocksV5, SocksV5Error};

use crate::core::{
    client::connect::dns::{GaiResolver, Resolve},
    rt::{Read, Write},
};

#[derive(Debug)]
pub enum SocksError<C> {
    Inner(C),
    Io(std::io::Error),

    DnsFailure,
    MissingHost,

    V4(SocksV4Error),
    V5(SocksV5Error),

    Parsing(ParsingError),
    Serialize(SerializeError),
}

#[derive(Debug)]
pub enum ParsingError {
    Incomplete,
    WouldOverflow,
    Other,
}

#[derive(Debug)]
pub enum SerializeError {
    WouldOverflow,
}

async fn read_message<T, M, C>(mut conn: &mut T, buf: &mut BytesMut) -> Result<M, SocksError<C>>
where
    T: Read + Unpin,
    M: for<'a> TryFrom<&'a mut BytesMut, Error = ParsingError>,
{
    let mut tmp = [0; 513];

    loop {
        let n = crate::core::rt::read(&mut conn, &mut tmp).await?;
        buf.extend_from_slice(&tmp[..n]);

        match M::try_from(buf) {
            Err(ParsingError::Incomplete) => {
                if n == 0 {
                    if buf.spare_capacity_mut().is_empty() {
                        return Err(SocksError::Parsing(ParsingError::WouldOverflow));
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected eof",
                        )
                        .into());
                    }
                }
            }
            Err(err) => return Err(err.into()),
            Ok(res) => return Ok(res),
        }
    }
}

impl<C> std::fmt::Display for SocksError<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SOCKS error: ")?;

        match self {
            Self::Inner(_) => f.write_str("failed to create underlying connection"),
            Self::Io(e) => f.write_fmt(format_args!("io error during SOCKS handshake: {e}")),

            Self::DnsFailure => f.write_str("could not resolve to acceptable address type"),
            Self::MissingHost => f.write_str("missing destination host"),

            Self::Parsing(e) => f.write_fmt(format_args!("failed parsing server response: {e:?}")),
            Self::Serialize(e) => f.write_fmt(format_args!("failed serialize request: {e:?}")),

            Self::V4(e) => e.fmt(f),
            Self::V5(e) => e.fmt(f),
        }
    }
}

impl<C: std::fmt::Debug + std::fmt::Display> std::error::Error for SocksError<C> {}

impl<C> From<std::io::Error> for SocksError<C> {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl<C> From<ParsingError> for SocksError<C> {
    fn from(err: ParsingError) -> Self {
        Self::Parsing(err)
    }
}

impl<C> From<SerializeError> for SocksError<C> {
    fn from(err: SerializeError) -> Self {
        Self::Serialize(err)
    }
}

impl<C> From<SocksV4Error> for SocksError<C> {
    fn from(err: SocksV4Error) -> Self {
        Self::V4(err)
    }
}

impl<C> From<SocksV5Error> for SocksError<C> {
    fn from(err: SocksV5Error) -> Self {
        Self::V5(err)
    }
}

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    #[allow(missing_debug_implementations)]
    pub struct Handshaking<F, T, E> {
        #[pin]
        fut: BoxHandshaking<T, E>,
        _marker: std::marker::PhantomData<F>
    }
}

type BoxHandshaking<T, E> = Pin<Box<dyn Future<Output = Result<T, SocksError<E>>> + Send>>;

impl<F, T, E> Future for Handshaking<F, T, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, SocksError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

#[derive(Debug)]
pub enum Socks<C, R = GaiResolver> {
    SocksV5(SocksV5<C, R>),
    SocksV4(SocksV4<C, R>),
}

impl<C, R> Socks<C, R>
where
    R: Resolve + Clone,
{
    /// Create a new SOCKS service with the given inner service, resolver, proxy destination,
    /// and optional authentication credentials.
    ///
    /// The `proxy_dst` should be a valid URI with a scheme of `socks5`, `socks5h`, `socks4`, or
    /// `socks4a`.
    ///
    /// The `auth` parameter is optional and can be used to provide a username and password for
    /// SOCKS authentication. If provided, it should be a tuple containing the username and
    /// password.
    pub fn new_with_resolver(
        inner: C,
        resolver: R,
        proxy_dst: Uri,
        auth: Option<(Bytes, Bytes)>,
    ) -> Self {
        let scheme = proxy_dst.scheme_str();
        let (is_v5, local_dns) = match scheme {
            Some("socks5") => (true, true),
            Some("socks5h") => (true, false),
            Some("socks4") => (false, true),
            Some("socks4a") => (false, false),
            _ => unreachable!("connect_socks is only called for socks proxies"),
        };

        if is_v5 {
            let mut v5 =
                SocksV5::new_with_resolver(proxy_dst, inner, resolver).local_dns(local_dns);
            if let Some((user, pass)) = auth {
                v5 = v5.with_auth(user, pass);
            }

            Self::SocksV5(v5)
        } else {
            let v4 = SocksV4::new_with_resolver(proxy_dst, inner, resolver).local_dns(local_dns);
            Self::SocksV4(v4)
        }
    }
}

impl<C, R> Service<Uri> for Socks<C, R>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + Sync + 'static,
    R: Resolve + Clone + Send + 'static,
    <R as Resolve>::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::SocksV5(socks_v5) => socks_v5.poll_ready(cx),
            Self::SocksV4(socks_v4) => socks_v4.poll_ready(cx),
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        match self {
            Self::SocksV5(socks_v5) => socks_v5.call(dst),
            Self::SocksV4(socks_v4) => socks_v4.call(dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tower_service::Service;

    use super::{SocksV4, SocksV5};
    use crate::core::client::connect::HttpConnector;

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v5_without_auth_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_dst = format!("http://{proxy_addr}").parse().expect("uri");

        let target_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target_addr = target_tcp.local_addr().expect("local_addr");
        let target_dst = format!("http://{target_addr}").parse().expect("uri");

        let mut connector = SocksV5::new(proxy_dst, HttpConnector::new());

        // Client
        //
        // Will use `SocksV5` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let conn = connector.call(target_dst).await.expect("tunnel");
            let mut tcp = conn.into_inner();

            tcp.write_all(b"Hello World!").await.expect("write 1");

            let mut buf = [0u8; 64];
            let n = tcp.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Goodbye!");
        });

        // Proxy
        //
        // Will receive CONNECT command from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 513];

            // negotiation req/res
            let n = to_client.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], [0x05, 0x01, 0x00]);

            to_client.write_all(&[0x05, 0x00]).await.expect("write 1");

            // command req/rs
            let [p1, p2] = target_addr.port().to_be_bytes();
            let [ip1, ip2, ip3, ip4] = [0x7f, 0x00, 0x00, 0x01];
            let message = [0x05, 0x01, 0x00, 0x01, ip1, ip2, ip3, ip4, p1, p2];
            let n = to_client.read(&mut buf).await.expect("read 2");
            assert_eq!(&buf[..n], message);

            let mut to_target = TcpStream::connect(target_addr).await.expect("connect");

            let message = [0x05, 0x00, 0x00, 0x01, ip1, ip2, ip3, ip4, p1, p2];
            to_client.write_all(&message).await.expect("write 2");

            let (from_client, from_target) =
                tokio::io::copy_bidirectional(&mut to_client, &mut to_target)
                    .await
                    .expect("proxy");

            assert_eq!(from_client, 12);
            assert_eq!(from_target, 8)
        });

        // Target server
        //
        // Will accept connection from proxy server
        // Will receive "Hello World!" from the client and return "Goodbye!"
        let t3 = tokio::spawn(async move {
            let (mut io, _) = target_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 64];

            let n = io.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Hello World!");

            io.write_all(b"Goodbye!").await.expect("write 1");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
        t3.await.expect("task - target");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v5_with_auth_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_dst = format!("http://{proxy_addr}").parse().expect("uri");

        let target_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target_addr = target_tcp.local_addr().expect("local_addr");
        let target_dst = format!("http://{target_addr}").parse().expect("uri");

        let mut connector = SocksV5::new(proxy_dst, HttpConnector::new()).with_auth("user", "pass");

        // Client
        //
        // Will use `SocksV5` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let conn = connector.call(target_dst).await.expect("tunnel");
            let mut tcp = conn.into_inner();

            tcp.write_all(b"Hello World!").await.expect("write 1");

            let mut buf = [0u8; 64];
            let n = tcp.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Goodbye!");
        });

        // Proxy
        //
        // Will receive CONNECT command from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 513];

            // negotiation req/res
            let n = to_client.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], [0x05, 0x01, 0x02]);

            to_client.write_all(&[0x05, 0x02]).await.expect("write 1");

            // auth req/res
            let n = to_client.read(&mut buf).await.expect("read 2");
            let [u1, u2, u3, u4] = b"user";
            let [p1, p2, p3, p4] = b"pass";
            let message = [0x01, 0x04, *u1, *u2, *u3, *u4, 0x04, *p1, *p2, *p3, *p4];
            assert_eq!(&buf[..n], message);

            to_client.write_all(&[0x01, 0x00]).await.expect("write 2");

            // command req/res
            let n = to_client.read(&mut buf).await.expect("read 3");
            let [p1, p2] = target_addr.port().to_be_bytes();
            let [ip1, ip2, ip3, ip4] = [0x7f, 0x00, 0x00, 0x01];
            let message = [0x05, 0x01, 0x00, 0x01, ip1, ip2, ip3, ip4, p1, p2];
            assert_eq!(&buf[..n], message);

            let mut to_target = TcpStream::connect(target_addr).await.expect("connect");

            let message = [0x05, 0x00, 0x00, 0x01, ip1, ip2, ip3, ip4, p1, p2];
            to_client.write_all(&message).await.expect("write 3");

            let (from_client, from_target) =
                tokio::io::copy_bidirectional(&mut to_client, &mut to_target)
                    .await
                    .expect("proxy");

            assert_eq!(from_client, 12);
            assert_eq!(from_target, 8)
        });

        // Target server
        //
        // Will accept connection from proxy server
        // Will receive "Hello World!" from the client and return "Goodbye!"
        let t3 = tokio::spawn(async move {
            let (mut io, _) = target_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 64];

            let n = io.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Hello World!");

            io.write_all(b"Goodbye!").await.expect("write 1");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
        t3.await.expect("task - target");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v5_with_server_resolved_domain_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_addr = format!("http://{proxy_addr}").parse().expect("uri");

        let mut connector = SocksV5::new(proxy_addr, HttpConnector::new())
            .with_auth("user", "pass")
            .local_dns(false);

        // Client
        //
        // Will use `SocksV5` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let _conn = connector
                .call("https://hyper.rs:443".try_into().unwrap())
                .await
                .expect("tunnel");
        });

        // Proxy
        //
        // Will receive CONNECT command from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 513];

            // negotiation req/res
            let n = to_client.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], [0x05, 0x01, 0x02]);

            to_client.write_all(&[0x05, 0x02]).await.expect("write 1");

            // auth req/res
            let n = to_client.read(&mut buf).await.expect("read 2");
            let [u1, u2, u3, u4] = b"user";
            let [p1, p2, p3, p4] = b"pass";
            let message = [0x01, 0x04, *u1, *u2, *u3, *u4, 0x04, *p1, *p2, *p3, *p4];
            assert_eq!(&buf[..n], message);

            to_client.write_all(&[0x01, 0x00]).await.expect("write 2");

            // command req/res
            let n = to_client.read(&mut buf).await.expect("read 3");

            let host = "hyper.rs";
            let port: u16 = 443;
            let mut message = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            message.extend(host.bytes());
            message.extend(port.to_be_bytes());
            assert_eq!(&buf[..n], message);

            let mut message = vec![0x05, 0x00, 0x00, 0x03, host.len() as u8];
            message.extend(host.bytes());
            message.extend(port.to_be_bytes());
            to_client.write_all(&message).await.expect("write 3");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v5_with_locally_resolved_domain_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_addr = format!("http://{proxy_addr}").parse().expect("uri");

        let mut connector = SocksV5::new(proxy_addr, HttpConnector::new())
            .with_auth("user", "pass")
            .local_dns(true);

        // Client
        //
        // Will use `SocksV5` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let _conn = connector
                .call("https://hyper.rs:443".try_into().unwrap())
                .await
                .expect("tunnel");
        });

        // Proxy
        //
        // Will receive CONNECT command from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 513];

            // negotiation req/res
            let n = to_client.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], [0x05, 0x01, 0x02]);

            to_client.write_all(&[0x05, 0x02]).await.expect("write 1");

            // auth req/res
            let n = to_client.read(&mut buf).await.expect("read 2");
            let [u1, u2, u3, u4] = b"user";
            let [p1, p2, p3, p4] = b"pass";
            let message = [0x01, 0x04, *u1, *u2, *u3, *u4, 0x04, *p1, *p2, *p3, *p4];
            assert_eq!(&buf[..n], message);

            to_client.write_all(&[0x01, 0x00]).await.expect("write 2");

            // command req/res
            let n = to_client.read(&mut buf).await.expect("read 3");
            let message = [0x05, 0x01, 0x00, 0x01];
            assert_eq!(&buf[..4], message);
            assert_eq!(n, 4 + 4 + 2);

            let message = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            to_client.write_all(&message).await.expect("write 3");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v4_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_dst = format!("http://{proxy_addr}").parse().expect("uri");

        let target_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target_addr = target_tcp.local_addr().expect("local_addr");
        let target_dst = format!("http://{target_addr}").parse().expect("uri");

        let mut connector = SocksV4::new(proxy_dst, HttpConnector::new());

        // Client
        //
        // Will use `SocksV4` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let conn = connector.call(target_dst).await.expect("tunnel");
            let mut tcp = conn.into_inner();

            tcp.write_all(b"Hello World!").await.expect("write 1");

            let mut buf = [0u8; 64];
            let n = tcp.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Goodbye!");
        });

        // Proxy
        //
        // Will receive CONNECT command from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 512];

            let [p1, p2] = target_addr.port().to_be_bytes();
            let [ip1, ip2, ip3, ip4] = [127, 0, 0, 1];
            let message = [4, 0x01, p1, p2, ip1, ip2, ip3, ip4, 0, 0];
            let n = to_client.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..n], message);

            let mut to_target = TcpStream::connect(target_addr).await.expect("connect");

            let message = [0, 90, p1, p2, ip1, ip2, ip3, ip4];
            to_client.write_all(&message).await.expect("write");

            let (from_client, from_target) =
                tokio::io::copy_bidirectional(&mut to_client, &mut to_target)
                    .await
                    .expect("proxy");

            assert_eq!(from_client, 12);
            assert_eq!(from_target, 8)
        });

        // Target server
        //
        // Will accept connection from proxy server
        // Will receive "Hello World!" from the client and return "Goodbye!"
        let t3 = tokio::spawn(async move {
            let (mut io, _) = target_tcp.accept().await.expect("accept");
            let mut buf = [0u8; 64];

            let n = io.read(&mut buf).await.expect("read 1");
            assert_eq!(&buf[..n], b"Hello World!");

            io.write_all(b"Goodbye!").await.expect("write 1");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
        t3.await.expect("task - target");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn test_socks_v5_optimistic_works() {
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy_tcp.local_addr().expect("local_addr");
        let proxy_dst = format!("http://{proxy_addr}").parse().expect("uri");

        let target_addr = std::net::SocketAddr::new([127, 0, 0, 1].into(), 1234);
        let target_dst = format!("http://{target_addr}").parse().expect("uri");

        let mut connector = SocksV5::new(proxy_dst, HttpConnector::new())
            .with_auth("ABC", "XYZ")
            .send_optimistically(true);

        // Client
        //
        // Will use `SocksV5` to establish proxy tunnel.
        // Will send "Hello World!" to the target and receive "Goodbye!" back.
        let t1 = tokio::spawn(async move {
            let _ = connector.call(target_dst).await.expect("tunnel");
        });

        // Proxy
        //
        // Will receive SOCKS handshake from client.
        // Will connect to target and success code back to client.
        // Will blindly tunnel between client and target.
        let t2 = tokio::spawn(async move {
            let (mut to_client, _) = proxy_tcp.accept().await.expect("accept");
            let [p1, p2] = target_addr.port().to_be_bytes();

            let mut buf = [0; 22];
            let request = vec![
                5, 1, 2, // Negotiation
                1, 3, 65, 66, 67, 3, 88, 89, 90, // Auth ("ABC"/"XYZ")
                5, 1, 0, 1, 127, 0, 0, 1, p1, p2, // Reply
            ];

            let response = vec![
                5, 2, // Negotiation,
                1, 0, // Auth,
                5, 0, 0, 1, 127, 0, 0, 1, p1, p2, // Reply
            ];

            // Accept all handshake messages
            to_client.read_exact(&mut buf).await.expect("read");
            assert_eq!(request.as_slice(), buf);

            // Send all handshake messages back
            to_client
                .write_all(response.as_slice())
                .await
                .expect("write");

            to_client.flush().await.expect("flush");
        });

        t1.await.expect("task - client");
        t2.await.expect("task - proxy");
    }
}
