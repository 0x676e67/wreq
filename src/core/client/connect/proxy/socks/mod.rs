mod v5;

use http::Uri;
use pin_project_lite::pin_project;
use std::{
    error::Error as StdError,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use tower_service::Service;
pub use v5::{SocksV5, SocksV5Error};

mod v4;
pub use v4::{SocksV4, SocksV4Error};

use bytes::BytesMut;

use crate::core::rt::{Read, Write};

#[derive(Debug)]
pub enum SocksError<C> {
    Inner(C),
    Io(std::io::Error),

    DnsFailure,
    MissingHost,
    MissingPort,

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
            Self::Io(_) => f.write_str("io error during SOCKS handshake"),

            Self::DnsFailure => f.write_str("could not resolve to acceptable address type"),
            Self::MissingHost => f.write_str("missing destination host"),
            Self::MissingPort => f.write_str("missing destination port"),

            Self::Parsing(_) => f.write_str("failed parsing server response"),
            Self::Serialize(_) => f.write_str("failed serialize request"),

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
pub struct Socks<C> {
    inner: Inner<C>,
    proxy_dst: Uri,
}

#[derive(Debug)]
enum Inner<C> {
    SocksV5(SocksV5<C>),
    SocksV4(SocksV4<C>),
}

impl<C> Socks<C> {
    pub fn new(inner: C, proxy_dst: Uri, auth: Option<(&str, &str)>) -> Self {
        let scheme = proxy_dst.scheme_str();
        let (is_v5, local_dns) = match scheme {
            Some("socks5") => (true, true),
            Some("socks5h") => (true, false),
            Some("socks4") => (false, true),
            Some("socks4a") => (false, false),
            _ => unreachable!("connect_socks is only called for socks proxies"),
        };

        let inner = if is_v5 {
            let mut v5 = SocksV5::new(proxy_dst.clone(), inner).local_dns(local_dns);
            if let Some((user, pass)) = auth {
                v5 = v5.with_auth(user.to_owned(), pass.to_owned());
            }
            Inner::SocksV5(v5)
        } else {
            let v4 = SocksV4::new(proxy_dst.clone(), inner).local_dns(local_dns);
            Inner::SocksV4(v4)
        };

        Self { inner, proxy_dst }
    }
}

impl<C> Service<Uri> for Socks<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + Sync + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            Inner::SocksV5(socks_v5) => {
                std::task::ready!(socks_v5.poll_ready(cx))?;
            }
            Inner::SocksV4(socks_v4) => {
                std::task::ready!(socks_v4.poll_ready(cx))?;
            }
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        Handshaking {
            fut: match &mut self.inner {
                Inner::SocksV5(socks_v5) => Box::pin(socks_v5.call(dst)),
                Inner::SocksV4(socks_v4) => Box::pin(socks_v4.call(dst)),
            },
            _marker: Default::default(),
        }
    }
}
