//! Hyper SSL support via BoringSSL.
mod boring;
mod cache;

use crate::tls::{AlpsProtos, TlsResult};
use crate::util::client::connect::{Connected, Connection};
use crate::util::rt::TokioIo;

use boring2::ex_data::Index;
use boring2::ssl::Ssl;
use cache::SessionKey;
use hyper2::rt::{Read, ReadBufCursor, Write};
use std::fmt;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use tokio::io;
use tokio_boring2::SslStream;
use typed_builder::TypedBuilder;

pub use self::boring::{BoringTlsConnector, HttpsConnector};

fn key_index() -> TlsResult<Index<Ssl, SessionKey>> {
    static IDX: LazyLock<TlsResult<Index<Ssl, SessionKey>>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Settings for [`BoringTlsConnector`]
#[derive(TypedBuilder)]
pub struct HandshakeSettings {
    /// Sets whether to enable session caching capacity. Defaults to `8`.
    #[builder(default = 8)]
    session_cache_capacity: usize,

    /// Sets whether to enable session caching. Defaults to `false`.
    #[builder(default = false)]
    session_cache: bool,

    /// Sets whether to enable no session ticket. Defaults to `false`.
    #[builder(default = false)]
    skip_session_ticket: bool,

    /// Sets whether to enable ECH grease. Defaults to `false`.
    #[builder(default = false)]
    enable_ech_grease: bool,

    /// Sets whether to enable hostname verification. Defaults to `true`.
    #[builder(default = true)]
    verify_hostname: bool,

    /// Sets whether to enable TLS SNI. Defaults to `true`.
    #[builder(default = true)]
    tls_sni: bool,

    /// Sets the ALPS. Defaults to `None`.
    #[builder(default = None)]
    alps_protos: Option<AlpsProtos>,

    /// Sets whether to use the new ALPS codepoint. Defaults to `false`.
    #[builder(default = false)]
    alps_use_new_codepoint: bool,

    /// Sets whether the random aes hardware override should be enabled.
    #[builder(default = false)]
    random_aes_hw_override: bool,
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(TokioIo<SslStream<TokioIo<T>>>),
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let mut connected = s.inner().get_ref().connected();

                if s.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }

                connected
            }
        }
    }
}

impl<T: Read + Write + Unpin> Read for MaybeHttpsStream<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: Write + Read + Unpin> Write for MaybeHttpsStream<T> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(s) => s.is_write_vectored(),
            MaybeHttpsStream::Https(s) => s.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
