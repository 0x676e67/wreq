//! Hyper SSL support via BoringSSL.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]
mod cache;
pub mod layer;

pub use self::layer::*;
use crate::tls::TlsResult;
use crate::util::client::connect::{Connected, Connection};
use crate::util::rt::TokioIo;
use crate::HttpVersionPref;
use boring::ex_data::Index;
use boring::ssl::Ssl;
use cache::SessionKey;
use hyper2::rt::{Read, ReadBufCursor, Write};
use std::fmt;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use tokio::io;
use tokio_boring::SslStream;

fn key_index() -> TlsResult<Index<Ssl, SessionKey>> {
    static IDX: LazyLock<TlsResult<Index<Ssl, SessionKey>>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Settings for [`HttpsLayer`]
pub struct HttpsLayerSettings {
    session_cache_capacity: usize,
    session_cache: bool,
    skip_session_ticket: bool,
    application_settings: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    alpn_protos: HttpVersionPref,
    tls_sni: bool,
}

impl HttpsLayerSettings {
    /// Constructs an [`HttpsLayerSettingsBuilder`] for configuring settings
    pub fn builder() -> HttpsLayerSettingsBuilder {
        HttpsLayerSettingsBuilder(HttpsLayerSettings::default())
    }
}

impl Default for HttpsLayerSettings {
    fn default() -> Self {
        Self {
            session_cache_capacity: 8,
            session_cache: false,
            skip_session_ticket: false,
            application_settings: false,
            enable_ech_grease: false,
            verify_hostname: true,
            tls_sni: true,
            alpn_protos: HttpVersionPref::All,
        }
    }
}

/// Builder for [`HttpsLayerSettings`]
pub struct HttpsLayerSettingsBuilder(HttpsLayerSettings);

impl HttpsLayerSettingsBuilder {
    /// Sets maximum number of sessions to cache. Session capacity is per session key (domain).
    /// Defaults to 8.
    pub fn session_cache_capacity(mut self, capacity: usize) -> Self {
        self.0.session_cache_capacity = capacity;
        self
    }

    /// Sets whether to enable session caching. Defaults to `false`.
    pub fn session_cache(mut self, enable: bool) -> Self {
        self.0.session_cache = enable;
        self
    }

    /// Sets whether to enable no session ticket. Defaults to `false`.
    pub fn skip_session_ticket(mut self, enable: bool) -> Self {
        self.0.skip_session_ticket = enable;
        self
    }

    /// Sets whether to enable application settings. Defaults to `false`.
    pub fn application_settings(mut self, enable: bool) -> Self {
        self.0.application_settings = enable;
        self
    }

    /// Sets whether to enable ECH grease. Defaults to `false`.
    pub fn enable_ech_grease(mut self, enable: bool) -> Self {
        self.0.enable_ech_grease = enable;
        self
    }

    /// Sets whether to enable TLS SNI. Defaults to `true`.
    pub fn tls_sni(mut self, enable: bool) -> Self {
        self.0.tls_sni = enable;
        self
    }

    /// Sets whether to enable hostname verification. Defaults to `true`.
    pub fn verify_hostname(mut self, enable: bool) -> Self {
        self.0.verify_hostname = enable;
        self
    }

    /// Sets the ALPN protos. Defaults to `None`.
    pub fn alpn_protos(mut self, protos: HttpVersionPref) -> Self {
        self.0.alpn_protos = protos;
        self
    }

    /// Consumes the builder, returning a new [`HttpsLayerSettings`]
    pub fn build(self) -> HttpsLayerSettings {
        self.0
    }
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
