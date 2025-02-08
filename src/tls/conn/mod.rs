//! Hyper SSL support via BoringSSL.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]
mod cache;
mod layer;

pub use self::layer::*;
use super::BoringTlsConnector;
use crate::connect::HttpConnector;
use crate::tls::ext::SslRefExt;
use crate::tls::{AlpnProtos, AlpsProtos, TlsResult};
use crate::util::client::connect::{Connected, Connection};
use crate::util::rt::TokioIo;
use boring2::ex_data::Index;
use boring2::ssl::Ssl;
use cache::SessionKey;
use hyper2::rt::{Read, ReadBufCursor, Write};
use std::borrow::Cow;
use std::fmt;
use std::io::IoSlice;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use tokio::io;
use tokio_boring2::SslStream;

fn key_index() -> TlsResult<Index<Ssl, SessionKey>> {
    static IDX: LazyLock<TlsResult<Index<Ssl, SessionKey>>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

pub(crate) struct HttpsConnectorBuilder {
    http: HttpConnector,
    alpn_protos: Option<AlpnProtos>,
}

impl HttpsConnectorBuilder {
    #[inline]
    pub fn new(http: HttpConnector) -> HttpsConnectorBuilder {
        HttpsConnectorBuilder {
            http,
            alpn_protos: None,
        }
    }

    #[inline]
    pub fn alpn_protos(mut self, alpn_protos: Option<AlpnProtos>) -> Self {
        self.alpn_protos = alpn_protos;
        self
    }

    #[inline]
    pub fn addresses(mut self, (ipv4, ipv6): (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        match (ipv4, ipv6) {
            (Some(a), Some(b)) => self.http.set_local_addresses(a, b),
            (Some(a), None) => self.http.set_local_address(Some(IpAddr::V4(a))),
            (None, Some(b)) => self.http.set_local_address(Some(IpAddr::V6(b))),
            _ => (),
        }
        self
    }

    #[inline]
    #[allow(unused_mut)]
    pub fn interface(mut self, _interface: Option<Cow<'static, str>>) -> Self {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            all(
                feature = "apple-bindable-device",
                any(
                    target_os = "ios",
                    target_os = "visionos",
                    target_os = "macos",
                    target_os = "tvos",
                    target_os = "watchos",
                )
            )
        ))]
        self.http.set_interface(_interface);
        self
    }

    #[inline]
    pub(crate) fn build(self, tls: BoringTlsConnector) -> HttpsConnector<HttpConnector> {
        let mut connector = HttpsConnector::with_connector_layer(self.http, tls.0);
        connector.set_ssl_callback(move |ssl, _| ssl.alpn_protos(self.alpn_protos));
        connector
    }
}

/// Settings for [`HttpsLayer`]
pub struct HttpsLayerSettings {
    session_cache_capacity: usize,
    session_cache: bool,
    skip_session_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protos: AlpnProtos,
    alps_protos: Option<AlpsProtos>,
    alps_use_new_codepoint: bool,
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
            enable_ech_grease: false,
            verify_hostname: true,
            tls_sni: true,
            alpn_protos: AlpnProtos::ALL,
            alps_protos: None,
            alps_use_new_codepoint: false,
        }
    }
}

/// Builder for [`HttpsLayerSettings`]
pub struct HttpsLayerSettingsBuilder(HttpsLayerSettings);

impl HttpsLayerSettingsBuilder {
    /// Sets whether to enable session caching. Defaults to `false`.
    #[inline]
    pub fn session_cache(mut self, enable: bool) -> Self {
        self.0.session_cache = enable;
        self
    }

    /// Sets whether to enable no session ticket. Defaults to `false`.
    #[inline]
    pub fn skip_session_ticket(mut self, enable: bool) -> Self {
        self.0.skip_session_ticket = enable;
        self
    }

    /// Sets whether to enable ECH grease. Defaults to `false`.
    #[inline]
    pub fn enable_ech_grease(mut self, enable: bool) -> Self {
        self.0.enable_ech_grease = enable;
        self
    }

    /// Sets whether to enable TLS SNI. Defaults to `true`.
    #[inline]
    pub fn tls_sni(mut self, enable: bool) -> Self {
        self.0.tls_sni = enable;
        self
    }

    /// Sets whether to enable hostname verification. Defaults to `true`.
    #[inline]
    pub fn verify_hostname(mut self, enable: bool) -> Self {
        self.0.verify_hostname = enable;
        self
    }

    /// Sets the ALPN protos. Defaults to `None`.
    #[inline]
    pub fn alpn_protos(mut self, protos: AlpnProtos) -> Self {
        self.0.alpn_protos = protos;
        self
    }

    /// Sets the ALPS. Defaults to `None`.
    #[inline]
    pub fn alps_protos(mut self, alps: Option<AlpsProtos>) -> Self {
        self.0.alps_protos = alps;
        self
    }

    /// Sets whether to use the new ALPS codepoint. Defaults to `false`.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enable: bool) -> Self {
        self.0.alps_use_new_codepoint = enable;
        self
    }

    /// Consumes the builder, returning a new [`HttpsLayerSettings`]
    #[inline]
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
