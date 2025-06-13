//! Hyper SSL support via BoringSSL.
mod boring;
mod cache;
mod ext;

use std::{
    fmt,
    io::IoSlice,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
};

use boring2::{error::ErrorStack, ex_data::Index, ssl::Ssl};
use cache::SessionKey;
use tokio::io;
use tokio_boring2::SslStream;

pub use self::boring::{HttpsConnector, TlsConnector};
use crate::{
    core::{
        client::connect::{Connected, Connection},
        rt::{Read, ReadBufCursor, TokioIo, Write},
    },
    tls::AlpsProtos,
};

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, SessionKey>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Builds for [`HandshakeSettings`].
pub struct HandshakeSettingsBuilder {
    settings: HandshakeSettings,
}

/// Settings for [`TlsConnector`]
pub struct HandshakeSettings {
    session_cache_capacity: usize,
    session_cache: bool,
    skip_session_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alps_protos: Option<AlpsProtos>,
    alps_use_new_codepoint: bool,
    random_aes_hw_override: bool,
}

impl HandshakeSettingsBuilder {
    /// Sets the session cache capacity.
    pub fn session_cache_capacity(mut self, capacity: usize) -> Self {
        self.settings.session_cache_capacity = capacity;
        self
    }

    /// Enables or disables session cache.
    pub fn session_cache(mut self, enabled: bool) -> Self {
        self.settings.session_cache = enabled;
        self
    }

    /// Skips the session ticket.
    pub fn skip_session_ticket(mut self, skip: bool) -> Self {
        self.settings.skip_session_ticket = skip;
        self
    }

    /// Enables or disables ECH grease.
    pub fn enable_ech_grease(mut self, enable: bool) -> Self {
        self.settings.enable_ech_grease = enable;
        self
    }

    /// Sets hostname verification.
    pub fn verify_hostname(mut self, verify: bool) -> Self {
        self.settings.verify_hostname = verify;
        self
    }

    /// Sets TLS SNI.
    pub fn tls_sni(mut self, sni: bool) -> Self {
        self.settings.tls_sni = sni;
        self
    }

    /// Sets ALPS protocol.
    pub fn alps_protos(mut self, protos: Option<AlpsProtos>) -> Self {
        self.settings.alps_protos = protos;
        self
    }

    /// Sets ALPS new codepoint usage.
    pub fn alps_use_new_codepoint(mut self, use_new: bool) -> Self {
        self.settings.alps_use_new_codepoint = use_new;
        self
    }

    /// Sets random AES hardware override.
    pub fn random_aes_hw_override(mut self, override_: bool) -> Self {
        self.settings.random_aes_hw_override = override_;
        self
    }

    /// Builds the `HandshakeSettings`.
    pub fn build(self) -> HandshakeSettings {
        self.settings
    }
}

impl HandshakeSettings {
    /// Creates a new `HandshakeSettingsBuilder`.
    pub fn builder() -> HandshakeSettingsBuilder {
        HandshakeSettingsBuilder {
            settings: HandshakeSettings::default(),
        }
    }
}

impl Default for HandshakeSettings {
    fn default() -> Self {
        Self {
            session_cache_capacity: 8,
            session_cache: false,
            skip_session_ticket: false,
            enable_ech_grease: false,
            verify_hostname: true,
            tls_sni: true,
            alps_protos: None,
            alps_use_new_codepoint: false,
            random_aes_hw_override: false,
        }
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
