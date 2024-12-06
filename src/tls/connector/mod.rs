#![allow(missing_debug_implementations)]
#![allow(missing_docs)]
mod cache;

/// referrer: https://github.com/cloudflare/boring/blob/master/hyper-boring/src/lib.rs
use antidote::Mutex;
use boring::ex_data::Index;
use boring::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslRef, SslSessionCacheMode,
};

use super::TlsResult;
use cache::{SessionCache, SessionKey};
use http::uri::Scheme;
use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use hyper::Uri;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::{error::Error, fmt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_boring::SslStream;
use tower_layer::Layer;

fn key_index() -> TlsResult<Index<Ssl, SessionKey>> {
    static IDX: LazyLock<TlsResult<Index<Ssl, SessionKey>>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Option<Arc<Mutex<SessionCache>>>,
    callback: Option<Callback>,
    ssl_callback: Option<SslCallback>,
}

type Callback = Arc<dyn Fn(&mut ConnectConfiguration, &Uri) -> TlsResult<()> + Sync + Send>;
type SslCallback = Arc<dyn Fn(&mut SslRef, &Uri) -> TlsResult<()> + Sync + Send>;

impl Inner {
    fn setup_ssl(&self, uri: &Uri, host: &str) -> TlsResult<Ssl> {
        let mut conf = self.ssl.configure()?;

        if let Some(ref callback) = self.callback {
            callback(&mut conf, uri)?;
        }

        let key = SessionKey {
            host: host.to_string(),
            port: uri.port_u16().unwrap_or(443),
        };

        if let Some(ref cache) = self.cache {
            if let Some(session) = cache.lock().get(&key) {
                unsafe {
                    conf.set_session(&session)?;
                }
            }
        }

        let idx = key_index()?;
        conf.set_ex_data(idx, key);

        let mut ssl = conf.into_ssl(host)?;

        if let Some(ref ssl_callback) = self.ssl_callback {
            ssl_callback(&mut ssl, uri)?;
        }

        Ok(ssl)
    }
}

/// A layer which wraps services in an `HttpsConnector`.
#[derive(Clone)]
pub struct HttpsLayer {
    inner: Inner,
}

/// Settings for [`HttpsLayer`]
pub struct HttpsLayerSettings {
    session_cache_capacity: usize,
    session_cache: bool,
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
            session_cache: true,
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

    /// Sets whether to enable session caching. Defaults to `true`.
    pub fn session_cache(mut self, enable: bool) -> Self {
        self.0.session_cache = enable;
        self
    }

    /// Consumes the builder, returning a new [`HttpsLayerSettings`]
    pub fn build(self) -> HttpsLayerSettings {
        self.0
    }
}

impl HttpsLayer {
    /// Creates a new `HttpsLayer` with settings
    pub fn with_connector_and_settings(
        mut ssl: SslConnectorBuilder,
        settings: HttpsLayerSettings,
    ) -> TlsResult<HttpsLayer> {
        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = if settings.session_cache {
            let cache = Arc::new(Mutex::new(SessionCache::with_capacity(
                settings.session_cache_capacity,
            )));

            ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

            ssl.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Some(key) = key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                        cache.lock().insert(key.clone(), session);
                    }
                }
            });

            Some(cache)
        } else {
            None
        };

        Ok(HttpsLayer {
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: None,
                ssl_callback: None,
            },
        })
    }
}

impl<S> Layer<S> for HttpsLayer {
    type Service = HttpsConnector<S>;

    fn layer(&self, inner: S) -> HttpsConnector<S> {
        HttpsConnector {
            http: inner,
            inner: self.inner.clone(),
        }
    }
}

/// A Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new `HttpsConnector` with a given `HttpConnector`
    pub fn with_connector_layer(http: S, layer: HttpsLayer) -> HttpsConnector<S> {
        HttpsConnector {
            http,
            inner: layer.inner,
        }
    }

    /// Configures the SSL context for a given URI.
    pub fn setup_ssl(&self, uri: &Uri, host: &str) -> TlsResult<Ssl> {
        self.inner.setup_ssl(uri, host)
    }

    /// Registers a callback which can customize the configuration of each connection.
    ///
    /// Unsuitable to change verify hostflags (with `config.param_mut().set_hostflags(…)`),
    /// as they are reset after the callback is executed. Use [`Self::set_ssl_callback`]
    /// instead.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> TlsResult<()> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    S::Response: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<S::Response>;
    type Error = Box<dyn Error + Sync + Send>;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls_scheme = uri
            .scheme()
            .map(|s| s == &Scheme::HTTPS || s.as_str() == "wss")
            .unwrap_or(false);

        let tls_setup = if is_tls_scheme {
            Some((self.inner.clone(), uri.clone()))
        } else {
            None
        };

        let connect = self.http.call(uri);

        let f = async {
            let conn = connect.await.map_err(Into::into)?;

            let (inner, uri) = match tls_setup {
                Some((inner, uri)) => (inner, uri),
                None => return Ok(MaybeHttpsStream::Http(conn)),
            };

            let mut host = uri.host().ok_or("URI missing host")?;

            // If `host` is an IPv6 address, we must strip away the square brackets that surround
            // it (otherwise, boring will fail to parse the host as an IP address, eventually
            // causing the handshake to fail due a hostname verification error).
            if !host.is_empty() {
                let last = host.len() - 1;
                let mut chars = host.chars();

                if let (Some('['), Some(']')) = (chars.next(), chars.last()) {
                    if host[1..last].parse::<net::Ipv6Addr>().is_ok() {
                        host = &host[1..last];
                    }
                }
            }

            let ssl = inner.setup_ssl(&uri, host)?;
            let stream = tokio_boring::SslStreamBuilder::new(ssl, conn)
                .connect()
                .await?;

            Ok(MaybeHttpsStream::Https(stream))
        };

        Box::pin(f)
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(ctx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(ctx),
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
                let mut connected = s.get_ref().connected();

                if s.ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }

                connected
            }
        }
    }
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}
