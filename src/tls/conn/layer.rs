/// referrer: https://github.com/cloudflare/boring/blob/master/hyper-boring/src/lib.rs
use super::cache::{SessionCache, SessionKey};
use super::{key_index, HttpsLayerSettings, MaybeHttpsStream};
use crate::cfg_bindable_device;
use crate::connect::HttpConnector;
use crate::error::BoxError;
use crate::tls::ext::SslRefExt;
use crate::tls::{AlpnProtos, BoringTlsConnector, ConnectConfigurationExt};
use crate::util::client::connect::Connection;
use crate::util::rt::TokioIo;
use antidote::Mutex;
use boring::error::ErrorStack;
use boring::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslRef, SslSessionCacheMode,
};
use http::uri::Scheme;
use http::Uri;
use hyper2::rt::{Read, Write};
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use tokio_boring::SslStream;

use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;

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
    pub fn with_alpn_protos(mut self, alpn_protos: Option<AlpnProtos>) -> Self {
        self.alpn_protos = alpn_protos;
        self
    }

    #[inline]
    pub fn with_addresses(mut self, (ipv4, ipv6): (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
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
    pub fn with_interface(mut self, _interface: Option<Cow<'static, str>>) -> Self {
        cfg_bindable_device! {
            self.http.set_interface(_interface);
        }
        self
    }

    #[inline]
    pub(crate) fn build(self, tls: BoringTlsConnector) -> HttpsConnector<HttpConnector> {
        let mut connector = HttpsConnector::with_connector_layer(self.http, tls.0);
        connector.set_ssl_callback(move |ssl, _| ssl.alpn_protos(self.alpn_protos));
        connector
    }
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl HttpsConnector<HttpConnector> {
    /// Creates a new `HttpsConnectorBuilder`
    pub fn builder(http: HttpConnector) -> HttpsConnectorBuilder {
        HttpsConnectorBuilder::new(http)
    }
}

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: Read + Write + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new `HttpsConnector` with a given `HttpConnector`
    pub fn with_connector_layer(http: S, layer: HttpsLayer) -> HttpsConnector<S> {
        HttpsConnector {
            http,
            inner: layer.inner,
        }
    }

    /// Registers a callback which can customize the SSL context for a given URI.
    ///
    /// This callback is executed after the callback registered by [`Self::set_ssl_callback`] is executed.
    #[inline]
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.ssl_callback = Some(Arc::new(callback));
    }

    /// Connects to the given URI using the given connection.
    ///
    /// This function is used to connect to the given URI using the given connection.
    #[inline]
    pub async fn connect<A>(
        &self,
        uri: &Uri,
        host: &str,
        conn: A,
    ) -> Result<SslStream<TokioIo<A>>, BoxError>
    where
        A: Read + Write + Unpin + Send + Sync + Debug + 'static,
    {
        self.inner.connect(uri, host, conn).await
    }
}

/// A layer which wraps services in an `HttpsConnector`.
#[derive(Clone)]
pub struct HttpsLayer {
    inner: Inner,
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Option<Arc<Mutex<SessionCache>>>,
    callback: Option<Callback>,
    ssl_callback: Option<SslCallback>,
    skip_session_ticket: bool,
}

type Callback =
    Arc<dyn Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + Sync + Send>;
type SslCallback = Arc<dyn Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + Sync + Send>;

impl HttpsLayer {
    /// Creates a new `HttpsLayer` with settings
    pub fn with_connector_and_settings(
        mut ssl: SslConnectorBuilder,
        settings: HttpsLayerSettings,
    ) -> HttpsLayer {
        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = if settings.session_cache {
            let cache = Arc::new(Mutex::new(SessionCache::with_capacity(
                settings.session_cache_capacity,
            )));

            ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

            ssl.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.lock().insert(key.clone(), session);
                    }
                }
            });

            Some(cache)
        } else {
            None
        };

        let callback = Arc::new(move |conf: &mut ConnectConfiguration, _: &Uri| {
            // Set ECH grease
            conf.enable_ech_grease(settings.enable_ech_grease)?;

            // Use server name indication
            conf.set_use_server_name_indication(settings.tls_sni);

            // Verify hostname
            conf.set_verify_hostname(settings.verify_hostname);

            // Set ALPS
            conf.alps_proto(settings.alps_proto)?;

            Ok(())
        });

        HttpsLayer {
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: Some(callback),
                ssl_callback: None,
                skip_session_ticket: settings.skip_session_ticket,
            },
        }
    }
}

impl Inner {
    /// Connects to the given URI using the given connection.
    ///
    /// This function is used to connect to the given URI using the given connection.
    pub async fn connect<A>(
        &self,
        uri: &Uri,
        host: &str,
        conn: A,
    ) -> Result<SslStream<TokioIo<A>>, BoxError>
    where
        A: Read + Write + Unpin + Send + Sync + Debug + 'static,
    {
        let ssl = self.setup_ssl(uri, host)?;
        tokio_boring::SslStreamBuilder::new(ssl, TokioIo::new(conn))
            .connect()
            .await
            .map_err(Into::into)
    }

    fn setup_ssl(&self, uri: &Uri, host: &str) -> Result<Ssl, ErrorStack> {
        let mut conf = self.ssl.configure()?;

        if let Some(ref callback) = self.callback {
            callback(&mut conf, uri)?;
        }

        if let Some(authority) = uri.authority() {
            let key = SessionKey(authority.clone());

            if let Some(ref cache) = self.cache {
                if let Some(session) = cache.lock().get(&key) {
                    unsafe {
                        conf.set_session(&session)?;
                    }

                    if self.skip_session_ticket {
                        conf.skip_session_ticket()?;
                    }
                }
            }

            let idx = key_index()?;
            conf.set_ex_data(idx, key);
        }

        let mut ssl = conf.into_ssl(host)?;

        if let Some(ref ssl_callback) = self.ssl_callback {
            ssl_callback(&mut ssl, uri)?;
        }

        Ok(ssl)
    }
}

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: Read + Write + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = Box<dyn Error + Sync + Send>;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        // Early return if it is not a tls scheme
        if uri.scheme() != Some(&Scheme::HTTPS) {
            let connect = self.http.call(uri);
            return Box::pin(async move {
                let conn = connect.await.map_err(Into::into)?;
                Ok(MaybeHttpsStream::Http(conn))
            });
        }

        let connect = self.http.call(uri.clone());
        let inner = self.inner.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?;

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

            inner
                .connect(&uri, host, conn)
                .await
                .map(TokioIo::new)
                .map(MaybeHttpsStream::Https)
        };

        Box::pin(f)
    }
}
