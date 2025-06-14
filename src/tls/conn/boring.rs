//! backport: <https://github.com/cloudflare/boring/blob/master/hyper-boring/src/lib.rs>

use std::{
    error::Error,
    fmt::Debug,
    future::Future,
    net::{IpAddr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use antidote::Mutex;
use boring2::{
    error::ErrorStack,
    ssl::{
        ConnectConfiguration, SslConnector, SslConnectorBuilder, SslMethod, SslOptions, SslRef,
        SslSessionCacheMode,
    },
};
use http::{Uri, uri::Scheme};
use tokio_boring2::SslStream;
use tower_service::Service;

use super::{
    HandshakeSettings, MaybeHttpsStream,
    cache::{SessionCache, SessionKey},
    ext::{ConnectConfigurationExt, SslConnectorBuilderExt, SslRefExt},
    key_index,
};
use crate::{
    Dst,
    connect::HttpConnector,
    core::{
        client::connect::Connection,
        rt::{Read, TokioIo, Write},
    },
    error::BoxError,
    tls::{CertStore, Identity, KeyLogPolicy, TlsConfig},
};

type Callback =
    Arc<dyn Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + Sync + Send>;
type SslCallback = Arc<dyn Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + Sync + Send>;

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl HttpsConnector<HttpConnector> {
    /// Creates a new `HttpsConnector`
    pub fn new(
        mut http: HttpConnector,
        connector: TlsConnector,
        dst: &mut Dst,
    ) -> HttpsConnector<HttpConnector> {
        // Get the ALPN protocols from the destination
        let alpn_protos = dst.alpn_protos();

        // Set the local address and interface
        match dst.addresses() {
            (Some(a), Some(b)) => http.set_local_addresses(a, b),
            (Some(a), None) => http.set_local_address(Some(IpAddr::V4(a))),
            (None, Some(b)) => http.set_local_address(Some(IpAddr::V6(b))),
            _ => (),
        }

        // Set the interface
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        http.set_interface(dst.interface());

        let mut connector = HttpsConnector::with_connector(http, connector);
        connector.set_ssl_callback(move |ssl, _| ssl.alpn_protos(alpn_protos));
        connector
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
    pub fn with_connector(http: S, connector: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector {
            http,
            inner: connector.inner,
        }
    }

    /// Registers a callback which can customize the SSL context for a given URI.
    ///
    /// This callback is executed after the callback registered by [`Self::set_ssl_callback`] is
    /// executed.
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

/// A builder for creating a `TlsConnector`.
#[derive(Clone)]
pub struct TlsConnectorBuilder {
    keylog_policy: Option<KeyLogPolicy>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
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

impl TlsConnectorBuilder {
    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, policy: Option<KeyLogPolicy>) -> Self {
        self.keylog_policy = policy;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build(self, config: TlsConfig) -> crate::Result<TlsConnector> {
        let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())?
            .cert_store(self.cert_store)?
            .cert_verification(self.cert_verification)?
            .identity(self.identity)?
            .alpn_protos(config.alpn_protos)?
            .min_tls_version(config.min_tls_version)?
            .max_tls_version(config.max_tls_version)?;

        if config.enable_ocsp_stapling {
            connector.enable_ocsp_stapling();
        }

        if config.enable_signed_cert_timestamps {
            connector.enable_signed_cert_timestamps();
        }

        if !config.session_ticket {
            connector.set_options(SslOptions::NO_TICKET);
        }

        if !config.psk_dhe_ke {
            connector.set_options(SslOptions::NO_PSK_DHE_KE);
        }

        if !config.renegotiation {
            connector.set_options(SslOptions::NO_RENEGOTIATION);
        }

        if let Some(grease_enabled) = config.grease_enabled {
            connector.set_grease_enabled(grease_enabled);
        }

        if let Some(permute_extensions) = config.permute_extensions {
            connector.set_permute_extensions(permute_extensions);
        }

        if let Some(curves_list) = config.curves_list.as_deref() {
            connector.set_curves_list(curves_list)?;
        }

        if let Some(sigalgs_list) = config.sigalgs_list.as_deref() {
            connector.set_sigalgs_list(sigalgs_list)?;
        }

        if let Some(delegated_credentials) = config.delegated_credentials.as_deref() {
            connector.set_delegated_credentials(delegated_credentials)?;
        }

        if let Some(cipher_list) = config.cipher_list.as_deref() {
            connector.set_cipher_list(cipher_list)?;
        }

        if let Some(cert_compression_algorithm) = config.cert_compression_algorithm {
            for algorithm in cert_compression_algorithm.iter() {
                connector = connector.add_cert_compression_algorithm(*algorithm)?;
            }
        }

        if let Some(record_size_limit) = config.record_size_limit {
            connector.set_record_size_limit(record_size_limit);
        }

        if let Some(limit) = config.key_shares_limit {
            connector.set_key_shares_limit(limit);
        }

        if let Some(permutation) = config.extension_permutation {
            connector.set_extension_permutation(&permutation)?;
        }

        if let Some(aes_hw_override) = config.aes_hw_override {
            connector.set_aes_hw_override(aes_hw_override);
        }

        if let Some(policy) = self.keylog_policy {
            let handle = policy.open_handle().map_err(crate::Error::builder)?;
            connector.set_keylog_callback(move |_, line| {
                let line = format!("{}\n", line);
                handle.write_log_line(line);
            });
        }

        // Create the `HandshakeSettings` with the default session cache capacity.
        let settings = HandshakeSettings::builder()
            .session_cache_capacity(8)
            .session_cache(config.pre_shared_key)
            .skip_session_ticket(config.psk_skip_session_ticket)
            .alps_protos(config.alps_protos)
            .alps_use_new_codepoint(config.alps_use_new_codepoint)
            .enable_ech_grease(config.enable_ech_grease)
            .tls_sni(self.tls_sni)
            .verify_hostname(self.verify_hostname)
            .random_aes_hw_override(config.random_aes_hw_override)
            .build();

        Ok(TlsConnector::with_connector_and_settings(
            connector, settings,
        ))
    }
}

impl TlsConnector {
    /// Creates a new `TlsConnectorBuilder` with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            keylog_policy: None,
            identity: None,
            cert_store: None,
            cert_verification: true,
            tls_sni: true,
            verify_hostname: true,
        }
    }

    /// Creates a new `TlsConnector` with settings
    fn with_connector_and_settings(
        mut ssl: SslConnectorBuilder,
        settings: HandshakeSettings,
    ) -> TlsConnector {
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
            // Use server name indication
            conf.set_use_server_name_indication(settings.tls_sni);

            // Verify hostname
            conf.set_verify_hostname(settings.verify_hostname);

            // Set ECH grease
            conf.set_enable_ech_grease(settings.enable_ech_grease);

            // Set AES hardware override
            conf.set_random_aes_hw_override(settings.random_aes_hw_override);

            // Set ALPS
            conf.alps_protos(settings.alps_protos, settings.alps_use_new_codepoint)?;

            Ok(())
        });

        TlsConnector {
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

        tokio_boring2::SslStreamBuilder::new(ssl, TokioIo::new(conn))
            .connect()
            .await
            .map_err(Into::into)
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
                connect
                    .await
                    .map(MaybeHttpsStream::Http)
                    .map_err(Into::into)
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
                    if host[1..last].parse::<Ipv6Addr>().is_ok() {
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
