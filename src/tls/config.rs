//! Client TLS construction settings for TCP, Unix and QUIC.

use std::sync::Arc;

use btls::ssl::{SslContextBuilder, SslVerifyMode};

use super::{
    TlsVersion, connector,
    ext::SslContextBuilderExt,
    keylog::KeyLog,
    session::{SessionStore, TlsSessionStore},
    trust::{CertStore, Identity},
};
use crate::{Error, Protocol, conn::config::ConfigSet};

/// Client settings used to build TLS connection services and QUIC configurations.
/// Protocol selection and minimum version apply to TCP/Unix. QUIC checks the maximum
/// version against TLS 1.3 and uses its own ALPN.
#[derive(Clone)]
pub(super) struct Config {
    pub(super) protocol: Protocol,
    pub(super) max_version: Option<TlsVersion>,
    pub(super) min_version: Option<TlsVersion>,
    pub(super) tls_sni: bool,
    pub(super) verify_hostname: bool,
    pub(super) cert_verification: bool,
    pub(super) session: Arc<SessionStore>,
    keylog: Option<KeyLog>,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
}

/// Configures client TLS settings before compiling TCP/Unix or QUIC contexts.
/// Clones retain one client session scope across both transports.
#[derive(Clone)]
pub(crate) struct TlsConnectorBuilder {
    config: Config,
}

// ===== impl Config =====

impl Config {
    /// Applies the client's identity, trust roots, verification and key log to a context.
    pub(super) fn configure(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        builder.set_identity(self.identity.as_ref())?;
        builder.set_root_store(self.cert_store.as_ref())?;
        builder.set_cert_verification(self.cert_verification);

        if let Some(policy) = self.keylog.clone()
            && let Some(handle) = policy.handle().map_err(Error::tls)?
        {
            builder.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        Ok(())
    }

    /// Shares this client's session scope across contexts and, when verification is enabled,
    /// re-verifies the server certificate chain on resumption.
    pub(super) fn enable_resumption(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        // Resumption skips certificate checks unless a custom verifier runs them again; this
        // one keeps the built-in X.509 checks. Verification off uses VERIFY_NONE, which
        // re-verification does not support.
        if self.cert_verification {
            builder.set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
                Ok(ssl.verify_peer_cert_chain()?)
            });
            builder.set_reverify_on_resume(true);
        }
        let scope = self.session.session_id_context().map_err(Error::tls)?;
        builder.set_session_id_context(&scope).map_err(Error::tls)?;
        // This limits TLS 1.2 sessions; TLS 1.3 also obeys the server's ticket lifetime.
        builder.set_session_timeout(60 * 60);
        Ok(())
    }
}

// ===== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Starts configuring the client-wide TLS policy.
    pub(crate) fn new() -> Self {
        Self {
            config: Config {
                protocol: Protocol::Auto,
                min_version: None,
                max_version: None,
                identity: None,
                tls_sni: true,
                verify_hostname: true,
                cert_store: None,
                cert_verification: true,
                keylog: None,
                session: Arc::new(SessionStore::new(None)),
            },
        }
    }

    /// Supplies the HTTP preference used for TCP TLS negotiation.
    /// HTTP/3 uses automatic selection on TCP; QUIC sets its own ALPN.
    /// Fixed modes override TLS options; automatic mode preserves their ALPN list.
    #[inline]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        #[cfg(feature = "http3")]
        let protocol = if protocol == Protocol::Http3 {
            Protocol::Auto
        } else {
            protocol
        };
        self.config.protocol = protocol;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.config.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.config.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.config.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.config.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn sni(mut self, enabled: bool) -> Self {
        self.config.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.config.verify_hostname = enabled;
        self
    }

    /// Sets the shared TLS session store.
    #[inline]
    pub fn session_store(mut self, tls_session_store: Option<Arc<dyn TlsSessionStore>>) -> Self {
        if let Some(store) = tls_session_store {
            self.config.session = Arc::new(SessionStore::new(Some(store)));
        }
        self
    }

    /// Compiles the client's context from its TLS options and consumes this builder.
    /// Missing options leave TLS customization to the backend's defaults; the client-wide
    /// trust, version, and ALPN policy still applies.
    pub fn build(self, config_set: ConfigSet) -> crate::Result<connector::TlsConnector> {
        connector::TlsConnector::new(self.config, config_set)
    }

    /// Compiles the client's QUIC context from its QUIC options and consumes this builder.
    #[cfg(feature = "http3")]
    pub(crate) fn build_quic(self, config_set: ConfigSet) -> crate::Result<super::quic::TlsConfig> {
        super::quic::TlsConfig::new(self.config, config_set)
    }
}
