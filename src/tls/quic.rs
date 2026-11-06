//! BoringSSL configuration for outbound QUIC connections.

use std::sync::{Arc, OnceLock};

use btls::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslMethod, SslRef, SslSession, SslVerifyMode},
};
use bytes::Bytes;
use quic::{
    TransportConfig,
    crypto::btls::{NoSessionCache, QuicClientConfig, SessionCache, Zeroizing},
};

use super::{
    AlpnProtocol, AlpsProtocol, TlsVersion,
    config::Config,
    ext::{SslContextBuilderExt as _, set_ech_grease_host},
    session::{Key, SessionStore, SessionTarget, SessionTransport},
};
use crate::{
    Error, Result,
    conn::{
        config::{ConfigSet, Overrides},
        request::ConnectRequest,
        transport::TUNNEL_MTU,
    },
    quic::QuicOptions,
};

/// Builds per-connection QUIC configurations from shared client TLS policy.
/// Different request context options are compiled for each connection attempt.
#[derive(Clone)]
pub(crate) struct TlsConfig(Arc<Inner>);

/// Client policy, QUIC options, compiled TLS context and transport configuration.
struct Inner {
    config: Config,
    config_set: ConfigSet,
    options: Option<Arc<QuicOptions>>,
    context: QuicClientConfig,
    transport: Arc<TransportConfig>,
    proxy_transport: Arc<TransportConfig>,
}

/// Adapts one connection's session key to the QUIC stack's hostname-keyed cache.
/// Tickets are taken before the handshake; the server's transport parameters travel with them.
struct Resumption {
    store: Arc<SessionStore>,
    key: Key,
    verify_peer: bool,
    /// Ticket taken from the store on the first lookup and shared by the address race.
    /// Later lookups clone this ticket without consuming more from the store.
    ticket: OnceLock<Option<Zeroizing<Vec<u8>>>>,
}

// ===== impl TlsConfig =====

impl TlsConfig {
    pub(super) fn new(config: Config, config_set: ConfigSet) -> Result<Self> {
        let options = config_set.get_arc::<QuicOptions>();
        let context = compile(&config, options.as_deref())?;
        let transport = match options.as_deref() {
            Some(options) => Arc::new(options.transport()?),
            None => Arc::new(TransportConfig::default()),
        };
        let proxy_transport = Arc::new(proxy_transport(options.as_deref())?);
        Ok(Self(Arc::new(Inner {
            config,
            config_set,
            options,
            context,
            transport,
            proxy_transport,
        })))
    }

    /// Returns the transport of a MASQUE proxy connection, built from client options.
    #[inline]
    pub(crate) fn proxy_transport(&self) -> Arc<TransportConfig> {
        self.0.proxy_transport.clone()
    }

    /// Returns the QUIC configuration of one connection for `request`.
    ///
    /// QUIC always negotiates TLS 1.3, so a client capped below it fails here rather than
    /// when it is built. A tunnel fixes the inner MTU while its outer path discovers its own.
    pub(crate) fn config(
        &self,
        request: &ConnectRequest,
        tunnel_mtu: Option<u16>,
    ) -> Result<quic::ClientConfig> {
        let inner = &*self.0;
        if inner
            .config
            .max_version
            .is_some_and(|version| version != TlsVersion::TLS_1_3)
        {
            return Err(Error::tls("HTTP/3 requires TLS 1.3"));
        }

        let overrides = Overrides::for_context(
            request.config_set().clone(),
            &inner.config_set,
            SessionTransport::Quic,
        );
        let mut crypto = if overrides.is_empty() {
            inner.context.clone()
        } else {
            compile(&inner.config, overrides.get::<QuicOptions>())?
        };

        let requested = request.config_override_arc::<QuicOptions>();
        let options = requested.clone().or_else(|| inner.options.clone());
        let verify_peer = inner.config.cert_verification;
        let resumption = options
            .as_ref()
            .is_some_and(|options| options.pre_shared_key);
        crypto.set_ssl_callback(move |ssl, server_name| {
            if options
                .as_ref()
                .is_some_and(|options| options.ech_grease.is_some())
            {
                set_ech_grease_host(ssl, server_name.len())?;
            }
            configure_connection(ssl, verify_peer, options.as_deref())
        });

        if resumption {
            let store = inner.config.session.clone();
            let target = SessionTarget::new(
                request,
                &inner.config_set,
                SessionTransport::Quic,
                None,
                store.session_id_context().map_err(Error::tls)?,
            );
            crypto.set_session_cache(Arc::new(Resumption {
                store,
                key: target.into_key(),
                verify_peer,
                ticket: OnceLock::new(),
            }));
        }

        let transport = if let Some(mtu) = tunnel_mtu {
            let mut transport = requested
                .as_deref()
                .or(inner.options.as_deref())
                .map_or_else(|| Ok(TransportConfig::default()), QuicOptions::transport)?;
            // The tunnel's outer path owns MTU discovery; preserve other transport options.
            transport
                .initial_mtu(mtu)
                .min_mtu(mtu)
                .mtu_discovery_config(None);
            Arc::new(transport)
        } else {
            match (requested.as_deref(), inner.options.as_deref()) {
                (Some(requested), Some(client)) if requested.same_transport(client) => {
                    inner.transport.clone()
                }
                (Some(requested), _) => Arc::new(requested.transport()?),
                (None, _) => inner.transport.clone(),
            }
        };
        let mut client = quic::ClientConfig::new(Arc::new(crypto));
        client.transport_config(transport);
        Ok(client)
    }
}

/// Outer MTU fitting a tunneled 1200-byte datagram: QUIC short header (1 + 20-byte CID + 4),
/// AEAD tag (16), DATAGRAM frame (9), Quarter Stream ID (8) and Context ID (1), at most.
const PROXY_MTU: u16 = TUNNEL_MTU + 59;

/// Builds a MASQUE proxy transport from client options. Its Datagrams carry the tunnel and
/// cannot be fragmented, so a frame limit or initial MTU too small for one is raised
/// ([RFC 9298 Section 6.1](https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1)).
fn proxy_transport(options: Option<&QuicOptions>) -> Result<TransportConfig> {
    let mut options = options.cloned().unwrap_or_default();
    if options
        .max_datagram_frame_size
        .is_some_and(|size| size < u64::from(PROXY_MTU))
    {
        options.max_datagram_frame_size = None;
    }
    options.initial_mtu = Some(options.initial_mtu.unwrap_or_default().max(PROXY_MTU));
    options.transport()
}

/// Compiles a QUIC context from the client policy and the context options of `options`.
/// Callbacks and the session cache are configured for each connection attempt.
fn compile(config: &Config, options: Option<&QuicOptions>) -> Result<QuicClientConfig> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(Error::tls)?;
    config.configure(&mut builder)?;
    if let Some(options) = options {
        builder.set_quic_options(options)?;

        if options.pre_shared_key {
            config.enable_resumption(&mut builder)?;
        }
    }
    // QUIC always uses TLS 1.3 and HTTP/3 ALPN.
    builder
        .set_alpn_protos(&AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]))
        .map_err(Error::tls)?;
    let mut tls = QuicClientConfig::try_from(builder).map_err(Error::tls)?;
    tls.set_server_name_indication(config.tls_sni);
    tls.set_verify_hostname(config.verify_hostname);
    // A connection-scoped adapter is installed only when resumption is enabled.
    tls.set_session_cache(Arc::new(NoSessionCache));
    Ok(tls)
}

/// Applies the client's verification policy and per-connection [`QuicOptions`] to one handshake.
fn configure_connection(
    ssl: &mut SslRef,
    verify_peer: bool,
    options: Option<&QuicOptions>,
) -> std::result::Result<(), ErrorStack> {
    // The backend enables chain verification by default, even when the
    // context disabled it. Restore the client policy before selecting PSK.
    if !verify_peer {
        ssl.set_verify(SslVerifyMode::NONE);
    }
    let Some(options) = options else {
        return Ok(());
    };

    set_option_ref_try!(
        options,
        key_shares,
        ssl,
        set_client_key_shares,
        std::convert::identity
    );

    // Offer ALPS for h3, the only protocol QUIC negotiates.
    if options.enable_alps_protocol {
        ssl.add_application_settings(AlpsProtocol::HTTP3.0, None)?;
        ssl.set_alps_use_new_codepoint(options.alps_use_new_codepoint);
    }
    Ok(())
}

// ===== impl Resumption =====

impl SessionCache for Resumption {
    fn put(&self, _key: Bytes, value: Zeroizing<Vec<u8>>, session: SslSession) {
        self.store.insert_quic(self.key.clone(), session, value);
    }

    fn take(&self, _key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.ticket
            .get_or_init(|| self.store.pop_quic(&self.key, self.verify_peer))
            .clone()
    }

    fn remove(&self, _key: &[u8]) {
        // `take` already consumed the ticket of a failed handshake; the others belong to later
        // handshakes.
    }

    fn clear(&self) {
        // The adapter only keeps this connection's ticket; new tickets go straight to the
        // client's store.
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn client_hello_extensions_follow_quic_options() {
        use std::{sync::Mutex, time::Duration};

        use btls::ssl::{ExtensionType, SelectCertError};
        use quic::crypto::btls::QuicServerConfig;

        use super::*;
        use crate::tls::{EchGrease, EchGreaseAead};

        let h3 = b"\x00\x03\x02h3".to_vec();
        let cases = [
            (QuicOptions::default(), None, None),
            (
                QuicOptions::builder().enable_alps_protocol(false).build(),
                None,
                None,
            ),
            (
                QuicOptions::builder().enable_alps_protocol(true).build(),
                Some(h3.clone()),
                None,
            ),
            (
                QuicOptions::builder()
                    .enable_alps_protocol(true)
                    .alps_use_new_codepoint(false)
                    .build(),
                None,
                Some(h3.clone()),
            ),
        ]
        .into_iter()
        .chain(
            [
                EchGrease::Default,
                EchGrease::Aead(EchGreaseAead::CHACHA20_POLY1305),
                EchGrease::NssPre3127,
                EchGrease::Nss3127,
            ]
            .map(|policy| {
                (
                    QuicOptions::builder().ech_grease(policy).build(),
                    None,
                    None,
                )
            }),
        )
        .collect::<Vec<_>>();
        let hellos = Arc::new(Mutex::new(Vec::new()));
        let mut server = SslContextBuilder::new(SslMethod::tls()).unwrap();
        server.set_alpn_protos(b"\x02h3").unwrap();
        server.set_select_certificate_callback({
            let hellos = hellos.clone();
            move |hello| {
                hellos.lock().unwrap().push((
                    hello
                        .get_extension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                        .map(<[u8]>::to_vec),
                    hello
                        .get_extension(ExtensionType::APPLICATION_SETTINGS)
                        .map(<[u8]>::to_vec),
                    hello
                        .get_extension(ExtensionType::APPLICATION_SETTINGS_OLD)
                        .map(<[u8]>::to_vec),
                    hello
                        .get_extension(ExtensionType::ENCRYPTED_CLIENT_HELLO)
                        .map(|ech| u16::from_be_bytes([ech[3], ech[4]])),
                ));
                // Capturing the ClientHello needs neither a certificate nor a completed handshake.
                Err(SelectCertError::ERROR)
            }
        });
        let server =
            quic::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap()));
        let endpoint = quic::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("https://{}/", endpoint.local_addr().unwrap());
        let attempts = cases.len();
        let server = tokio::spawn(async move {
            for _ in 0..attempts {
                assert!(endpoint.accept().await.unwrap().await.is_err());
            }
        });

        for (options, new, old) in cases {
            let grease = options.ech_grease;
            let client = crate::Client::builder(crate::rt::tokio::TokioRuntime)
                .no_proxy()
                .http3_only()
                .tls_sni(false)
                .quic_options(options)
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            assert!(client.get(&url).send().await.is_err());
            let hellos = hellos.lock().unwrap();
            let (alpn, alps_new, alps_old, aead) = hellos.last().unwrap();
            assert_eq!((alpn, alps_new, alps_old), (&Some(h3.clone()), &new, &old));
            assert_eq!(aead.is_some(), grease.is_some());
            if let Some(EchGrease::Aead(expected)) = grease {
                assert_eq!(*aead, Some(expected.id()));
            }
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hellos.lock().unwrap().len(), attempts);
    }
}
