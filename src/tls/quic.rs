//! BoringSSL configuration for outbound QUIC connections.

use std::sync::{Arc, OnceLock};

use btls::{
    asn1::{Asn1Time, TimeDiff},
    error::ErrorStack,
    ssl::{SslContextBuilder, SslMethod, SslRef, SslSession, SslVerifyMode},
    x509::{X509Ref, X509StoreContextRef},
};
use bytes::Bytes;
use quic::{
    TokenStore, TransportConfig,
    crypto::btls::{NoSessionCache, QuicClientConfig, SessionCache, Zeroizing},
};

use super::{
    AlpnProtocol, AlpsProtocol, TlsVersion,
    config::Config,
    ext::{SslContextBuilderExt as _, set_ech_grease_host},
    session::{Key, SessionStore, SessionTarget},
};
use crate::{
    Error, Result,
    conn::{
        config::{ConfigSet, Overrides},
        request::ConnectRequest,
        transport::TUNNEL_MTU,
    },
    protocol::TransportKind,
    quic::QuicOptions,
    sync::Mutex,
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

/// The QUIC configuration of one connection, shared by its address race.
/// Each handshake attempt starts from its own [`client`](Self::client) configuration.
pub(crate) struct QuicConfig {
    crypto: Arc<QuicClientConfig>,
    handshake: Arc<Handshake>,
    resumption: Option<Arc<Resumption>>,
    transport: Arc<TransportConfig>,
    tokens: Option<Arc<dyn TokenStore>>,
}

/// The settings the SSL callback applies to each handshake of one connection.
///
/// The QUIC stack reports a session its SSL callback rejected as `EndpointStopping`, as it does
/// for a stopped endpoint driver, so the callback's first error is kept to tell them apart.
struct Handshake {
    verify_peer: bool,
    options: Option<Arc<QuicOptions>>,
    rejected: OnceLock<ErrorStack>,
}

/// The client's session store and the session key of one connection.
struct Resumption {
    session_store: Arc<SessionStore>,
    key: Key,
}

/// Adapts one handshake attempt to the QUIC stack's hostname-keyed cache.
///
/// It holds the ticket taken for this attempt until the handshake takes it, so concurrent
/// attempts never offer the same one
/// ([RFC 8446 Appendix C.4](https://www.rfc-editor.org/rfc/rfc8446#appendix-C.4)). New tickets
/// go to the store with the expiry of the certificate path the handshake verified.
struct Attempt {
    resumption: Arc<Resumption>,
    ticket: Mutex<Option<Zeroizing<Vec<u8>>>>,
    not_after: OnceLock<i64>,
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

    /// Returns the MASQUE proxy transport for `request`, built from the same QUIC options as
    /// its TLS; the client's is reused unless the request changes transport fields.
    pub(crate) fn proxy_transport(&self, request: &ConnectRequest) -> Result<Arc<TransportConfig>> {
        let inner = &*self.0;
        match (
            request.config_override::<QuicOptions>(),
            inner.options.as_deref(),
        ) {
            (Some(requested), Some(client)) if requested.same_transport(client) => {
                Ok(inner.proxy_transport.clone())
            }
            (Some(requested), _) => proxy_transport(Some(requested)).map(Arc::new),
            (None, _) => Ok(inner.proxy_transport.clone()),
        }
    }

    /// Returns the QUIC configuration of one connection for `request`.
    ///
    /// QUIC always negotiates TLS 1.3, so a client capped below it fails here rather than
    /// when it is built. A tunnel fixes the inner MTU while its outer path discovers its own.
    pub(crate) fn config(
        &self,
        request: &ConnectRequest,
        tunnel_mtu: Option<u16>,
    ) -> Result<QuicConfig> {
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
            TransportKind::Quic,
        );
        let mut crypto = if overrides.is_empty() {
            inner.context.clone()
        } else {
            compile(&inner.config, overrides.get::<QuicOptions>())?
        };

        let requested = request.config_override_arc::<QuicOptions>();
        let options = requested.clone().or_else(|| inner.options.clone());
        let resumption = options
            .as_ref()
            .is_some_and(|options| options.pre_shared_key);
        let handshake = Arc::new(Handshake {
            verify_peer: inner.config.cert_verification,
            options,
            rejected: OnceLock::new(),
        });
        crypto.set_ssl_callback({
            let handshake = handshake.clone();
            move |ssl, server_name| handshake.configure(ssl, server_name)
        });

        let resumption = if resumption {
            let session_store = inner.config.session_store.clone();
            let target = SessionTarget::new(
                request,
                &inner.config_set,
                TransportKind::Quic,
                None,
                session_store.session_id_context().map_err(Error::tls)?,
            );
            Some(Arc::new(Resumption {
                session_store,
                key: target.into_key(),
            }))
        } else {
            None
        };

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
        Ok(QuicConfig {
            crypto: Arc::new(crypto),
            handshake,
            resumption,
            transport,
            tokens: None,
        })
    }
}

// ===== impl QuicConfig =====

impl QuicConfig {
    /// Returns the configuration of one handshake attempt.
    ///
    /// With resumption, the attempt takes its own ticket here, before the QUIC endpoint's lock
    /// is held, so a slow session store stalls only this connection.
    pub(crate) fn client(&self) -> quic::ClientConfig {
        let crypto = match &self.resumption {
            Some(resumption) => Arc::new(self.attempt(resumption)),
            None => self.crypto.clone(),
        };
        let mut client = quic::ClientConfig::new(crypto);
        client.transport_config(self.transport.clone());
        if let Some(tokens) = &self.tokens {
            client.token_store(tokens.clone());
        }
        client
    }

    /// Sets the transport configuration of every attempt.
    #[inline]
    pub(crate) fn transport_config(&mut self, transport: Arc<TransportConfig>) {
        self.transport = transport;
    }

    /// Sets the address validation token store of every attempt.
    #[inline]
    pub(crate) fn token_store(&mut self, tokens: Arc<dyn TokenStore>) {
        self.tokens = Some(tokens);
    }

    /// Returns the SSL callback's error once it rejected a session.
    #[inline]
    pub(crate) fn rejected(&self) -> Option<&ErrorStack> {
        self.handshake.rejected.get()
    }

    /// Builds the TLS configuration of one attempt around a ticket of its own. A verifying
    /// handshake also reports the expiry of the path it verified.
    fn attempt(&self, resumption: &Arc<Resumption>) -> QuicClientConfig {
        let verify_peer = self.handshake.verify_peer;
        let attempt = Arc::new(Attempt {
            resumption: resumption.clone(),
            ticket: Mutex::new(
                resumption
                    .session_store
                    .pop_quic(&resumption.key, verify_peer),
            ),
            not_after: OnceLock::new(),
        });
        let mut crypto = (*self.crypto).clone();
        crypto.set_ssl_callback({
            let handshake = self.handshake.clone();
            let attempt = attempt.clone();
            move |ssl, server_name| {
                handshake.configure(ssl, server_name)?;
                if verify_peer {
                    let attempt = attempt.clone();
                    ssl.set_verify_callback(SslVerifyMode::PEER, move |ok, ctx| {
                        attempt.verified(ok, ctx);
                        ok
                    });
                }
                Ok(())
            }
        });
        crypto.set_session_cache(attempt);
        crypto
    }
}

// ===== impl Handshake =====

impl Handshake {
    /// Configures one handshake, keeping the first error.
    fn configure(
        &self,
        ssl: &mut SslRef,
        server_name: &str,
    ) -> std::result::Result<(), ErrorStack> {
        configure_connection(ssl, server_name, self.verify_peer, self.options.as_deref())
            .inspect_err(|error| {
                let _ = self.rejected.set(error.clone());
            })
    }
}

/// Outer MTU fitting a tunneled 1200-byte datagram: QUIC short header (1 + 20-byte CID + 4),
/// AEAD tag (16), DATAGRAM frame (9), Quarter Stream ID (8) and Context ID (1), at most.
const PROXY_MTU: u16 = TUNNEL_MTU + 59;

/// Smallest frame limit a MASQUE proxy connection keeps. The QUIC stack also bounds buffered
/// datagrams by this limit, so it must hold a burst of tunnel packets, not one or two.
const PROXY_DATAGRAM_BUFFER: u64 = 16 * PROXY_MTU as u64;

/// Builds a MASQUE proxy transport from client options. Its Datagrams carry the tunnel and
/// cannot be fragmented, so the path MTU starts at and never drops below one that fits them,
/// even after a black hole reset
/// ([RFC 9298 Section 6.1](https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1)); a frame
/// limit too small for a burst of them falls back to the default.
fn proxy_transport(options: Option<&QuicOptions>) -> Result<TransportConfig> {
    let mut options = options.cloned().unwrap_or_default();
    if options
        .max_datagram_frame_size
        .is_some_and(|size| size < PROXY_DATAGRAM_BUFFER)
    {
        options.max_datagram_frame_size = None;
    }
    let mut transport = options.transport()?;
    // The initial MTU is raised to this floor as well.
    transport.min_mtu(PROXY_MTU);
    Ok(transport)
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
    tls.set_server_name_indication(config.sni);
    tls.set_verify_hostname(config.verify_hostname);
    // A connection-scoped adapter is installed only when resumption is enabled.
    tls.set_session_cache(Arc::new(NoSessionCache));
    Ok(tls)
}

/// Applies the client's verification policy and per-connection [`QuicOptions`] to one handshake.
fn configure_connection(
    ssl: &mut SslRef,
    server_name: &str,
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

    if options.ech_grease.is_some() {
        set_ech_grease_host(ssl, server_name.len())?;
    }

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

/// Returns the earliest expiry among `certs`, as POSIX time.
fn earliest_not_after<'a>(certs: impl IntoIterator<Item = &'a X509Ref>) -> Option<i64> {
    let epoch = Asn1Time::from_unix(0).ok()?;
    certs
        .into_iter()
        .filter_map(|cert| {
            let TimeDiff { days, secs } = epoch.diff(cert.not_after()).ok()?;
            Some(i64::from(days) * 86_400 + i64::from(secs))
        })
        .min()
}

// ===== impl Attempt =====

impl Attempt {
    /// Records the expiry of the path BoringSSL verified once it accepts the leaf, which it
    /// checks last. Certificates the server sent off that path do not count.
    fn verified(&self, ok: bool, ctx: &X509StoreContextRef) {
        if ok
            && ctx.error_depth() == 0
            && let Some(not_after) = ctx.chain().and_then(earliest_not_after)
        {
            let _ = self.not_after.set(not_after);
        }
    }
}

impl SessionCache for Attempt {
    fn put(&self, _key: Bytes, value: Zeroizing<Vec<u8>>, session: SslSession) {
        // Without a verified path every certificate the server sent counts.
        let not_after = self
            .not_after
            .get()
            .copied()
            .or_else(|| session.peer_chain_not_after());
        let Resumption { session_store, key } = &*self.resumption;
        session_store.insert_quic(key.clone(), session, value, not_after);
    }

    fn take(&self, _key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.ticket.lock().take()
    }

    fn remove(&self, _key: &[u8]) {
        // `take` already consumed the ticket of a failed handshake; the others stay in the
        // client's store.
    }

    fn clear(&self) {
        // The adapter holds at most this attempt's ticket; new tickets go straight to the
        // client's store.
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn proxy_transport_keeps_room_for_tunnel_datagrams() {
        use super::*;

        // The frame limit is advertised as is; only one too small for a burst is replaced.
        for (size, advertised) in [(1500, 1_250_000), (65_536, 65_536)] {
            let options = QuicOptions::builder().max_datagram_frame_size(size).build();
            let transport = format!("{:?}", proxy_transport(Some(&options)).unwrap());
            assert!(
                transport.contains(&format!("datagram_receive_buffer_size: Some({advertised})")),
                "{transport}"
            );
            // A black hole reset keeps the path MTU large enough for a tunnel packet.
            assert!(
                transport.contains(&format!("min_mtu: {PROXY_MTU},")),
                "{transport}"
            );
        }
    }

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

    #[tokio::test]
    async fn tcp_client_hello_follows_shared_options() {
        use std::{pin::Pin, sync::Mutex, time::Duration};

        use btls::ssl::{ClientHello, ExtensionType, SelectCertError, Ssl};
        use quic::crypto::btls::QuicServerConfig;

        use super::*;
        use crate::tls::{
            EchGrease, EchGreaseAead, Tls13Cipher, TlsOptions,
            compress::{CertificateCompressionAlgorithm, CertificateCompressor, Codec},
        };

        /// Advertises Brotli; no certificate is ever compressed.
        #[derive(Debug)]
        struct Compressor;
        impl CertificateCompressor for Compressor {
            fn algorithm(&self) -> CertificateCompressionAlgorithm {
                CertificateCompressionAlgorithm::BROTLI
            }
            fn compress(&self) -> Codec {
                Codec::Pointer(|_, _| Err(std::io::ErrorKind::Unsupported.into()))
            }
            fn decompress(&self) -> Codec {
                self.compress()
            }
        }

        // Both builders name the shared options alike. The permutation options only reorder
        // extensions, so they are left out.
        macro_rules! shared {
            ($builder:expr) => {
                $builder
                    .ech_grease(EchGrease::Aead(EchGreaseAead::CHACHA20_POLY1305))
                    .enable_ocsp_stapling(true)
                    .enable_signed_cert_timestamps(true)
                    .psk_dhe_ke(false)
                    .grease_enabled(true)
                    .grease_sigalgs_enabled(true)
                    .curves_list("P-256:X25519")
                    .sigalgs_list("ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256")
                    .tls13_cipher_list(&[
                        Tls13Cipher::CHACHA20_POLY1305_SHA256,
                        Tls13Cipher::AES_128_GCM_SHA256,
                    ])
                    .certificate_compressors(vec![&Compressor as &dyn CertificateCompressor])
                    .delegated_credentials("ecdsa_secp256r1_sha256")
                    .record_size_limit(0x4001)
                    .trust_anchors(b"\x02\x01\x02")
                    .build()
            };
        }

        /// The TLS 1.3 suites, then the extensions that the shared options set.
        fn shared(hello: &ClientHello<'_>) -> Vec<Option<Vec<u8>>> {
            // GREASE values are random per handshake (RFC 8701); keep only their positions.
            let degrease = |list: &[u8]| {
                list.as_chunks::<2>()
                    .0
                    .iter()
                    .flat_map(|&[hi, lo]| {
                        if hi == lo && hi & 0x0f == 0x0a {
                            [0x0a; 2]
                        } else {
                            [hi, lo]
                        }
                    })
                    .collect()
            };
            let ciphers = hello.ciphers().as_chunks::<2>().0.iter();
            let tls13 = ciphers.filter(|[hi, _]| *hi == 0x13).flatten().copied();
            [
                Some(tls13.collect()),
                hello
                    .get_extension(ExtensionType::ENCRYPTED_CLIENT_HELLO)
                    .map(|ech| ech[..5].to_vec()),
                hello
                    .get_extension(ExtensionType::SUPPORTED_GROUPS)
                    .map(degrease),
                hello
                    .get_extension(ExtensionType::SIGNATURE_ALGORITHMS)
                    .map(degrease),
            ]
            .into_iter()
            .chain(
                [
                    ExtensionType::STATUS_REQUEST,
                    ExtensionType::CERTIFICATE_TIMESTAMP,
                    ExtensionType::PSK_KEY_EXCHANGE_MODES,
                    ExtensionType::CERT_COMPRESSION,
                    ExtensionType::DELEGATED_CREDENTIAL,
                    ExtensionType::RECORD_SIZE_LIMIT,
                    ExtensionType::TRUST_ANCHORS,
                ]
                .map(|extension| hello.get_extension(extension).map(<[u8]>::to_vec)),
            )
            .collect()
        }

        let hellos = Arc::new(Mutex::new(Vec::new()));
        let server = || {
            let hellos = hellos.clone();
            let mut server = SslContextBuilder::new(SslMethod::tls()).unwrap();
            server.set_select_certificate_callback(move |hello| {
                hellos.lock().unwrap().push(shared(&hello));
                Err(SelectCertError::ERROR)
            });
            server
        };
        let tcp = server().build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_url = format!("https://{}/", listener.local_addr().unwrap());
        let tcp_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let ssl = Ssl::new(&tcp).unwrap();
                let mut stream = tokio_btls::SslStream::new(ssl, socket).unwrap();
                assert!(Pin::new(&mut stream).accept().await.is_err());
            }
        });
        let quic = QuicServerConfig::try_from(server()).unwrap();
        let quic = quic::ServerConfig::with_crypto(Arc::new(quic));
        let endpoint = quic::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
        let quic_url = format!("https://{}/", endpoint.local_addr().unwrap());
        let quic_server =
            tokio::spawn(async move { assert!(endpoint.accept().await.unwrap().await.is_err()) });

        let client = || {
            crate::Client::builder(crate::rt::tokio::TokioRuntime)
                .no_proxy()
                .tls_sni(false)
                .timeout(Duration::from_secs(5))
        };
        for client in [
            client(),
            client().tls_options(shared!(TlsOptions::builder())),
        ] {
            let client = client.build().unwrap();
            assert!(client.get(&tcp_url).send().await.is_err());
        }
        let client = client()
            .http3_only()
            .quic_options(shared!(QuicOptions::builder()))
            .build()
            .unwrap();
        assert!(client.get(&quic_url).send().await.is_err());
        for server in [tcp_server, quic_server] {
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }

        let hellos = std::mem::take(&mut *hellos.lock().unwrap());
        let [default, tcp, quic] = <[_; 3]>::try_from(hellos).unwrap();
        // Every shared item follows the options on TCP, as it does on QUIC.
        for (configured, default) in tcp.iter().zip(&default) {
            assert_ne!(configured, default);
        }
        assert_eq!(tcp, quic);
    }
}
