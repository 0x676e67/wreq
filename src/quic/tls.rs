//! BoringSSL configuration for outbound QUIC connections.

use std::sync::{Arc, OnceLock};

use ::quic::crypto::btls::{NoSessionCache, QuicClientConfig};
use btls::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslMethod, SslRef, SslVerifyMode},
};
use http::Uri;

use super::{
    QuicOptions,
    session::{Attempt, Resumption},
};
use crate::{
    Error, Result,
    config::ConnectConfig,
    tls::{
        self, AlpnProtocol, AlpsProtocol, KeyIdentity, TlsContext, TlsVersion,
        macros::set_hello_options, set_ech_grease_host,
    },
};

/// Shared TLS settings and compiled context cache for QUIC connections.
///
/// Owned by the QUIC endpoint manager; [`Context::config`] resolves a per-connection
/// [`Config`] using either the base context or a cached override.
pub(crate) struct Context {
    config: tls::Config,
    context: TlsContext<QuicOptions, QuicClientConfig>,
}

/// Per-connection QUIC TLS configuration shared across address attempts.
///
/// Carries the connection's SSL callback state and optional [`Resumption`] handle; each
/// address attempt calls [`Config::attempt`] to obtain its own [`QuicClientConfig`].
pub(crate) struct Config {
    crypto: Arc<QuicClientConfig>,
    handshake: Arc<Handshake>,
    resumption: Option<Arc<Resumption>>,
}

/// Per-connection state applied inside BoringSSL's handshake callback.
///
/// The QUIC stack reports a callback rejection as `EndpointStopping` (the same error as a
/// stopped endpoint driver), so the first callback error is saved here to tell them apart.
struct Handshake {
    verify_peer: bool,
    options: Option<Arc<QuicOptions>>,
    rejected: OnceLock<ErrorStack>,
}

// ===== impl Context =====

impl Context {
    /// Compiles the base QUIC TLS context from client settings and default options.
    pub(crate) fn new(config: tls::Config, connect: &ConnectConfig) -> Result<Self> {
        compile(&config, connect.get_ref()).map(|inner| Self {
            config,
            context: TlsContext::new(inner),
        })
    }

    /// Builds the QUIC TLS configuration for `origin` and its TLS `peer`.
    ///
    /// QUIC requires TLS 1.3, so a client capped below TLS 1.3 fails here rather than at
    /// build time. Each connection clones the cached context to install its own SSL callback.
    pub(crate) fn config(
        &self,
        origin: &Uri,
        peer: &Uri,
        config: &ConnectConfig,
    ) -> Result<Config> {
        if self
            .config
            .max_version
            .is_some_and(|version| version != TlsVersion::TLS_1_3)
        {
            return Err(Error::tls("HTTP/3 requires TLS 1.3"));
        }

        let overrides = config.override_if_different(KeyIdentity::same);
        let mut crypto = self
            .context
            .get_or_compile(overrides, |options| compile(&self.config, Some(options)))?;
        let options = config.get_arc::<QuicOptions>();
        let resumption = options
            .as_ref()
            .is_some_and(|options| options.pre_shared_key);
        let handshake = Arc::new(Handshake {
            verify_peer: self.config.cert_verification,
            options,
            rejected: OnceLock::new(),
        });
        crypto.set_ssl_callback({
            let handshake = handshake.clone();
            move |ssl, server_name| handshake.configure(ssl, server_name)
        });

        let resumption = resumption
            .then(|| Resumption::new(&self.config.tickets, origin, peer, config))
            .transpose()?
            .map(Arc::new);

        Ok(Config {
            crypto: Arc::new(crypto),
            handshake,
            resumption,
        })
    }
}

// ===== impl Config =====

impl Config {
    /// Returns the TLS config for a single address attempt.
    ///
    /// When resumption is enabled, pops a ticket upfront before the endpoint lock is acquired.
    #[must_use]
    pub(crate) fn attempt(&self) -> Arc<QuicClientConfig> {
        match &self.resumption {
            Some(resumption) => Arc::new(self.resuming_attempt(resumption)),
            None => self.crypto.clone(),
        }
    }

    /// Returns the first error recorded by the SSL callback, if it rejected a handshake.
    #[must_use]
    pub(crate) fn rejected(&self) -> Option<&ErrorStack> {
        self.handshake.rejected.get()
    }

    /// Clones the TLS config for an attempt with its own ticket and (when verifying peers)
    /// a verify callback that records certificate expiry.
    #[must_use]
    fn resuming_attempt(&self, resumption: &Arc<Resumption>) -> QuicClientConfig {
        let verify_peer = self.handshake.verify_peer;
        let attempt = Arc::new(Attempt::new(resumption, verify_peer));
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
    /// Applies per-connection options to `ssl`, recording the first error.
    fn configure(
        &self,
        ssl: &mut SslRef,
        server_name: &str,
    ) -> std::result::Result<(), ErrorStack> {
        // The backend enables chain verification by default, even when the
        // context disabled it. Restore the client policy before selecting PSK.
        if !self.verify_peer {
            ssl.set_verify(SslVerifyMode::NONE);
        }
        let Some(options) = &self.options else {
            return Ok(());
        };

        let record_error = |error: &ErrorStack| {
            let _ = self.rejected.set(error.clone());
        };

        if options.ech_grease.is_some() {
            set_ech_grease_host(ssl, server_name.len()).inspect_err(record_error)?;
        }

        if let Some(key_shares) = &options.key_shares {
            ssl.set_client_key_shares(key_shares)
                .inspect_err(record_error)?;
        }

        // Offer ALPS for h3, the only protocol QUIC negotiates.
        if options.enable_alps_protocol {
            ssl.add_application_settings(AlpsProtocol::HTTP3.as_bytes(), None)
                .inspect_err(record_error)?;
            ssl.set_alps_use_new_codepoint(options.alps_use_new_codepoint);
        }
        Ok(())
    }
}

/// Compiles a reusable [`QuicClientConfig`].
///
/// Per-connection SSL callbacks and per-attempt session caches are attached later.
fn compile(config: &tls::Config, options: Option<&QuicOptions>) -> Result<QuicClientConfig> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(Error::tls)?;
    config.configure(&mut builder)?;
    if let Some(options) = options {
        set_hello_options!(common, options, &mut builder);

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use btls::ssl::{SslContextBuilder, SslMethod};
    use http::Uri;

    use super::{Config, Context, QuicOptions};
    use crate::{config::ConnectConfig, tls};

    #[tokio::test]
    async fn cached_contexts_take_a_callback_per_connection() {
        use std::net::Ipv4Addr;

        use btls::ssl::SslContextRef;

        use crate::{reuse::Group, tls::KeyShare};

        // The key share is not among the curves, so the SSL callback of each connection fails.
        let overrides = |grease: Option<bool>, group| {
            let mut connect_config = ConnectConfig::default();
            if let Some(group) = group {
                connect_config.insert(Group::new(group));
            }
            if let Some(grease) = grease {
                let options = QuicOptions::builder()
                    .curves_list("X25519")
                    .key_shares(vec![KeyShare::P256])
                    .grease_enabled(grease);
                let options = if group.is_some() {
                    options.initial_mtu(1280).enable_alps_protocol(true)
                } else {
                    options
                };
                connect_config.insert(options.build());
            }
            connect_config
        };
        let uri = Uri::from_static("https://localhost/");
        let tls = Context::new(tls::Config::default(), &ConnectConfig::default()).unwrap();
        let [client, first, second, other] = [
            (None, None),
            (Some(false), None),
            (Some(false), Some("tenant")),
            (Some(true), None),
        ]
        .map(|(grease, group)| tls.config(&uri, &uri, &overrides(grease, group)).unwrap());
        let context = |config: &Config| -> *const SslContextRef { &**config.attempt().ctx() };
        // Equal context options hit the cache; others compile their own context.
        assert_eq!(context(&first), context(&second));
        assert_ne!(context(&first), context(&other));
        assert_ne!(context(&first), context(&client));

        // The cached context carries no callback, so each connection records its own rejection.
        let endpoint = quic::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let address = endpoint.local_addr().unwrap();
        for config in [&first, &second] {
            assert!(config.rejected().is_none());
            assert!(
                endpoint
                    .connect_with(
                        quic::ClientConfig::new(config.attempt()),
                        address,
                        "localhost"
                    )
                    .is_err()
            );
            assert!(config.rejected().is_some());
        }
    }

    #[tokio::test]
    async fn client_hello_extensions_follow_quic_options() {
        use std::{sync::Mutex, time::Duration};

        use btls::ssl::{ExtensionType, SelectCertError};
        use quic::crypto::btls::QuicServerConfig;

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
