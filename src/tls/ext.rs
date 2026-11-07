//! BoringSSL context configuration for client policy and transport-specific TLS options.

use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{EchGreaseRounding, Ssl, SslContextBuilder, SslOptions, SslRef, SslVerifyMode},
};

#[cfg(feature = "http3")]
use crate::quic::QuicOptions;
use crate::{
    Error,
    tls::{
        EchGrease, TlsOptions,
        compress::{self, CertificateCompressor},
        trust::{CertStore, Identity},
    },
};

fn host_length_index() -> Result<Index<Ssl, usize>, ErrorStack> {
    static INDEX: std::sync::LazyLock<Result<Index<Ssl, usize>, ErrorStack>> =
        std::sync::LazyLock::new(Ssl::new_ex_index);
    INDEX.clone()
}

/// Enables GREASE and retains the target host length for NSS sizing, even without SNI.
pub(super) fn set_ech_grease_host(ssl: &mut SslRef, host_length: usize) -> Result<(), ErrorStack> {
    ssl.set_enable_ech_grease(true);
    ssl.set_ex_data(host_length_index()?, host_length);
    Ok(())
}

fn set_ech_grease_policy(builder: &mut SslContextBuilder, policy: Option<EchGrease>) {
    if let Some(policy) = policy
        && policy != EchGrease::Default
    {
        builder.set_ech_grease_callback(move |ssl, info| {
            let nss = |rounding| {
                let host_length = ssl.ex_data(host_length_index()?).copied().unwrap_or(0);
                info.nss_parameters(100, host_length, rounding)
            };
            match policy {
                EchGrease::Default => info.boringssl_parameters(info.default_aead()),
                EchGrease::Aead(aead) => info.boringssl_parameters(aead),
                EchGrease::NssPre3127 => nss(EchGreaseRounding::NssPre3127),
                EchGrease::Nss3127 => nss(EchGreaseRounding::Nss3127),
            }
        });
    }
}

#[cfg(any(feature = "chromium-roots", feature = "webpki-roots"))]
static BUNDLED_CERT_STORE: std::sync::LazyLock<Result<CertStore, std::sync::Arc<Error>>> =
    std::sync::LazyLock::new(|| {
        let sources = &[
            #[cfg(feature = "chromium-roots")]
            chromium_roots::TLS_SERVER_ROOT_CERTS,
            #[cfg(feature = "webpki-roots")]
            webpki_root_certs::TLS_SERVER_ROOT_CERTS,
        ];

        let certs = sources
            .iter()
            .enumerate()
            .flat_map(|(source_index, source)| {
                let previous_sources = &sources[..source_index];
                source.iter().filter(move |cert| {
                    !previous_sources.iter().any(|source| source.contains(*cert))
                })
            })
            .map(AsRef::as_ref);

        CertStore::from_der_certs(certs).map_err(std::sync::Arc::new)
    });

/// Applies client policy and TLS options to BoringSSL contexts.
pub(super) trait SslContextBuilderExt {
    /// Applies TCP/Unix context options.
    /// Version limits, resumption callbacks and per-SSL settings are applied separately.
    fn set_tls_options(&mut self, options: &TlsOptions) -> crate::Result<()>;

    /// Applies QUIC context options. ALPN, resumption and per-SSL settings are set separately.
    #[cfg(feature = "http3")]
    fn set_quic_options(&mut self, options: &QuicOptions) -> crate::Result<()>;

    /// Installs the client certificate chain and private key.
    fn set_identity(&mut self, identity: Option<&Identity>) -> crate::Result<()>;

    /// Installs the supplied trust roots or the configured default root store.
    fn set_root_store(&mut self, store: Option<&CertStore>) -> crate::Result<()>;

    /// Controls certificate chain verification independently of hostname checks.
    fn set_cert_verification(&mut self, enable: bool);

    /// Registers certificate compressors in the supplied order.
    /// Returns backend errors for the caller to classify once.
    fn set_cert_compressors(
        &mut self,
        compressors: &[&dyn CertificateCompressor],
    ) -> Result<(), ErrorStack>;
}

impl SslContextBuilderExt for SslContextBuilder {
    fn set_tls_options(&mut self, options: &TlsOptions) -> crate::Result<()> {
        set_hello_options!(tcp, options, self);
        Ok(())
    }

    #[cfg(feature = "http3")]
    fn set_quic_options(&mut self, options: &QuicOptions) -> crate::Result<()> {
        set_hello_options!(quic, options, self);
        Ok(())
    }

    fn set_identity(&mut self, identity: Option<&Identity>) -> crate::Result<()> {
        if let Some(identity) = identity {
            self.set_certificate(&identity.cert).map_err(Error::tls)?;
            self.set_private_key(&identity.pkey).map_err(Error::tls)?;
            for cert in identity.chain.iter() {
                // https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_extra_chain_cert.html
                // specifies that "When sending a certificate chain, extra chain certificates are
                // sent in order following the end entity certificate."
                self.add_extra_chain_cert(cert.clone())
                    .map_err(Error::tls)?;
            }
        }
        Ok(())
    }

    fn set_root_store(&mut self, store: Option<&CertStore>) -> crate::Result<()> {
        if let Some(store) = store {
            self.set_cert_store_ref(&store.0)
        } else {
            cfg_select! {
                any(feature = "chromium-roots", feature = "webpki-roots") => {
                    let store = BUNDLED_CERT_STORE
                        .as_ref()
                        .map_err(|error| Error::tls(error.clone()))?;
                    self.set_cert_store_ref(&store.0);
                }
                _ => {
                    self.set_default_verify_paths().map_err(Error::tls)?;
                }
            }
        }

        Ok(())
    }

    fn set_cert_verification(&mut self, enable: bool) {
        self.set_verify(if enable {
            SslVerifyMode::PEER
        } else {
            SslVerifyMode::NONE
        });
    }

    fn set_cert_compressors(
        &mut self,
        compressors: &[&dyn CertificateCompressor],
    ) -> Result<(), ErrorStack> {
        for &compressor in compressors {
            compress::register(compressor, self)?;
        }

        Ok(())
    }
}
