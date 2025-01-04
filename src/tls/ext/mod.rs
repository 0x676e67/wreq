pub mod cert_compression;
#[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
mod cert_load;
use super::{AlpnProtos, RootCertsStore, TlsResult, TlsVersion};
use ::std::os::raw::c_int;
use boring::error::ErrorStack;
use boring::ssl::{ConnectConfiguration, SslConnectorBuilder, SslRef, SslVerifyMode};
use cert_compression::CertCompressionAlgorithm;
use foreign_types::ForeignTypeRef;

// ALPN protocol for HTTP/1.1 and HTTP/2.
const ALPN_HTTP_1: &[u8] = b"\x08http/1.1";
const ALPN_HTTP_2: &[u8] = b"\x02h2";
const ALPN_HTTP_1_AND_2: &[u8] = b"\x02h2\x08http/1.1";

/// Application Settings protocol for HTTP/1.1 and HTTP/2.
const ASP_HTTP_1: &[u8] = b"http/1.1";
const ASP_HTTP_2: &[u8] = b"h2";

/// Error handler for the boringssl functions.
fn sv_handler(r: c_int) -> TlsResult<c_int> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// TlsExtension trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn cert_verification(self, certs_verification: bool) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
    fn alpn_protos(self, http_version: AlpnProtos) -> TlsResult<SslConnectorBuilder>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn min_tls_version(self, min_tls_version: Option<TlsVersion>)
        -> TlsResult<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn max_tls_version(self, max_tls_version: Option<TlsVersion>)
        -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the RootCertsStore for the given `SslConnectorBuilder`.
    fn root_certs_store(self, stroe: RootCertsStore) -> TlsResult<SslConnectorBuilder>;
}

/// TlsExtension trait for `SslRef`.
pub trait SslRefExt {
    /// Configure the ALPN protos for the given `SslRef`.
    fn alpn_protos(&mut self, version: Option<AlpnProtos>) -> TlsResult<()>;
}

/// TlsConnectExtension trait for `ConnectConfiguration`.
pub trait ConnectConfigurationExt {
    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn enable_ech_grease(
        &mut self,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the add_application_settings for the given `ConnectConfiguration`.
    fn add_application_settings(
        &mut self,
        http_version: AlpnProtos,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the no session ticket for the given `ConnectConfiguration`.
    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline]
    fn cert_verification(mut self, certs_verification: bool) -> TlsResult<SslConnectorBuilder> {
        if !certs_verification {
            self.set_verify(SslVerifyMode::NONE);
        } else {
            self.set_verify(SslVerifyMode::PEER);
        }
        Ok(self)
    }

    #[inline]
    fn alpn_protos(mut self, http_version: AlpnProtos) -> TlsResult<SslConnectorBuilder> {
        let alpn = match http_version {
            AlpnProtos::Http1 => ALPN_HTTP_1,
            AlpnProtos::Http2 => ALPN_HTTP_2,
            AlpnProtos::All => ALPN_HTTP_1_AND_2,
        };

        self.set_alpn_protos(alpn).map(|_| self)
    }

    #[inline]
    fn min_tls_version(
        mut self,
        min_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder> {
        self.set_min_proto_version(min_tls_version.map(|v| v.0))
            .map(|_| self)
    }

    #[inline]
    fn max_tls_version(
        mut self,
        max_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder> {
        self.set_max_proto_version(max_tls_version.map(|v| v.0))
            .map(|_| self)
    }

    #[inline]
    fn add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        sv_handler(unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                self.as_ptr(),
                cert_compression_alg as _,
                cert_compression_alg.compression_fn(),
                cert_compression_alg.decompression_fn(),
            )
        })
        .map(|_| self)
    }

    #[inline]
    fn root_certs_store(
        mut self,
        root_certs_stroe: RootCertsStore,
    ) -> TlsResult<SslConnectorBuilder> {
        // Conditionally configure the TLS builder based on the "native-roots" feature.
        // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
        match root_certs_stroe {
            RootCertsStore::None => {
                // WebPKI root certificates are enabled (regardless of whether native-roots is also enabled).
                #[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
                {
                    if let Ok(cert_store) = cert_load::LOAD_CERTS.as_deref() {
                        log::debug!("Using CA certs from webpki/native roots");
                        sv_handler(unsafe {
                            boring_sys::SSL_CTX_set1_verify_cert_store(
                                self.as_ptr(),
                                cert_store.as_ptr(),
                            )
                        })?;
                    } else {
                        log::debug!("No CA certs provided, using system default");
                        self.set_default_verify_paths()?;
                    }
                }

                // Neither native-roots nor WebPKI roots are enabled, proceed with the default builder.
                #[cfg(not(any(feature = "webpki-roots", feature = "native-roots")))]
                {
                    self.set_default_verify_paths()?;
                }
            }
            RootCertsStore::Owned(cert_store) => {
                self.set_verify_cert_store(cert_store)?;
            }
            RootCertsStore::Borrowed(cert_store) => {
                sv_handler(unsafe {
                    boring_sys::SSL_CTX_set1_verify_cert_store(self.as_ptr(), cert_store.as_ptr())
                })?;
            }
        }

        Ok(self)
    }
}

impl ConnectConfigurationExt for ConnectConfiguration {
    #[inline]
    fn enable_ech_grease(
        &mut self,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration> {
        unsafe { boring_sys::SSL_set_enable_ech_grease(self.as_ptr(), enable_ech_grease as _) }
        Ok(self)
    }

    #[inline]
    fn add_application_settings(
        &mut self,
        http_version: AlpnProtos,
    ) -> TlsResult<&mut ConnectConfiguration> {
        let asp = match http_version {
            AlpnProtos::Http1 => ASP_HTTP_1,
            AlpnProtos::Http2 | AlpnProtos::All => ASP_HTTP_2,
        };

        sv_handler(unsafe {
            boring_sys::SSL_add_application_settings(
                self.as_ptr(),
                asp.as_ptr(),
                asp.len(),
                std::ptr::null(),
                0,
            )
        })
        .map(|_| self)
    }

    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration> {
        sv_handler(unsafe {
            boring_sys::SSL_set_options(self.as_ptr(), boring_sys::SSL_OP_NO_TICKET as _) as _
        })
        .map(|_| self)
    }
}

impl SslRefExt for SslRef {
    #[inline]
    fn alpn_protos(&mut self, version: Option<AlpnProtos>) -> TlsResult<()> {
        let alpn = match version {
            Some(AlpnProtos::Http1) => ALPN_HTTP_1,
            Some(AlpnProtos::Http2) => ALPN_HTTP_2,
            Some(AlpnProtos::All) => ALPN_HTTP_1_AND_2,
            None => return Ok(()),
        };

        self.set_alpn_protos(alpn)
    }
}
