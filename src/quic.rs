//! QUIC transport and TLS 1.3 handshake options.
//!
//! Use [`QuicOptions`] to configure QUIC connections, [`Http3Options`] for HTTP/3 framing,
//! and [`TlsOptions`] for TLS over TCP/Unix sockets.
//!
//! [`Http3Options`]: crate::http3::Http3Options
//! [`TlsOptions`]: crate::tls::TlsOptions

mod session;
pub(crate) mod tls;

use std::{borrow::Cow, time::Duration};

use derive_deftly::Deftly;
use educe::Educe;

use crate::{
    Error,
    tls::{
        EchGrease, ExtensionType, KeyShare, Tls13Cipher,
        compress::{CertificateCompressor, Compressors},
    },
};

/// Builder for [`QuicOptions`].
///
/// Created via [`QuicOptions::builder`] to configure QUIC transport parameters and TLS 1.3
/// handshake options for HTTP/3 connections.
#[must_use]
#[derive(Debug, Clone)]
pub struct QuicOptionsBuilder {
    config: QuicOptions,
}

/// QUIC transport parameters and TLS 1.3 handshake options for HTTP/3 connections.
///
/// QUIC always negotiates TLS 1.3 with ALPN `h3`
/// ([RFC 9001 Section 4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.2)), so
/// version bounds, ALPN lists, and TLS 1.2 settings are omitted. Shared TLS fields match
/// [`TlsOptions`](crate::tls::TlsOptions) in name and behavior but are configured
/// independently; `None` keeps the backend default.
#[non_exhaustive]
#[derive(Debug, Clone, Educe, Deftly)]
#[educe(Default)]
#[derive_deftly(crate::tls::macros::TlsKey)]
#[deftly(tls_key(quic))]
pub struct QuicOptions {
    /// Maximum idle timeout advertised as `max_idle_timeout`
    /// ([RFC 9000 Section 10.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1)).
    ///
    /// Zero omits the parameter and leaves only the server's limit; in that case an
    /// unanswered handshake is only bounded by
    /// [`connect_timeout`](crate::ClientBuilder::connect_timeout).
    ///
    /// **Default:** `None` (30 seconds).
    #[deftly(tls_key(transport))]
    pub max_idle_timeout: Option<Duration>,

    /// Interval for sending PING frames during inactivity (must be non-zero).
    ///
    /// **Default:** `None` (disabled).
    #[deftly(tls_key(transport))]
    pub keep_alive_interval: Option<Duration>,

    /// Connection-level flow control limit, advertised as `initial_max_data` (must be non-zero).
    ///
    /// **Default:** `None` (backend default).
    #[deftly(tls_key(transport))]
    pub initial_max_data: Option<u64>,

    /// Per-stream flow control limit, advertised as `initial_max_stream_data_bidi_local`,
    /// `initial_max_stream_data_bidi_remote`, and `initial_max_stream_data_uni` (at least 1024;
    /// [RFC 9114 Section 6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2)).
    ///
    /// **Default:** `None` (backend default).
    #[deftly(tls_key(transport))]
    pub initial_max_stream_data: Option<u64>,

    /// Maximum bidirectional streams the server may open (`initial_max_streams_bidi`, up to
    /// 65535).
    ///
    /// Each allowed stream slot is reserved when the connection starts.
    ///
    /// **Default:** `None` (100).
    #[deftly(tls_key(transport))]
    pub initial_max_streams_bidi: Option<u64>,

    /// Maximum unidirectional streams the server may open (`initial_max_streams_uni`, 3–65535;
    /// [RFC 9114 Section 6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2)).
    ///
    /// **Default:** `None` (100).
    #[deftly(tls_key(transport))]
    pub initial_max_streams_uni: Option<u64>,

    /// Largest DATAGRAM frame the server may send (`max_datagram_frame_size`,
    /// [RFC 9221 Section 3](https://www.rfc-editor.org/rfc/rfc9221.html#section-3)).
    ///
    /// Also bounds buffered datagrams; zero disables them. `quic://` proxy connections ignore
    /// values too small to buffer 16 tunneled packets (~20 KB) and use the default instead.
    ///
    /// **Default:** `None` (1,250,000).
    #[deftly(tls_key(transport))]
    pub max_datagram_frame_size: Option<u64>,

    /// Initial UDP payload size before path MTU discovery (values below 1200 are clamped to 1200).
    ///
    /// **Default:** `None` (1200).
    #[deftly(tls_key(transport))]
    pub initial_mtu: Option<u16>,

    /// Controls the latency spin bit ([RFC 9000 Section 17.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.4)).
    ///
    /// **Default:** `None` (enabled on most connections).
    #[deftly(tls_key(transport))]
    pub allow_spin: Option<bool>,

    /// Supported groups, as [`TlsOptions::curves_list`](crate::tls::TlsOptions::curves_list).
    ///
    /// **Default:** `None`.
    pub curves_list: Option<Cow<'static, str>>,

    /// Key shares offered in the ClientHello, as
    /// [`TlsOptions::key_shares`](crate::tls::TlsOptions::key_shares).
    ///
    /// **Default:** `None`.
    #[deftly(tls_key(session))]
    pub key_shares: Option<Cow<'static, [KeyShare]>>,

    /// Signature algorithms, as
    /// [`TlsOptions::sigalgs_list`](crate::tls::TlsOptions::sigalgs_list).
    ///
    /// **Default:** `None`.
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// TLS 1.3 cipher suites in offer order, as in
    /// [`TlsOptions::tls13_cipher_list`](crate::tls::TlsOptions::tls13_cipher_list).
    ///
    /// An empty list uses backend defaults; duplicate suites fail TLS setup.
    ///
    /// **Default:** `None` (backend defaults).
    pub tls13_cipher_list: Option<Cow<'static, [Tls13Cipher]>>,

    /// Controls TLS GREASE ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_enabled: Option<bool>,

    /// Controls a GREASE value in the `signature_algorithms` extension.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_sigalgs_enabled: Option<bool>,

    /// Controls permutation of ClientHello extensions.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub permute_extensions: Option<bool>,

    /// ClientHello extension order, as in
    /// [`TlsOptions::extension_permutation`](crate::tls::TlsOptions::extension_permutation).
    ///
    /// QUIC sends [`ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD`] and never sends padding.
    ///
    /// **Default:** `None`.
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`.
    pub(crate) certificate_compressors: Compressors,

    /// Signature algorithms for delegated credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// **Default:** `None`.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// Requests OCSP stapling.
    ///
    /// **Default:** `false`.
    pub enable_ocsp_stapling: bool,

    /// Requests Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`.
    pub enable_signed_cert_timestamps: bool,

    /// Sends the `record_size_limit` extension ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449.html)).
    ///
    /// QUIC does not use TLS records, so this only shapes the ClientHello.
    ///
    /// **Default:** `None`.
    pub record_size_limit: Option<u16>,

    /// Encoded Trust Anchor IDs, as
    /// [`TlsOptions::trust_anchors`](crate::tls::TlsOptions::trust_anchors).
    ///
    /// **Default:** `None`.
    pub trust_anchors: Option<Cow<'static, [u8]>>,

    /// ECH GREASE policy; independent of the TLS cipher suite order.
    ///
    /// **Default:** `None` (GREASE disabled).
    pub ech_grease: Option<EchGrease>,

    /// Controls PSK with (EC)DHE key establishment (`psk_dhe_ke`); `Some(false)` disables
    /// resumption.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub psk_dhe_ke: Option<bool>,

    /// Resumes sessions through the TLS 1.3 `pre_shared_key` extension, without early data.
    ///
    /// **Default:** `false`.
    pub pre_shared_key: bool,

    /// Offers ALPS for `h3` during the TLS handshake, independently of ALPN negotiation.
    ///
    /// **Default:** `false`.
    #[deftly(tls_key(pool))]
    pub enable_alps_protocol: bool,

    /// Selects the new ALPS codepoint when ALPS is enabled.
    ///
    /// **Default:** `true`.
    #[educe(Default = true)]
    #[deftly(tls_key(pool))]
    pub alps_use_new_codepoint: bool,
}

// ===== impl QuicOptionsBuilder =====

impl QuicOptionsBuilder {
    /// Sets the idle timeout.
    #[inline]
    pub fn max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.max_idle_timeout = Some(timeout);
        self
    }

    /// Sets the keep-alive interval.
    #[inline]
    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config.keep_alive_interval = Some(interval);
        self
    }

    /// Sets the connection flow control limit.
    #[inline]
    pub fn initial_max_data(mut self, limit: u64) -> Self {
        self.config.initial_max_data = Some(limit);
        self
    }

    /// Sets the stream flow control limit.
    #[inline]
    pub fn initial_max_stream_data(mut self, limit: u64) -> Self {
        self.config.initial_max_stream_data = Some(limit);
        self
    }

    /// Sets how many bidirectional streams the server may open.
    #[inline]
    pub fn initial_max_streams_bidi(mut self, count: u64) -> Self {
        self.config.initial_max_streams_bidi = Some(count);
        self
    }

    /// Sets how many unidirectional streams the server may open.
    #[inline]
    pub fn initial_max_streams_uni(mut self, count: u64) -> Self {
        self.config.initial_max_streams_uni = Some(count);
        self
    }

    /// Sets the largest DATAGRAM frame the server may send; zero disables datagrams.
    #[inline]
    pub fn max_datagram_frame_size(mut self, size: u64) -> Self {
        self.config.max_datagram_frame_size = Some(size);
        self
    }

    /// Sets the initial UDP payload size.
    #[inline]
    pub fn initial_mtu(mut self, mtu: u16) -> Self {
        self.config.initial_mtu = Some(mtu);
        self
    }

    /// Sets whether the latency spin bit may be used.
    #[inline]
    pub fn allow_spin(mut self, enabled: bool) -> Self {
        self.config.allow_spin = Some(enabled);
        self
    }

    /// Sets the supported groups.
    #[inline]
    pub fn curves_list<T: Into<Cow<'static, str>>>(mut self, curves: T) -> Self {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the key shares offered in the ClientHello.
    #[inline]
    pub fn key_shares<T: Into<Cow<'static, [KeyShare]>>>(mut self, key_shares: T) -> Self {
        self.config.key_shares = Some(key_shares.into());
        self
    }

    /// Sets the signature algorithms.
    #[inline]
    pub fn sigalgs_list<T: Into<Cow<'static, str>>>(mut self, sigalgs: T) -> Self {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the TLS 1.3 cipher suites in offer order.
    ///
    /// An empty list restores backend defaults; duplicate suites fail TLS setup.
    #[inline]
    pub fn tls13_cipher_list<T: Into<Cow<'static, [Tls13Cipher]>>>(mut self, ciphers: T) -> Self {
        self.config.tls13_cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the GREASE flag.
    #[inline]
    pub fn grease_enabled<T: Into<Option<bool>>>(mut self, enabled: T) -> Self {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets the signature algorithms GREASE flag.
    #[inline]
    pub fn grease_sigalgs_enabled<T: Into<Option<bool>>>(mut self, enabled: T) -> Self {
        self.config.grease_sigalgs_enabled = enabled.into();
        self
    }

    /// Sets whether ClientHello extensions are permuted.
    #[inline]
    pub fn permute_extensions<T: Into<Option<bool>>>(mut self, permute: T) -> Self {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the ClientHello extension order.
    #[inline]
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compressors<T>(mut self, compressors: T) -> Self
    where
        T: Into<Cow<'static, [&'static dyn CertificateCompressor]>>,
    {
        self.config.certificate_compressors = Compressors::new(&compressors.into());
        self
    }

    /// Sets the delegated credentials.
    #[inline]
    pub fn delegated_credentials<T: Into<Cow<'static, str>>>(mut self, credentials: T) -> Self {
        self.config.delegated_credentials = Some(credentials.into());
        self
    }

    /// Sets the OCSP stapling flag.
    #[inline]
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    #[inline]
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    #[inline]
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the encoded Trust Anchor IDs.
    #[inline]
    pub fn trust_anchors<T: Into<Cow<'static, [u8]>>>(mut self, ids: T) -> Self {
        self.config.trust_anchors = Some(ids.into());
        self
    }

    /// Sets the ECH GREASE policy, or disables GREASE with `None`.
    #[inline]
    pub fn ech_grease<T: Into<Option<EchGrease>>>(mut self, policy: T) -> Self {
        self.config.ech_grease = policy.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = Some(enabled);
        self
    }

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets whether HTTP/3 ALPS is offered.
    #[inline]
    pub fn enable_alps_protocol(mut self, enabled: bool) -> Self {
        self.config.enable_alps_protocol = enabled;
        self
    }

    /// Sets whether ALPS uses the new codepoint.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }

    /// Builds the [`QuicOptions`].
    #[inline]
    pub fn build(self) -> QuicOptions {
        self.config
    }
}

// ===== impl QuicOptions =====

impl QuicOptions {
    /// Creates a new [`QuicOptionsBuilder`].
    pub fn builder() -> QuicOptionsBuilder {
        QuicOptionsBuilder {
            config: QuicOptions::default(),
        }
    }

    /// Builds a [`TransportConfig`](::quic::TransportConfig) with the given datagram frame limit.
    ///
    /// Returns an error if any option is out of range for its QUIC transport parameter.
    pub(crate) fn transport(
        &self,
        datagram_frame_size: Option<u64>,
    ) -> crate::Result<::quic::TransportConfig> {
        use ::quic::{IdleTimeout, TransportConfig, VarInt};

        // The backend reserves every allowed stream when a connection starts.
        const MAX_STREAMS: u64 = u16::MAX as u64;

        let out_of_range = |name: &str, value: &dyn std::fmt::Debug| {
            Error::builder(format!("QUIC option {name} out of range: {value:?}"))
        };
        let var = |name: &str, value: u64, min: u64, max: u64| {
            (min..=max)
                .contains(&value)
                .then(|| VarInt::from_u64(value).ok())
                .flatten()
                .ok_or_else(|| out_of_range(name, &value))
        };
        let mut transport = TransportConfig::default();
        if let Some(timeout) = self.max_idle_timeout {
            // Milliseconds on the wire; a shorter nonzero value would read as disabled.
            let timeout = match timeout {
                Duration::ZERO => timeout,
                timeout => timeout.max(Duration::from_millis(1)),
            };
            let timeout = IdleTimeout::try_from(timeout)
                .map_err(|_| out_of_range("max_idle_timeout", &timeout))?;
            transport.max_idle_timeout(Some(timeout));
        }
        if let Some(interval) = self.keep_alive_interval {
            if interval.is_zero() || IdleTimeout::try_from(interval).is_err() {
                return Err(out_of_range("keep_alive_interval", &interval));
            }
            transport.keep_alive_interval(Some(interval));
        }
        if let Some(limit) = self.initial_max_data {
            transport.receive_window(var("initial_max_data", limit, 1, VarInt::MAX.into_inner())?);
        }
        if let Some(limit) = self.initial_max_stream_data {
            transport.stream_receive_window(var(
                "initial_max_stream_data",
                limit,
                1024,
                VarInt::MAX.into_inner(),
            )?);
        }
        if let Some(count) = self.initial_max_streams_bidi {
            transport.max_concurrent_bidi_streams(var(
                "initial_max_streams_bidi",
                count,
                0,
                MAX_STREAMS,
            )?);
        }
        if let Some(count) = self.initial_max_streams_uni {
            transport.max_concurrent_uni_streams(var(
                "initial_max_streams_uni",
                count,
                3,
                MAX_STREAMS,
            )?);
        }
        if let Some(size) = datagram_frame_size {
            let size = (size != 0)
                .then(|| {
                    let name = "max_datagram_frame_size";
                    let size = var(name, size, 1, VarInt::MAX.into_inner())?.into_inner();
                    usize::try_from(size).map_err(|_| out_of_range(name, &size))
                })
                .transpose()?;
            transport.datagram_receive_buffer_size(size);
        }
        if let Some(mtu) = self.initial_mtu {
            transport.initial_mtu(mtu);
        }
        if let Some(enabled) = self.allow_spin {
            transport.allow_spin(enabled);
        }
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::QuicOptions;

    #[test]
    fn options_compare_compressors_by_algorithm_in_order() {
        use crate::tls::compress::tests::compare_options;

        compare_options(QuicOptions::default(), |compressors| {
            QuicOptions::builder()
                .certificate_compressors(compressors)
                .build()
        });
    }
}
