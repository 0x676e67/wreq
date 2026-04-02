//! HTTP/3 protocol options and utilities.

use std::borrow::Cow;

#[allow(unused_imports)]
pub use h3::{PseudoId, PseudoOrder, SettingId};
#[allow(unused_imports)]
pub use quinn_proto::{
    TransportParameterConfig, TransportParameterId, TransportParameterKind, VarInt,
    VersionEntry, VersionInformation,
};

use btls::ssl::ExtensionType;

use crate::tls::compress::CertificateCompressor;

/// Builder for [`Http3Options`].
#[must_use]
#[derive(Debug, Clone)]
pub struct Http3OptionsBuilder {
    opts: Http3Options,
}

/// Options for tuning HTTP/3 connections and QUIC transport parameters.
///
/// `Http3Options` lets you adjust how HTTP/3 and QUIC work — SETTINGS frame
/// entries and ordering, QPACK configuration, pseudo-header ordering, QUIC
/// transport parameter ordering and values, and QUIC-specific TLS overrides.
///
/// All fields are optional and have sensible defaults. See each field for
/// details.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Http3Options {
    // === HTTP/3 SETTINGS (h3 layer) ===
    /// QPACK max table capacity (SETTINGS 0x1).
    pub qpack_max_table_capacity: Option<u64>,

    /// QPACK blocked streams (SETTINGS 0x7).
    pub qpack_blocked_streams: Option<u64>,

    /// Max header list / field section size (SETTINGS 0x6).
    pub max_field_section_size: Option<u64>,

    /// Enable CONNECT protocol (SETTINGS 0x8).
    pub enable_connect_protocol: Option<bool>,

    /// Enable HTTP/3 datagrams (SETTINGS 0x33).
    pub enable_datagram: Option<bool>,

    /// Whether to send GREASE in the SETTINGS frame.
    pub send_grease: Option<bool>,

    /// Ordered list of setting IDs for the SETTINGS frame.
    ///
    /// Controls the wire order of SETTINGS entries. GREASE (if enabled)
    /// is always appended after these.
    pub settings_order: Option<Vec<SettingId>>,

    /// Extra/custom settings entries (e.g., Firefox's unknown IDs).
    ///
    /// Each entry is a `(SettingId, value)` pair that will be included
    /// in the SETTINGS frame.
    pub extra_settings: Option<Vec<(SettingId, u64)>>,

    /// Pseudo-header order for requests (`:method`, `:authority`, `:scheme`, `:path`).
    ///
    /// Chrome uses "masp" (Method, Authority, Scheme, Path).
    /// Firefox uses "msap" (Method, Scheme, Authority, Path).
    pub pseudo_header_order: Option<PseudoOrder>,

    // === QUIC Transport Parameters (quinn layer) ===
    /// Full transport parameter configuration (ordering, custom params, GREASE).
    ///
    /// This controls which transport parameters are emitted on the wire
    /// and in what order. Use `TransportParameterConfig::new()` with a
    /// list of `TransportParameterKind` entries.
    pub transport_parameter_config: Option<TransportParameterConfig>,

    /// Max idle timeout in milliseconds.
    pub max_idle_timeout: Option<u64>,

    /// Connection-level flow control window (`initial_max_data`).
    pub conn_receive_window: Option<u32>,

    /// Per-stream flow control window (`initial_max_stream_data_bidi_local`).
    pub stream_receive_window: Option<u32>,

    /// Max concurrent bidirectional streams.
    pub max_concurrent_bidi_streams: Option<u32>,

    /// Max concurrent unidirectional streams.
    pub max_concurrent_uni_streams: Option<u32>,

    /// Max datagram frame size / receive buffer size.
    pub datagram_receive_buffer_size: Option<usize>,

    /// Send window size.
    pub send_window: Option<u64>,

    // === QUIC Endpoint Config ===
    /// Connection ID length (0 for Chrome's zero-length CIDs).
    pub connection_id_length: Option<usize>,

    /// Initial destination connection ID length (Chrome uses 8).
    ///
    /// The RFC requires at least 8 bytes. Quinn defaults to 20.
    pub initial_dst_cid_length: Option<usize>,

    /// Whether to GREASE the QUIC fixed bit.
    pub grease_quic_bit: Option<bool>,

    // === QUIC TLS overrides ===
    //
    // These override the corresponding values from `TlsOptions` when
    // configuring the QUIC TLS handshake. Browsers may use different
    // TLS parameters for QUIC vs TCP connections.
    /// Signature algorithms for QUIC TLS (may differ from HTTP/2 TLS).
    pub quic_sigalgs_list: Option<Cow<'static, str>>,

    /// TLS extension order for QUIC TLS (may differ from HTTP/2 TLS).
    pub quic_extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Whether to enable OCSP stapling for QUIC TLS.
    ///
    /// Chrome does not send status_request (5) for QUIC; Firefox does.
    pub quic_enable_ocsp_stapling: Option<bool>,

    /// Whether to enable signed certificate timestamps for QUIC TLS.
    ///
    /// Chrome does not send SCT (18) for QUIC; Firefox does.
    pub quic_enable_signed_cert_timestamps: Option<bool>,

    /// Whether TLS GREASE is enabled for QUIC (Chrome disables it for QUIC).
    pub quic_grease_enabled: Option<bool>,

    /// Certificate compressors for QUIC TLS (e.g., brotli).
    pub quic_certificate_compressors: Option<Cow<'static, [&'static dyn CertificateCompressor]>>,

    /// Curves list for QUIC TLS.
    pub quic_curves_list: Option<Cow<'static, str>>,

    /// ALPS protocols for QUIC (e.g., `["h3"]`).
    pub quic_alps_protocols: Option<Vec<Vec<u8>>>,

    /// Use new ALPS codepoint (17613 vs 17513).
    pub quic_alps_use_new_codepoint: Option<bool>,

    /// Enable ECH GREASE for QUIC TLS.
    pub quic_ech_grease: Option<bool>,
}

impl Http3OptionsBuilder {
    // === HTTP/3 SETTINGS ===

    /// Sets QPACK max table capacity (SETTINGS 0x1).
    #[inline]
    pub fn qpack_max_table_capacity(mut self, val: impl Into<Option<u64>>) -> Self {
        self.opts.qpack_max_table_capacity = val.into();
        self
    }

    /// Sets QPACK blocked streams (SETTINGS 0x7).
    #[inline]
    pub fn qpack_blocked_streams(mut self, val: impl Into<Option<u64>>) -> Self {
        self.opts.qpack_blocked_streams = val.into();
        self
    }

    /// Sets max header list / field section size (SETTINGS 0x6).
    #[inline]
    pub fn max_field_section_size(mut self, val: impl Into<Option<u64>>) -> Self {
        self.opts.max_field_section_size = val.into();
        self
    }

    /// Sets whether to enable the CONNECT protocol (SETTINGS 0x8).
    #[inline]
    pub fn enable_connect_protocol(mut self, val: bool) -> Self {
        self.opts.enable_connect_protocol = Some(val);
        self
    }

    /// Sets whether to enable HTTP/3 datagrams (SETTINGS 0x33).
    #[inline]
    pub fn enable_datagram(mut self, val: bool) -> Self {
        self.opts.enable_datagram = Some(val);
        self
    }

    /// Sets whether to send GREASE in the SETTINGS frame.
    #[inline]
    pub fn send_grease(mut self, val: bool) -> Self {
        self.opts.send_grease = Some(val);
        self
    }

    /// Sets the ordered list of setting IDs for the SETTINGS frame.
    #[inline]
    pub fn settings_order(mut self, order: impl Into<Option<Vec<SettingId>>>) -> Self {
        self.opts.settings_order = order.into();
        self
    }

    /// Sets extra/custom settings entries.
    #[inline]
    pub fn extra_settings(mut self, entries: impl Into<Option<Vec<(SettingId, u64)>>>) -> Self {
        self.opts.extra_settings = entries.into();
        self
    }

    /// Sets the pseudo-header order for requests.
    #[inline]
    pub fn pseudo_header_order(mut self, order: impl Into<Option<PseudoOrder>>) -> Self {
        self.opts.pseudo_header_order = order.into();
        self
    }

    // === QUIC Transport Parameters ===

    /// Sets the full transport parameter configuration.
    #[inline]
    pub fn transport_parameter_config(
        mut self,
        config: impl Into<Option<TransportParameterConfig>>,
    ) -> Self {
        self.opts.transport_parameter_config = config.into();
        self
    }

    /// Sets the max idle timeout in milliseconds.
    #[inline]
    pub fn max_idle_timeout(mut self, ms: impl Into<Option<u64>>) -> Self {
        self.opts.max_idle_timeout = ms.into();
        self
    }

    /// Sets the connection-level receive window (`initial_max_data`).
    #[inline]
    pub fn conn_receive_window(mut self, val: impl Into<Option<u32>>) -> Self {
        self.opts.conn_receive_window = val.into();
        self
    }

    /// Sets the per-stream receive window (`initial_max_stream_data_bidi_local`).
    #[inline]
    pub fn stream_receive_window(mut self, val: impl Into<Option<u32>>) -> Self {
        self.opts.stream_receive_window = val.into();
        self
    }

    /// Sets max concurrent bidirectional streams.
    #[inline]
    pub fn max_concurrent_bidi_streams(mut self, val: impl Into<Option<u32>>) -> Self {
        self.opts.max_concurrent_bidi_streams = val.into();
        self
    }

    /// Sets max concurrent unidirectional streams.
    #[inline]
    pub fn max_concurrent_uni_streams(mut self, val: impl Into<Option<u32>>) -> Self {
        self.opts.max_concurrent_uni_streams = val.into();
        self
    }

    /// Sets the datagram receive buffer size.
    #[inline]
    pub fn datagram_receive_buffer_size(mut self, val: impl Into<Option<usize>>) -> Self {
        self.opts.datagram_receive_buffer_size = val.into();
        self
    }

    /// Sets the send window size.
    #[inline]
    pub fn send_window(mut self, val: impl Into<Option<u64>>) -> Self {
        self.opts.send_window = val.into();
        self
    }

    // === QUIC Endpoint Config ===

    /// Sets the connection ID length (0 for zero-length CIDs like Chrome).
    #[inline]
    pub fn connection_id_length(mut self, len: impl Into<Option<usize>>) -> Self {
        self.opts.connection_id_length = len.into();
        self
    }

    /// Sets the initial destination connection ID length (Chrome uses 8).
    #[inline]
    pub fn initial_dst_cid_length(mut self, len: impl Into<Option<usize>>) -> Self {
        self.opts.initial_dst_cid_length = len.into();
        self
    }

    /// Sets whether to GREASE the QUIC fixed bit.
    #[inline]
    pub fn grease_quic_bit(mut self, val: bool) -> Self {
        self.opts.grease_quic_bit = Some(val);
        self
    }

    // === QUIC TLS overrides ===

    /// Sets the signature algorithms for QUIC TLS.
    #[inline]
    pub fn quic_sigalgs_list<T>(mut self, val: T) -> Self
    where
        T: Into<Option<Cow<'static, str>>>,
    {
        self.opts.quic_sigalgs_list = val.into();
        self
    }

    /// Sets the TLS extension order for QUIC TLS.
    #[inline]
    pub fn quic_extension_permutation<T>(mut self, val: T) -> Self
    where
        T: Into<Option<Cow<'static, [ExtensionType]>>>,
    {
        self.opts.quic_extension_permutation = val.into();
        self
    }

    /// Sets whether to enable OCSP stapling for QUIC TLS.
    #[inline]
    pub fn quic_enable_ocsp_stapling(mut self, val: bool) -> Self {
        self.opts.quic_enable_ocsp_stapling = Some(val);
        self
    }

    /// Sets whether to enable signed certificate timestamps for QUIC TLS.
    #[inline]
    pub fn quic_enable_signed_cert_timestamps(mut self, val: bool) -> Self {
        self.opts.quic_enable_signed_cert_timestamps = Some(val);
        self
    }

    /// Sets whether TLS GREASE is enabled for QUIC.
    #[inline]
    pub fn quic_grease_enabled(mut self, val: bool) -> Self {
        self.opts.quic_grease_enabled = Some(val);
        self
    }

    /// Sets certificate compressors for QUIC TLS.
    #[inline]
    pub fn quic_certificate_compressors<T>(mut self, val: T) -> Self
    where
        T: Into<Option<Cow<'static, [&'static dyn CertificateCompressor]>>>,
    {
        self.opts.quic_certificate_compressors = val.into();
        self
    }

    /// Sets the curves list for QUIC TLS.
    #[inline]
    pub fn quic_curves_list<T>(mut self, val: T) -> Self
    where
        T: Into<Option<Cow<'static, str>>>,
    {
        self.opts.quic_curves_list = val.into();
        self
    }

    /// Sets the ALPS protocols for QUIC.
    #[inline]
    pub fn quic_alps_protocols(mut self, val: impl Into<Option<Vec<Vec<u8>>>>) -> Self {
        self.opts.quic_alps_protocols = val.into();
        self
    }

    /// Sets whether to use the new ALPS codepoint.
    #[inline]
    pub fn quic_alps_use_new_codepoint(mut self, val: bool) -> Self {
        self.opts.quic_alps_use_new_codepoint = Some(val);
        self
    }

    /// Sets whether to enable ECH GREASE for QUIC TLS.
    #[inline]
    pub fn quic_ech_grease(mut self, val: bool) -> Self {
        self.opts.quic_ech_grease = Some(val);
        self
    }

    /// Builds the [`Http3Options`] instance.
    #[inline]
    pub fn build(self) -> Http3Options {
        self.opts
    }
}

impl Http3Options {
    /// Creates a new [`Http3OptionsBuilder`].
    pub fn builder() -> Http3OptionsBuilder {
        Http3OptionsBuilder {
            opts: Http3Options::default(),
        }
    }
}
