use http::{HeaderMap, HeaderValue, header};
use wreq::{
    Client, Emulation, OriginalHeaders,
    http1::Http1Options,
    http2::{
        Http2Options, Priorities, Priority, PseudoId, PseudoOrder, SettingId, SettingsOrder,
        StreamDependency, StreamId,
    },
    tls::{AlpnProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsOptions, TlsVersion},
};

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    //  TLS options config
    let tls = TlsOptions::builder()
        .curves_list(join!(
            ":",
            "X25519",
            "P-256",
            "P-384",
            "P-521",
            "ffdhe2048",
            "ffdhe3072"
        ))
        .cipher_list(join!(
            ":",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA"
        ))
        .sigalgs_list(join!(
            ":",
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "ecdsa_sha1",
            "rsa_pkcs1_sha1"
        ))
        .delegated_credentials(join!(
            ":",
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "ecdsa_sha1"
        ))
        .certificate_compression_algorithms(&[
            CertificateCompressionAlgorithm::ZLIB,
            CertificateCompressionAlgorithm::BROTLI,
            CertificateCompressionAlgorithm::ZSTD,
        ])
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .record_size_limit(0x4001)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .min_tls_version(TlsVersion::TLS_1_0)
        .max_tls_version(TlsVersion::TLS_1_3)
        .prefer_chacha20(true)
        .aes_hw_override(false)
        .random_aes_hw_override(true)
        .extension_permutation(&[
            ExtensionType::SERVER_NAME,
            ExtensionType::EXTENDED_MASTER_SECRET,
            ExtensionType::RENEGOTIATE,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::EC_POINT_FORMATS,
            ExtensionType::SESSION_TICKET,
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ExtensionType::STATUS_REQUEST,
            ExtensionType::DELEGATED_CREDENTIAL,
            ExtensionType::KEY_SHARE,
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::PSK_KEY_EXCHANGE_MODES,
            ExtensionType::RECORD_SIZE_LIMIT,
            ExtensionType::CERT_COMPRESSION,
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
        ])
        .build();

    //  HTTP/1 options config
    let http1 = Http1Options::builder()
        .allow_obsolete_multiline_headers_in_responses(true)
        .max_headers(100)
        .build();

    // HTTP/2 options config
    let http2 = {
        // HTTP/2 headers frame pseudo-header order
        let headers_pseudo_order = PseudoOrder::builder()
            .extend([
                PseudoId::Method,
                PseudoId::Scheme,
                PseudoId::Authority,
                PseudoId::Path,
            ])
            .build();

        // HTTP/2 settings frame order
        let settings_order = SettingsOrder::builder()
            .extend([
                SettingId::HeaderTableSize,
                SettingId::EnablePush,
                SettingId::MaxConcurrentStreams,
                SettingId::InitialWindowSize,
                SettingId::MaxFrameSize,
                SettingId::MaxHeaderListSize,
                SettingId::EnableConnectProtocol,
                SettingId::NoRfc7540Priorities,
            ])
            .build();

        // HTTP/2 Priority frames
        let priorities = Priorities::builder()
            .extend([
                Priority::new(
                    StreamId::from(3),
                    StreamDependency::new(StreamId::zero(), 200, false),
                ),
                Priority::new(
                    StreamId::from(5),
                    StreamDependency::new(StreamId::zero(), 100, false),
                ),
                Priority::new(
                    StreamId::from(7),
                    StreamDependency::new(StreamId::zero(), 0, false),
                ),
                Priority::new(
                    StreamId::from(9),
                    StreamDependency::new(StreamId::from(7), 0, false),
                ),
                Priority::new(
                    StreamId::from(11),
                    StreamDependency::new(StreamId::from(3), 0, false),
                ),
                Priority::new(
                    StreamId::from(13),
                    StreamDependency::new(StreamId::zero(), 240, false),
                ),
            ])
            .build();

        Http2Options::builder()
            .initial_stream_id(15)
            .header_table_size(65536)
            .initial_window_size(131072)
            .max_frame_size(16384)
            .initial_connection_window_size(12517377 + 65535)
            .headers_stream_dependency(StreamDependency::new(StreamId::from(13), 41, false))
            .headers_pseudo_order(headers_pseudo_order)
            .settings_order(settings_order)
            .priorities(priorities)
            .build()
    };

    // Default headers
    let headers = {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0"));
        headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(header::COOKIE, HeaderValue::from_static("foo=bar"));
        headers
    };

    // The headers keep the original case and order
    let original_headers = {
        let mut original_headers = OriginalHeaders::new();
        original_headers.insert("cookie");
        original_headers.insert("content-length");
        original_headers.insert("USER-AGENT");
        original_headers.insert("ACCEPT-LANGUAGE");
        original_headers.insert("ACCEPT-ENCODING");
        original_headers
    };

    // This provider encapsulates TLS, HTTP/1, HTTP/2, default headers, and original headers
    let emulation = Emulation::builder()
        .tls_options(tls)
        .http1_options(http1)
        .http2_options(http2)
        .headers(headers)
        .original_headers(original_headers)
        .build();

    // Build a client with emulation config
    let client = Client::builder()
        .emulation(emulation)
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.post("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
