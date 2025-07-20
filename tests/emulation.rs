use wreq::{
    Client, Emulation,
    http1::Http1Options,
    http2::{
        Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
    },
    tls::{AlpnProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsOptions, TlsVersion},
};

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

#[tokio::test]
async fn test_emulation_firefox() -> wreq::Result<()> {
    //  TLS options config
    let tls = TlsOptions::builder()
        .curves_list(join!(
            ":",
            "X25519MLKEM768",
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
        .alpn_protocols(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .record_size_limit(0x4001)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .key_shares_limit(3)
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
                PseudoId::Path,
                PseudoId::Authority,
                PseudoId::Scheme,
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

        Http2Options::builder()
            .header_table_size(65536)
            .enable_push(false)
            .initial_window_size(131072)
            .max_frame_size(16384)
            .initial_connection_window_size(12517377 + 65535)
            .headers_stream_dependency(StreamDependency::new(StreamId::ZERO, 41, false))
            .headers_pseudo_order(headers_pseudo_order)
            .settings_order(settings_order)
            .build()
    };

    // This provider encapsulates TLS, HTTP/1, HTTP/2, default headers, and original headers
    let emulation = Emulation::builder()
        .tls_options(tls)
        .http1_options(http1)
        .http2_options(http2)
        .build();

    // Build a client with emulation config
    let client = Client::builder()
        .emulation(emulation)
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.post("https://tls.browserleaks.com/").send().await?;
    let text = resp.text().await?;
    assert!(
        text.contains("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
        "Response ja4_hash fingerprint not found"
    );
    assert!(
        text.contains("6ea73faa8fc5aac76bded7bd238f6433"),
        "Response akamai_hash fingerprint not found"
    );

    Ok(())
}
