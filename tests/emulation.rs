use std::{
    io::{self, Write},
    time::Duration,
};

use brotli::{CompressorWriter as BrotliDecoder, Decompressor as BrotliEncoder};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use wreq::{
    Client, Emulation,
    http1::Http1Options,
    http2::{
        Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
    },
    tls::{
        AlpnProtocol, ExtensionType, KeyShare, TlsOptions, TlsVersion,
        compress::{CertificateCompressionAlgorithm, CertificateCompressor},
    },
};
use zstd::stream::{Decoder as ZstdDecoder, Encoder as ZstdEncoder};

#[derive(Debug)]
struct BrotliCompressor;

#[derive(Debug)]
struct ZlibCompressor;

#[derive(Debug)]
struct ZstdCompressor;

impl CertificateCompressor for BrotliCompressor {
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut writer = BrotliDecoder::new(output, input.len(), 11, 22);
        writer.write_all(input)?;
        writer.flush()
    }

    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut reader = BrotliEncoder::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::BROTLI
    }
}

impl CertificateCompressor for ZlibCompressor {
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut encoder = ZlibEncoder::new(output, Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut reader = ZlibDecoder::new(input);
        io::copy(&mut reader, output)?;
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZLIB
    }
}

impl CertificateCompressor for ZstdCompressor {
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut encoder = ZstdEncoder::new(output, 0)?;
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        let mut reader = ZstdDecoder::new(input)?;
        io::copy(&mut reader, output)?;
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZSTD
    }
}

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

fn tls_options_template() -> TlsOptions {
    //  TLS options config
    TlsOptions::builder()
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
        .certificate_compressors(vec![
            &BrotliCompressor as _,
            &ZlibCompressor as _,
            &ZstdCompressor as _,
        ])
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .record_size_limit(0x4001)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .key_shares(vec![
            KeyShare::X25519_MLKEM768,
            KeyShare::X25519,
            KeyShare::P256,
        ])
        .preserve_tls13_cipher_list(true)
        .aes_hw_override(true)
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
            ExtensionType::CERTIFICATE_TIMESTAMP,
            ExtensionType::KEY_SHARE,
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::PSK_KEY_EXCHANGE_MODES,
            ExtensionType::RECORD_SIZE_LIMIT,
            ExtensionType::CERT_COMPRESSION,
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
            ExtensionType::PADDING,
        ])
        .build()
}

fn http1_options_template() -> Http1Options {
    // HTTP/1 options config
    Http1Options::builder()
        .allow_obsolete_multiline_headers_in_responses(true)
        .max_headers(100)
        .build()
}

fn http2_options_template() -> Http2Options {
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
}

fn emulation_template() -> Emulation {
    // This provider encapsulates TLS, HTTP/1, HTTP/2
    Emulation::builder()
        .tls_options(tls_options_template())
        .http1_options(http1_options_template())
        .http2_options(http2_options_template())
        .build(Default::default())
}

#[tokio::test]
async fn test_emulation() -> wreq::Result<()> {
    let client = Client::builder()
        .emulation(emulation_template())
        .connect_timeout(Duration::from_secs(10))
        .tls_cert_verification(false)
        .build()?;

    let text = client
        .get("https://tls.browserleaks.com/")
        .send()
        .await?
        .text()
        .await?;

    assert!(
        text.contains("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
        "Response ja4_hash fingerprint not found: {text}"
    );
    assert!(
        text.contains("6ea73faa8fc5aac76bded7bd238f6433"),
        "Response akamai_hash fingerprint not found: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn test_request_with_emulation() -> wreq::Result<()> {
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .tls_cert_verification(false)
        .build()?;

    let text = client
        .get("https://tls.browserleaks.com/")
        .emulation(emulation_template())
        .send()
        .await?
        .text()
        .await?;

    assert!(
        text.contains("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
        "Response ja4_hash fingerprint not found: {text}"
    );
    assert!(
        text.contains("6ea73faa8fc5aac76bded7bd238f6433"),
        "Response akamai_hash fingerprint not found: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn test_request_with_emulation_tls() -> wreq::Result<()> {
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .tls_cert_verification(false)
        .build()?;

    let emulation = Emulation::builder()
        .tls_options(tls_options_template())
        .build(Default::default());

    let text = client
        .get("https://tls.browserleaks.com/")
        .emulation(emulation)
        .send()
        .await?
        .text()
        .await?;

    assert!(
        text.contains("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
        "Response ja4_hash fingerprint not found: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn test_request_with_emulation_http2() -> wreq::Result<()> {
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .tls_cert_verification(false)
        .build()?;

    let emulation = Emulation::builder()
        .http2_options(http2_options_template())
        .build(Default::default());

    let text = client
        .get("https://tls.browserleaks.com/")
        .emulation(emulation)
        .send()
        .await?
        .text()
        .await?;

    assert!(
        text.contains("6ea73faa8fc5aac76bded7bd238f6433"),
        "Response akamai_hash fingerprint not found: {text}"
    );

    Ok(())
}
