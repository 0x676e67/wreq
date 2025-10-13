use wreq::{
    Client, Emulation,
    header::{self, HeaderMap, HeaderValue, OrigHeaderMap},
    http2::{Http2Options, PseudoId, PseudoOrder},
    tls::{AlpnProtocol, TlsOptions, TlsVersion},
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
        .enable_ocsp_stapling(true)
        .curves_list(join!(":", "X25519", "P-256", "P-384"))
        .cipher_list(join!(
            ":",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        ))
        .sigalgs_list(join!(
            ":",
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1"
        ))
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build();

    // HTTP/2 options config
    let http2 = Http2Options::builder()
        .initial_stream_id(3)
        .initial_window_size(16777216)
        .initial_connection_window_size(16711681 + 65535)
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Method,
                    PseudoId::Path,
                    PseudoId::Authority,
                    PseudoId::Scheme,
                ])
                .build(),
        )
        .build();

    // Default headers
    let headers = {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("TwitterAndroid/10.89.0-release.0 (310890000-r-0) G011A/9 (google;G011A;google;G011A;0;;1;2016)"));
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en-US"));
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br, gzip, deflate"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("ct0=YOUR_CT0_VALUE;"),
        );
        headers
    };

    // The headers keep the original case and order
    let orig_headers = {
        let mut orig_headers = OrigHeaderMap::new();
        orig_headers.insert("cookie");
        orig_headers.insert("content-length");
        orig_headers.insert("User-Agent");
        orig_headers.insert("Accept-Language");
        orig_headers.insert("Accept-Encoding");
        orig_headers
    };

    // This provider encapsulates TLS, HTTP/1, HTTP/2, default headers, and original headers
    let emulation = Emulation::builder()
        .tls_options(tls)
        .http2_options(http2)
        .headers(headers)
        .orig_headers(orig_headers)
        .build();

    // Build a client with emulation config
    let client = Client::builder()
        .emulation(emulation)
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.browserleaks.com/").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
