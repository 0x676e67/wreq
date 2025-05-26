use http::{HeaderMap, HeaderName, HeaderValue, header};
use rquest::http2::{Http2Config, PseudoId, PseudoOrder};
use rquest::tls::{AlpnProtos, TlsConfig, TlsVersion};
use rquest::{Client, EmulationProvider};

// ============== TLS Extension Algorithms ==============

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

const CURVES_LIST: &str = join!(":", "X25519", "P-256", "P-384");

const CIPHER_LIST: &str = join!(
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
);

const SIGALGS_LIST: &str = join!(
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
);

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::COOKIE,
    header::HOST,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // TLS config
    let tls = TlsConfig::builder()
        .curves_list(CURVES_LIST)
        .cipher_list(CIPHER_LIST)
        .sigalgs_list(SIGALGS_LIST)
        .alpn_protos(AlpnProtos::ALL)
        .enable_ocsp_stapling(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build();

    // HTTP/2 config
    let http2 = Http2Config::builder()
        .initial_stream_id(3)
        .initial_stream_window_size(16777216)
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
        headers
    };

    // Create an emulation context
    let context = EmulationProvider::builder()
        .tls_config(tls)
        .http2_config(http2)
        .default_headers(headers)
        .headers_order(HEADER_ORDER)
        .build();

    // Build a client with emulation config
    let client = Client::builder()
        .emulation(context)
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
