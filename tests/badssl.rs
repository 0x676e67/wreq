use std::time::Duration;

use wreq::{
    Client, Extension,
    tls::{AlpsProtocol, CertStore, TlsInfo, TlsOptions, TlsVersion},
};

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

#[tokio::test]
async fn test_badssl_modern() {
    let text = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(360))
        .build()
        .unwrap()
        .get("https://mozilla-modern.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(!text.is_empty());
}

#[tokio::test]
async fn test_badssl_self_signed() {
    let text = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(360))
        .no_proxy()
        .build()
        .unwrap()
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(!text.is_empty());
}
const CURVES_LIST: &str = join!(
    ":",
    "X25519",
    "P-256",
    "P-384",
    "P-521",
    "ffdhe2048",
    "ffdhe3072"
);

#[tokio::test]
async fn test_3des_support() -> wreq::Result<()> {
    let tls_options = TlsOptions::builder()
        .cipher_list(join!(
            ":",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
        ))
        .curves_list(CURVES_LIST)
        .build();

    // Create a client with the TLS options
    let client = Client::builder()
        .emulation(tls_options)
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(360))
        .build()?;

    // Check if the client can connect to the 3des.badssl.com
    let content = client
        .get("https://3des.badssl.com/")
        .send()
        .await?
        .text()
        .await?;

    println!("3des.badssl.com is supported:\n{content}");

    Ok(())
}

#[tokio::test]
async fn test_firefox_7x_100_cipher() -> wreq::Result<()> {
    let tls_options = TlsOptions::builder()
        .cipher_list(join!(
            ":",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        ))
        .curves_list(CURVES_LIST)
        .build();

    // Create a client with the TLS options
    let client = Client::builder()
        .emulation(tls_options)
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(360))
        .build()?;

    // Check if the client can connect to the dh2048.badssl.com
    let content = client
        .get("https://dh2048.badssl.com/")
        .send()
        .await?
        .text()
        .await?;

    println!("dh2048.badssl.com is supported:\n{content}");

    Ok(())
}

#[tokio::test]
async fn test_alps_new_endpoint() -> wreq::Result<()> {
    let tls_options = TlsOptions::builder()
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .alps_protocols([AlpsProtocol::HTTP2])
        .alps_use_new_codepoint(true)
        .build();

    let client = Client::builder()
        .emulation(tls_options)
        .connect_timeout(Duration::from_secs(360))
        .build()?;

    let resp = client.get("https://www.google.com").send().await?;
    assert!(resp.status().is_success());
    Ok(())
}

#[tokio::test]
async fn test_aes_hw_override() -> wreq::Result<()> {
    const CIPHER_LIST: &str = join!(
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
    );

    let tls_options = TlsOptions::builder()
        .cipher_list(CIPHER_LIST)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .enable_ech_grease(true)
        .aes_hw_override(false)
        .preserve_tls13_cipher_list(true)
        .build();

    // Create a client with the TLS options
    let client = Client::builder()
        .emulation(tls_options)
        .connect_timeout(Duration::from_secs(360))
        .build()?;

    let resp = client.get("https://tls.browserleaks.com").send().await?;
    assert!(resp.status().is_success());
    let text = resp.text().await?;
    assert!(text.contains("ChaCha20Poly1305"));
    Ok(())
}

#[tokio::test]
async fn test_tls_self_signed_cert() {
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(360))
        .tls_info(true)
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap();

    let peer_cert_der = resp
        .extension::<TlsInfo>()
        .and_then(|Extension(info)| info.peer_certificate())
        .unwrap();

    let self_signed_cert_store = CertStore::builder()
        .add_der_cert(peer_cert_der)
        .build()
        .unwrap();

    let client = Client::builder()
        .cert_store(self_signed_cert_store)
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let res = client.get("https://www.google.com").send().await;
    assert!(res.is_err());
}
