use rquest::{AlpsProtos, Client, EmulationProvider, TlsInfo, TlsVersion};
use rquest::{SslCurve, TlsConfig};

#[tokio::test]
async fn test_badssl_modern() {
    let text = rquest::Client::builder()
        .no_proxy()
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
    let text = rquest::Client::builder()
        .cert_verification(false)
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

const CURVES: &[SslCurve] = &[
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
    SslCurve::FFDHE2048,
    SslCurve::FFDHE3072,
];

#[tokio::test]
async fn test_3des_support() -> Result<(), rquest::Error> {
    let client = Client::builder()
        .emulation(
            EmulationProvider::builder()
                .tls_config(
                    TlsConfig::builder()
                        .curves(CURVES)
                        .cipher_list("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")
                        .build(),
                )
                .build(),
        )
        .cert_verification(false)
        .build()?;

    // Check if the client can connect to the 3des.badssl.com
    let content = client
        .get("https://3des.badssl.com/")
        .send()
        .await?
        .text()
        .await?;

    println!("3des.badssl.com is supported:\n{}", content);

    Ok(())
}

#[tokio::test]
async fn test_firefox_7x_100_cipher() -> Result<(), rquest::Error> {
    let client = Client::builder()
        .emulation(
            EmulationProvider::builder()
                .tls_config(
                    TlsConfig::builder()
                        .curves(CURVES)
                        .cipher_list("TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")
                        .build(),
                )
                .build(),
        )
        .cert_verification(false)
        .build()?;

    // Check if the client can connect to the dh2048.badssl.com
    let content = client
        .get("https://dh2048.badssl.com/")
        .send()
        .await?
        .text()
        .await?;

    println!("dh2048.badssl.com is supported:\n{}", content);

    Ok(())
}

#[tokio::test]
async fn test_alps_new_endpoint() -> Result<(), rquest::Error> {
    let client = rquest::Client::builder()
        .emulation(
            EmulationProvider::builder()
                .tls_config(
                    TlsConfig::builder()
                        .min_tls_version(TlsVersion::TLS_1_2)
                        .max_tls_version(TlsVersion::TLS_1_3)
                        .alps_protos(AlpsProtos::HTTP2)
                        .alps_use_new_codepoint(true)
                        .build(),
                )
                .build(),
        )
        .build()?;

    let resp = client.get("https://www.google.com").send().await?;
    assert!(resp.status().is_success());
    Ok(())
}

#[tokio::test]
async fn test_aes_hw_override() -> Result<(), rquest::Error> {
    macro_rules! join {
        ($sep:expr, $first:expr $(, $rest:expr)*) => {
            concat!($first $(, $sep, $rest)*)
        };
    }

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

    let client = rquest::Client::builder()
        .emulation(
            EmulationProvider::builder()
                .tls_config(
                    TlsConfig::builder()
                        .cipher_list(CIPHER_LIST)
                        .min_tls_version(TlsVersion::TLS_1_2)
                        .max_tls_version(TlsVersion::TLS_1_3)
                        .enable_ech_grease(true)
                        .aes_hw_override(false)
                        .build(),
                )
                .build(),
        )
        .build()?;

    let resp = client.get("https://tls.browserleaks.com").send().await?;
    assert!(resp.status().is_success());
    let text = resp.text().await?;
    assert!(text.contains("ChaCha20Poly1305"));

    client
        .update()
        .emulation(
            EmulationProvider::builder()
                .tls_config(
                    TlsConfig::builder()
                        .cipher_list(CIPHER_LIST)
                        .min_tls_version(TlsVersion::TLS_1_2)
                        .max_tls_version(TlsVersion::TLS_1_3)
                        .enable_ech_grease(true)
                        .aes_hw_override(true)
                        .build(),
                )
                .build(),
        )
        .apply()?;

    let resp = client.get("https://tls.browserleaks.com").send().await?;
    assert!(resp.status().is_success());
    let text = resp.text().await?;
    assert!(!text.contains("ChaCha20Poly1305"));
    Ok(())
}

#[tokio::test]
async fn ssl_pinning() {
    let client = rquest::Client::builder()
        .cert_verification(false)
        .tls_info(true)
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap();

    let peer_cert_der = resp
        .extensions()
        .get::<TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .unwrap();

    let peer_cert = boring2::x509::X509::from_der(peer_cert_der)
        .unwrap()
        .to_pem()
        .unwrap();

    let client = rquest::Client::builder()
        .ssl_pinning([peer_cert])
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
