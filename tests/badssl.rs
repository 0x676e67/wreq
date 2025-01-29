use rquest::{join, SslCurve, TlsConfig};
use rquest::{Client, HttpContext};

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
        .danger_accept_invalid_certs(true)
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
        .impersonate(
            HttpContext::builder()
                .tls_config(
                    TlsConfig::builder()
                        .curves(CURVES)
                        .cipher_list(join!(
                            ":",
                            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
                        ))
                        .build(),
                )
                .build(),
        )
        .danger_accept_invalid_certs(true)
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
        .impersonate(
            HttpContext::builder()
                .tls_config(
                    TlsConfig::builder()
                        .curves(CURVES)
                        .cipher_list(join!(
                            ":",
                            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
                        ))
                        .build(),
                )
                .build(),
        )
        .danger_accept_invalid_certs(true)
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
