use std::time::Duration;

use wreq::{
    Client, Extension,
    tls::{CertStore, TlsInfo},
};

/// Certificate Store Example
///
/// In most cases, you don't need to manually configure certificate stores. wreq automatically
/// uses appropriate default certificates:
/// - With `webpki-roots` feature enabled: Uses Mozilla's maintained root certificate collection
/// - Without this feature: Uses system default certificate store paths
///
/// Manual certificate store configuration is only needed in the following special cases:
///
/// ## Scenarios requiring custom certificate store:
///
/// ### 1. Self-signed Certificates
/// - Connect to internal services using self-signed certificates
/// - Test servers in development environments
///
/// ### 2. Enterprise Internal CA
/// - Add root certificates from enterprise internal certificate authorities
/// - Access HTTPS services on corporate intranets
///
/// ### 3. Certificate Updates and Management
/// - Dynamically update certificates in the certificate store
/// - Remove revoked or expired certificates
///
/// ### 4. Compliance Requirements
/// - Special compliance requirements for certain industries or regions
/// - Need to use specific certificate collections
///
/// ### 5. Performance Optimization
/// - Reduce certificate store size to improve TLS handshake performance
/// - Include only necessary root certificates
#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Create a client with a custom certificate store using webpki-roots
    let client = Client::builder()
        .cert_store(CertStore::from_der_certs(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS,
        )?)
        .build()?;

    // Use the API you're already familiar with
    client.get("https://www.google.com").send().await?;

    // Self-signed certificate Client
    // Skip certificate verification for self-signed certificates
    let client = Client::builder()
        .tls_info(true)
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://self-signed.badssl.com/").send().await?;
    if let Some(Extension(tls_info)) = resp.extension::<TlsInfo>() {
        if let Some(peer_cert_der) = tls_info.peer_certificate() {
            // Create self-signed certificate Store
            let self_signed_store = CertStore::from_der_certs(&[peer_cert_der])?;

            // Create a client with self-signed certificate store
            let client = Client::builder()
                .cert_store(self_signed_store)
                .connect_timeout(Duration::from_secs(10))
                .build()?;

            // Use the API you're already familiar with
            let resp = client.get("https://self-signed.badssl.com/").send().await?;
            println!("{}", resp.text().await?);
        }
    }

    Ok(())
}
