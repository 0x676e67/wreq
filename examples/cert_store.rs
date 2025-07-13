use std::time::Duration;

use wreq::{
    Client,
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
/// ### 1. SSL Pinning (Certificate Pinning)
/// - To enhance security by pinning specific certificates or public keys
/// - Prevent man-in-the-middle attacks and maliciously issued CA certificates
///
/// ### 2. Self-signed Certificates
/// - Connect to internal services using self-signed certificates
/// - Test servers in development environments
///
/// ### 3. Enterprise Internal CA
/// - Add root certificates from enterprise internal certificate authorities
/// - Access HTTPS services on corporate intranets
///
/// ### 4. Certificate Updates and Management
/// - Dynamically update certificates in the certificate store
/// - Remove revoked or expired certificates
///
/// ### 5. Compliance Requirements
/// - Special compliance requirements for certain industries or regions
/// - Need to use specific certificate collections
///
/// ### 6. Performance Optimization
/// - Reduce certificate store size to improve TLS handshake performance
/// - Include only necessary root certificates
#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create a client with a custom certificate store using webpki-roots
    let client = Client::builder()
        .cert_store(CertStore::from_der_certs(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS,
        )?)
        .tls_info(true)
        .build()?;

    // Extract TLS peer certificate information
    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    if let Some(val) = resp.extensions().get::<TlsInfo>() {
        if let Some(peer_cert_der) = val.peer_certificate() {
            // Create a client with SSL pinning using the peer certificate
            let client = Client::builder()
                .ssl_pinning([peer_cert_der])
                .timeout(Duration::from_secs(10))
                .build()?;

            // Use the API you're already familiar with
            let resp = client.get("https://tls.peet.ws/api/all").send().await?;
            println!("{}", resp.text().await?);
        }
    }

    Ok(())
}
