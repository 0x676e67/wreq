#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = rquest::Client::builder().tls_info(true).build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    if let Some(val) = resp.extensions().get::<rquest::tls::TlsInfo>() {
        if let Some(peer_cert_der) = val.peer_certificate() {
            assert!(!peer_cert_der.is_empty());
        }
    }

    Ok(())
}
