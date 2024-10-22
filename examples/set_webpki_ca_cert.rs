use boring::x509::{store::X509StoreBuilder, X509};
use rquest::tls::Impersonate;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Edge127
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Edge127)
        .ca_cert_store(|| {
            let mut verify_store = X509StoreBuilder::new()?;
            for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                let x509 = X509::from_der(cert)?;
                verify_store.add_cert(x509)?;
            }
            Ok(verify_store.build())
        })
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
