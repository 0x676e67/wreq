use boring::{
    error::ErrorStack,
    x509::{
        store::{X509Store, X509StoreBuilder, X509StoreRef},
        X509,
    },
};
use rquest::tls::Impersonate;
use std::sync::LazyLock;

/// Loads the CA certificates from the native certificate store.
fn load_ca_certs() -> Option<&'static X509StoreRef> {
    static CERT_STORE: LazyLock<Result<X509Store, ErrorStack>> = LazyLock::new(|| {
        let mut cert_store = X509StoreBuilder::new()?;
        for cert in rustls_native_certs::load_native_certs().certs {
            let cert = X509::from_der(&*cert)?;
            cert_store.add_cert(cert)?;
        }
        Ok(cert_store.build())
    });

    match CERT_STORE.as_ref() {
        Ok(cert_store) => {
            log::info!("Loaded CA certs");
            Some(cert_store)
        }
        Err(err) => {
            log::error!("Failed to load CA certs: {:?}", err);
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Build a client to mimic Edge127
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Edge127)
        .ca_cert_store(load_ca_certs)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
