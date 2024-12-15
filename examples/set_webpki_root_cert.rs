use boring::{
    error::ErrorStack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};
use rquest::{tls::Impersonate, Client};
use std::sync::LazyLock;

/// Loads the root certificates from the WebPKI certificate store.
fn load_root_certs() -> Option<&'static X509Store> {
    static CERT_STORE: LazyLock<Result<X509Store, ErrorStack>> = LazyLock::new(|| {
        let mut cert_store = X509StoreBuilder::new()?;
        for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            let x509 = X509::from_der(cert)?;
            cert_store.add_cert(x509)?;
        }
        Ok(cert_store.build())
    });

    match CERT_STORE.as_ref() {
        Ok(cert_store) => {
            log::info!("Loaded root certs");
            Some(cert_store)
        }
        Err(err) => {
            log::error!("Failed to load root certs: {:?}", err);
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to mimic Edge127
    let client = Client::builder()
        .impersonate(Impersonate::Edge127)
        .root_certs_store(load_root_certs)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
