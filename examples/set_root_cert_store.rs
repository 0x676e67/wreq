use rquest::Client;
use rquest::{Error, X509Store, X509StoreBuilder, X509};
use std::sync::LazyLock;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    use_static_root_certs().await?;
    use_dynamic_root_certs().await?;
    Ok(())
}

/// Loads statically the root certificates from the webpki certificate store.
fn load_static_root_certs() -> Option<&'static X509Store> {
    static CERT_STORE: LazyLock<Result<X509Store, Error>> = LazyLock::new(|| {
        let mut cert_store = X509StoreBuilder::new()?;
        for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            let cert = X509::from_der(&*cert)?;
            cert_store.add_cert(cert)?;
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

/// Loads dynamically the root certificates from the native certificate store.
fn load_dynamic_root_certs() -> Result<X509Store, Error> {
    let mut cert_store = X509StoreBuilder::new()?;
    for cert in rustls_native_certs::load_native_certs().certs {
        let cert = X509::from_der(&cert)?;
        cert_store.add_cert(cert)?;
    }
    log::info!("Loaded dynamic root certs");
    Ok(cert_store.build())
}

async fn use_static_root_certs() -> Result<(), rquest::Error> {
    let client = Client::builder()
        .root_cert_store(load_static_root_certs)
        .build()?;

    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}

async fn use_dynamic_root_certs() -> Result<(), rquest::Error> {
    let client = Client::builder()
        .root_cert_store(load_dynamic_root_certs()?)
        .build()?;

    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
