use std::sync::LazyLock;

use wreq::{Client, tls::CertStore};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    use_static_root_certs().await?;
    use_dynamic_root_certs().await?;
    use_system_root_certs().await?;
    Ok(())
}

/// Loads the system root certificates.
fn load_system_root_certs() -> CertStore {
    static STORE: LazyLock<CertStore> = LazyLock::new(|| {
        CertStore::builder()
            .set_default_paths()
            .build()
            .expect("Failed to load system root certs")
    });

    STORE.clone()
}

/// Loads statically the root certificates from the webpki certificate store.
fn load_static_root_certs() -> CertStore {
    static STORE: LazyLock<CertStore> = LazyLock::new(|| {
        CertStore::from_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS)
            .expect("Failed to load static root certs")
    });

    STORE.clone()
}

/// Loads dynamically the root certificates from the native certificate store.
fn load_dynamic_root_certs() -> CertStore {
    CertStore::from_der_certs(&rustls_native_certs::load_native_certs().certs)
        .expect("Failed to load dynamic root certs")
}

async fn use_static_root_certs() -> wreq::Result<()> {
    let client = Client::builder()
        .cert_store(load_static_root_certs())
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

async fn use_dynamic_root_certs() -> wreq::Result<()> {
    let client = Client::builder()
        .cert_store(load_dynamic_root_certs())
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

async fn use_system_root_certs() -> wreq::Result<()> {
    let client = Client::builder()
        .cert_store(load_system_root_certs())
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
