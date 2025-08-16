#[cfg(unix)]
#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Create a Unix socket proxy
    let proxy = wreq::Proxy::unix("/var/run/docker.sock")?;

    // Build a client
    let client = wreq::Client::builder()
        // Specify the Unix socket path
        .proxy(proxy.clone())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Use the API you're already familiar with
    let resp = client
        .get("http://localhost/v1.41/containers/json")
        .send()
        .await?;
    println!("{}", resp.text().await?);

    // Or specify the Unix socket directly in the request
    let resp = client
        .get("http://localhost/v1.41/containers/json")
        .proxy(proxy)
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}

#[cfg(not(unix))]
fn main() {}
