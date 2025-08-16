#[cfg(unix)]
#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Build a client
    let client = wreq::Client::builder()
        // Specify the Unix socket path
        .unix_socket("/var/run/docker.sock")
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
        .unix_socket("/var/run/docker.sock")
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
