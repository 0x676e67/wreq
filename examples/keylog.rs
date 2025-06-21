use wreq::tls::KeyLogPolicy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Build a client
    let client = wreq::Client::builder()
        .keylog(KeyLogPolicy::File("keylog.txt".into()))
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
