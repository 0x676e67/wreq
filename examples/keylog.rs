use wreq::tls::KeyLog;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Build a client
    let client = wreq::Client::builder()
        .keylog(KeyLog::from_file("keylog.txt"))
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://www.google.com").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
