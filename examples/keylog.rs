use wreq::tls::KeyLog;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Build a client
    let client = wreq::Client::builder()
        .tls_keylog(KeyLog::from_file("keylog.txt"))
        .tls_cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://yande.re/post.json").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
