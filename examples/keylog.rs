use rquest::tls::KeyLogPolicy;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    // Build a client
    let client = rquest::Client::builder()
        .keylog(KeyLogPolicy::File("keylog.txt".into()))
        .cert_verification(false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
