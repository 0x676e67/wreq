use rquest::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Firefox133
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Firefox133)
        .build()?;

    // Use the API you're already familiar with
    let _ = client.get("https://tls.peet.ws/api/all").send().await?;

    // Now, let's impersonate a PSK
    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
