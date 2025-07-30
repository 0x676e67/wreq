#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = wreq::Client::new();

    let resp = client
        .get("https://tls.peet.ws/api/all")
        .proxy("http://127.0.0.1:6152")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
