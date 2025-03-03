#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = rquest::Client::builder().build()?;

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
