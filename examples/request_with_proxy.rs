#[tokio::main]
async fn main() -> rquest::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let resp = rquest::Client::new()
        .get("https://tls.peet.ws/api/all")
        .proxy("http://127.0.0.1:6152")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
