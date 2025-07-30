use wreq::redirect::Policy;

#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = wreq::Client::new();

    let resp = client
        .get("http://google.com/")
        .redirect(Policy::default())
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
