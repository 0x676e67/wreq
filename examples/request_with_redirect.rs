use wreq::redirect::Policy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let resp = wreq::Client::new()
        .get("http://google.com/")
        .redirect(Policy::none())
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
