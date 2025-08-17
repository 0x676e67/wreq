use wreq::redirect::Policy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Use the API you're already familiar with
    let resp = wreq::get("http://google.com/")
        .redirect(Policy::default())
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
