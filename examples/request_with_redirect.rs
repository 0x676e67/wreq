use rquest::redirect::Policy;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let resp = rquest::Client::new()
        .get("http://google.com/")
        .redirect(Policy::default())
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
