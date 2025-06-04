use wreq::{Client, Proxy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let resp = Client::new()
        .get("https://api.ipify.org?format=json")
        .proxy(Proxy::all("http://127.0.0.1:6152")?)
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
