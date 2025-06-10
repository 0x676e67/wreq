use wreq::{Client, Proxy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let resp = Client::new()
        .get("https://api.ipify.org?format=json")
        .proxy(Proxy::all("socks5h://localhost:6153")?)
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
