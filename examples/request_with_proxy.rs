use wreq::{Client, Proxy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Use the API you're already familiar with
    let resp = Client::new()
        .get("https://api.ip.sb/ip")
        .proxy(Proxy::all("socks5h://localhost:6153")?)
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
