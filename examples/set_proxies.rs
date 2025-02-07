use rquest::{Client, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Chrome130
    let client = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .no_proxy()
        .build()?;

    // Set the proxies
    let proxy = rquest::Proxy::all("socks5h://127.0.0.1:6153")?;
    client.as_mut().proxies(vec![proxy]).apply()?;
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Unset the proxies
    client.as_mut().unset_proxies().apply()?;
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
