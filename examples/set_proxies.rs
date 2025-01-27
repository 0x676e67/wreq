use rquest::{Client, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Chrome130
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the proxies
    {
        let proxy = rquest::Proxy::all("socks5h://abc:123@127.0.0.1:6153")?;
        client.as_mut().proxies(vec![proxy]);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // Clear the proxies
    {
        client.as_mut().proxies(None);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    Ok(())
}
