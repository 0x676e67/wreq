use rquest::Client;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = Client::builder().no_proxy().build()?;

    // Set the proxies
    let proxy = rquest::Proxy::all("socks5h://127.0.0.1:6153")?;
    client.update().proxies(vec![proxy]).apply()?;
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Unset the proxies
    client.update().unset_proxies().apply()?;
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
