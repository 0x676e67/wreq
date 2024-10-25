use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome130
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome130)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    let proxy = rquest::Proxy::all("socks5h://127.0.0.1:1080")?;
    client.set_proxies(&[proxy]);

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
