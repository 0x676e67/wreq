use rquest::{tls::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome130
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .async_build()
        .await?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the proxy
    {
        let proxy = rquest::Proxy::all("socks5h://127.0.0.1:1080")?;
        client.set_proxies(&[proxy]);

        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    Ok(())
}
