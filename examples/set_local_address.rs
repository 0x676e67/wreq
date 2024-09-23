use rquest::tls::Impersonate;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a client to mimic Chrome129
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    client.set_local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
