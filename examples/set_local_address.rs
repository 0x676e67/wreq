use rquest::Impersonate;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to impersonate Chrome130
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome130)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    client
        .as_mut()
        .local_address(IpAddr::from([172, 200, 10, 2]));

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
