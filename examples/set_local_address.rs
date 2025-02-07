use rquest::Impersonate;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to impersonate Chrome130
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome130)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the local address to `172.200.10.2`
    client
        .as_mut()
        .local_address(IpAddr::from([172, 200, 10, 2]))
        .apply()?;

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
