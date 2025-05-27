use std::net::IpAddr;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    // Build a client
    let client = rquest::Client::new();

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the local address to `172.200.10.2`
    client
        .update()
        .local_address(IpAddr::from([172, 200, 10, 2]))
        .apply()?;

    // Use the API you're already familiar with
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
