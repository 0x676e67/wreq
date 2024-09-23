use rquest::{tls::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a client to mimic Chrome129
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let client = Client::builder()
        .impersonate(Impersonate::Chrome129)
        .interface("eth0")
        .build()?;

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    let client = Client::builder()
        .impersonate(Impersonate::Chrome126)
        .enable_ech_grease()
        .permute_extensions()
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
