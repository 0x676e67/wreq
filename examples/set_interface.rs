use rquest::{tls::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome130
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let client = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .interface("eth0")
        .build()?;

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    let client = Client::builder()
        .impersonate(Impersonate::Chrome126)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
