use rquest::tls::Impersonate;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome128
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome128)
        .enable_ech_grease()
        .build()?;

    // Use the API you're already familiar with
    let _ = client.get("https://tls.peet.ws/api/all").send().await?;

    // Now, let's impersonate a PSK
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
