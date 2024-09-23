use rquest::tls::Impersonate;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome129 with headers
    let client = rquest::Client::builder()
        .impersonate_with_headers(Impersonate::Chrome129, false)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
