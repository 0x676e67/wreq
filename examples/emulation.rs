use rquest::Emulation;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to emulation Chrome133
    let client = rquest::Client::builder()
        .emulation(Emulation::Chrome133)
        .build()?;

    // Use the API you're already familiar with
    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
