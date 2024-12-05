use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Change the impersonate to Safari18
    client.set_impersonate(Impersonate::Safari18)?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Change the impersonate to Chrome131 without setting the headers
    client.set_impersonate_without_headers(Impersonate::Edge127)?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
