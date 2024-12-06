use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    let now = std::time::Instant::now();
    // Build a client to mimic Chrome131
    let _client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;
    println!("{:?}", now.elapsed());

    let now = std::time::Instant::now();
    // Build a client to mimic Chrome131
    let _client2 = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;
    println!("{:?}", now.elapsed());

    let resp = _client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    let resp = _client2.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
