use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let now = tokio::time::Instant::now();
    let client1 = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;
    println!("create client1 time: {:?}", now.elapsed());

    // Build a client to mimic Chrome131
    let now = tokio::time::Instant::now();
    let client2 = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;
    println!("create client2 time: {:?}", now.elapsed());

    let resp = client1.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    let resp = client2.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
