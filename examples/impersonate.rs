use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let client1 = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Build a client to mimic Safari18
    let client2 = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;

    let resp = client1.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    let resp = client2.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
