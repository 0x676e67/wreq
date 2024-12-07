#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The first creation will cache the certificate storage, of course it will take some time
    let _ = rquest::Client::builder()
        .impersonate(rquest::tls::Impersonate::Chrome100)
        .build()?;

    let now = tokio::time::Instant::now();
    for _ in 0..50 {
        let _ = rquest::Client::builder()
            .impersonate(rquest::tls::Impersonate::Chrome131)
            .build()?;
    }
    println!("create rquest client1 avg time: {:?}", now.elapsed());

    let now = tokio::time::Instant::now();
    for _ in 0..50 {
        let _ = reqwest::Client::builder().build()?;
    }
    println!("create reqwest client2 avg time: {:?}", now.elapsed());

    Ok(())
}
