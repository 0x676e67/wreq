#![deny(warnings)]

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    // Make sure you are running tor and this is your socks port
    let proxy = wreq::Proxy::all("socks5h://127.0.0.1:9050").expect("tor proxy should be there");
    let client = wreq::Client::builder()
        .proxy(proxy)
        .build()
        .expect("should be able to build wreq client");

    let res = client.get("https://check.torproject.org").send().await?;
    println!("Status: {}", res.status());

    let text = res.text().await?;
    let is_tor = text.contains("Congratulations. This emulation is configured to use Tor.");
    println!("Is Tor: {}", is_tor);
    assert!(is_tor);

    Ok(())
}
