use rquest::{Client, Emulation};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to emulation Chrome133
    let client = Client::builder().emulation(Emulation::Chrome133).build()?;

    // Change the emulation to Safari18
    client.as_mut().emulation(Emulation::Safari18).apply()?;
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
