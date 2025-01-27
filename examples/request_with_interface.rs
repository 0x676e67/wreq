use rquest::{Client, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Firefox128
    let client = Client::builder()
        .impersonate(Impersonate::Firefox128)
        .build()?;

    let text = client
        .get("https://api.ip.sb/ip")
        .interface("utun4")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
