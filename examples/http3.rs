use std::time::Duration;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let client = wreq::Client::builder_tokio()
        .http3_only()
        .timeout(Duration::from_secs(10))
        .build()?;

    let response = client
        .get("https://pingly.us.kg/api/tls")
        .header("User-Agent", env!("CARGO_PKG_NAME"))
        .send()
        .await?;
    println!(
        "{:?}\n{}\n{}",
        response.version(),
        response.status(),
        response.text().await?
    );
    Ok(())
}
