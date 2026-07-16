use std::time::Duration;

use wreq::Client;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Reset connections on close rather than closing them gracefully.
    let client = Client::builder().tcp_linger(Duration::ZERO).build()?;

    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Non-zero duration waits for unsent data to be flushed.
    let client = Client::builder()
        .tcp_linger(Duration::from_secs(5))
        .build()?;

    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
