//! Example application using `wreq` through a small local integration boundary.

#[path = "support/wreq_client.rs"]
mod wreq_client;

use wreq_client::HttpClient;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let client = HttpClient::new()?;
    let body = client.get_text("https://www.rust-lang.org").await?;

    println!("received {} bytes", body.len());
    Ok(())
}
