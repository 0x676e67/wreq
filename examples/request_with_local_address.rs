use wreq::redirect::Policy;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = wreq::Client::new();

    let resp = client
        .get("http://www.baidu.com")
        .redirect(Policy::default())
        .local_address(IpAddr::from([192, 168, 1, 226]))
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
