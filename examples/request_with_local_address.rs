use std::net::IpAddr;

use wreq::redirect::Policy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Use the API you're already familiar with
    let resp = wreq::get("http://www.baidu.com")
        .redirect(Policy::default())
        .local_address(IpAddr::from([192, 168, 1, 226]))
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
