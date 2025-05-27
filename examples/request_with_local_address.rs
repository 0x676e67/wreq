use rquest::redirect::Policy;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let resp = rquest::Client::new()
        .get("http://www.baidu.com")
        .redirect(Policy::default())
        .local_address(IpAddr::from([192, 168, 1, 226]))
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
