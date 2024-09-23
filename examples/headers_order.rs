use http::{header, HeaderName};
use rquest::tls::Impersonate;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome129
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .headers_order(vec![
            header::USER_AGENT,
            header::HOST,
            HeaderName::from_static("priority"),
            header::COOKIE,
        ])
        .build()?;

    // Use the API you're already familiar with
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .header("cookie", "cookiec=1")
        .header(header::HOST, "tls.peet.ws")
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
