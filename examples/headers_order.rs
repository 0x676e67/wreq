use http::{header, HeaderName};
use rquest::tls::Impersonate;

static HEADER_ORDER: [HeaderName; 6] = [
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::HOST,
    header::COOKIE,
    HeaderName::from_static("priority"),
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome130
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome130)
        .headers_order(&HEADER_ORDER)
        .build()?;

    // Use the API you're already familiar with
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .header(header::HOST, "tls.peet.ws")
        .header(header::COOKIE, "value1=1; value2=2")
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
