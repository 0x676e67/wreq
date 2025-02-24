use http::{header, HeaderName, HeaderValue};
use rquest::Emulation;

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::CONTENT_LENGTH,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to emulation Chrome133
    let client = rquest::Client::builder()
        .emulation(Emulation::Chrome133)
        .headers_order(HEADER_ORDER)
        .cookie_store(true)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set a cookie
    client.set_cookies(&url, [HeaderValue::from_static("foo=bar")]);

    // Use the API you're already familiar with
    let resp = client.post(url).body("hello").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
