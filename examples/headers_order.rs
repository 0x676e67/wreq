use http::{header, HeaderName, HeaderValue};
use rquest::tls::Impersonate;

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::CONTENT_LENGTH,
    header::HOST,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .headers_order(HEADER_ORDER)
        .cookie_store(true)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set a cookie
    client.set_cookies(
        &url,
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
    );

    // Use the API you're already familiar with
    let resp = client
        .post(url)
        .with_host_header()
        .body("hello")
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
