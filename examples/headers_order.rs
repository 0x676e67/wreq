use http::{header, HeaderName, HeaderValue};
use rquest::Impersonate;

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::CONTENT_LENGTH,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to impersonate Chrome133
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome133)
        .headers_order(HEADER_ORDER)
        .cookie_store(true)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set a cookie
    client.as_ref().set_cookies(
        &url,
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
    );

    // Use the API you're already familiar with
    let resp = client.post(url).body("hello").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
