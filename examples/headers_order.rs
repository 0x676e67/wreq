use http::{HeaderName, HeaderValue, header};

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::CONTENT_LENGTH,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    // Build a client
    let client = wreq::Client::builder()
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
