use rquest::{
    Url,
    cookie::Jar,
    header::{self, HeaderName},
};
use std::sync::Arc;

const HEADER_ORDER: &[HeaderName] = &[
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::CONTENT_LENGTH,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> rquest::Result<()> {
    // Create a cookie jar
    let jar = Arc::new(Jar::default());

    // Build a client
    let client = rquest::Client::builder()
        .headers_order(HEADER_ORDER)
        .cookie_provider(jar.clone())
        .build()?;

    // Build url
    let url = Url::parse("https://tls.peet.ws/api/all").unwrap();

    // Set a cookie
    jar.add_cookie_str("foo=bar", &url);

    // Use the API you're already familiar with
    let resp = client.post(url).body("hello").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
