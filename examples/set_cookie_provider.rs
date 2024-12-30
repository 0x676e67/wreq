use http::HeaderValue;
use rquest::cookie::Jar;
use rquest::tls::Impersonate;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set cookie provider
    client.set_cookie_provider(Arc::new(Jar::default()));

    // Set a cookie
    client.set_cookies(
        &url,
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
    );

    // Use the API you're already familiar with
    let resp = client.get(url).send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
