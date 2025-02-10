use http::HeaderValue;
use rquest::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to impersonate Chrome133
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome133)
        .cookie_store(true)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set a cookie
    client.as_ref().set_cookies(
        &url,
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
    );

    // Get cookies
    let cookies = client.as_ref().get_cookies(&url);
    println!("{:?}", cookies);

    // Use the API you're already familiar with
    let resp = client.get(url).send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
