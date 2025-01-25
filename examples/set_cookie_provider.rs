use http::HeaderValue;
use rquest::cookie::Jar;
use rquest::Impersonate;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    
    // Build a client to impersonate Chrome131
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set cookie provider
    client.as_mut().cookie_provider(Arc::new(Jar::default()));

    // Set a cookie
    client.set_cookies(
        &url,
        vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
    );

    // Use the API you're already familiar with
    let resp = client.get(url).send().await?.text().await?;
    println!("{}", resp);

    Ok(())
}
