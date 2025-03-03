use http::HeaderValue;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = rquest::Client::builder().cookie_store(true).build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set a cookie
    client.set_cookies(&url, [HeaderValue::from_static("foo=bar")]);

    // Use the API you're already familiar with
    let resp = client.get(url).send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
