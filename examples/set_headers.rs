use http::{HeaderValue, header};

#[tokio::main]
async fn main() -> rquest::Result<()> {
    // Build a client
    let client = rquest::Client::new();

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Set a header
    client.update().headers(update_headers).apply()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}

fn update_headers(headers: &mut http::HeaderMap) {
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
}
