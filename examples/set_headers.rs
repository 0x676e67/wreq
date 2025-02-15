use http::{header, HeaderValue};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to emulation Chrome133
    let client = rquest::Client::builder().build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Set a header
    client.as_mut().headers(update_headers).apply()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}

fn update_headers(headers: &mut http::HeaderMap) {
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
}
