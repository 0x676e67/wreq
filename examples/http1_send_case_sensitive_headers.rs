use http::{HeaderMap, HeaderName, HeaderValue};
use wreq::OriginalHeaders;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let client = wreq::Client::builder()
        .cert_verification(false)
        .http1_only()
        .build()?;

    // Create a request with a case-sensitive header
    let mut original_headers = OriginalHeaders::new();
    original_headers.insert("Host");
    original_headers.insert("X-custom-Header1");
    original_headers.extend(["x-Custom-Header2"]);
    original_headers.insert(HeaderName::from_static("x-custom-header3"));

    // Use the API you're already familiar with
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .original_headers(original_headers)
        .headers({
            let mut headers = HeaderMap::new();
            headers.insert("x-custom-header1", HeaderValue::from_static("value1"));
            headers.insert("x-custom-header2", HeaderValue::from_static("value2"));
            headers.insert("x-custom-header3", HeaderValue::from_static("value3"));
            headers
        })
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
