use http::{HeaderMap, HeaderName, HeaderValue};
use wreq::{Client, header::OrigHeaderMap};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let client = Client::builder()
        .cert_verification(false)
        .http1_only()
        .build()?;

    // Create a request with a case-sensitive header
    let mut orig_headers = OrigHeaderMap::new();
    orig_headers.insert("Host");
    orig_headers.insert("X-custom-Header1");
    orig_headers.insert("x-Custom-Header2");
    orig_headers.insert(HeaderName::from_static("x-custom-header3"));

    // Use the API you're already familiar with
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .orig_headers(orig_headers)
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
