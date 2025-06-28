use http::{HeaderName, Version};
use wreq::OriginalHeaders;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Create a request with a case-sensitive header
    let mut original_headers = OriginalHeaders::new();
    original_headers.insert("Host");
    original_headers.insert("X-custom-Header1");
    original_headers.extend(["x-Custom-Header2"]);
    original_headers.insert(HeaderName::from_static("x-custom-header3"));

    let resp = wreq::Client::new()
        .get("https://tls.peet.ws/api/all")
        .header("X-custom-Header1", "value1")
        .header("x-Custom-Header2", "value2")
        .header("x-custom-header3", "value3")
        .original_headers(original_headers)
        .version(Version::HTTP_11)
        .send()
        .await?
        .text()
        .await?;

    println!("{resp}");

    Ok(())
}
