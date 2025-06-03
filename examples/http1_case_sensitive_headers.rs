use http::Version;
use wreq::OriginalHeaders;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Create a request with a case-sensitive header
    let mut original_headers = OriginalHeaders::new();
    original_headers.insert("X-custom-header");
    original_headers.insert("Host");

    let resp = wreq::Client::new()
        .get("https://tls.peet.ws/api/all")
        .header("X-Custom-Header", "value")
        .original_headers(original_headers)
        .version(Version::HTTP_11)
        .send()
        .await?
        .text()
        .await?;

    println!("{}", resp);

    Ok(())
}
