use wreq::{Client, OriginalHeaders, http1::Http1Options};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Enable case-sensitive header handling in HTTP/1
    let http1_options = Http1Options::builder()
        .preserve_header_case(true)
        .http09_responses(true)
        .max_headers(100)
        .build();

    // Create a client with the HTTP/1 options
    let client = Client::builder()
        .emulation(http1_options)
        .http1_only()
        .build()?;

    // Use the API you're already familiar with
    let resp = client.post("https://httpbin.org").send().await?;
    if let Some(original) = resp.extensions().get::<OriginalHeaders>() {
        for (name, raw_name) in original.iter() {
            println!(
                "Header: {} (original: {})",
                name,
                String::from_utf8_lossy(raw_name)
            );
        }
    }
    Ok(())
}
