use wreq::{OriginalHeaders, http1::Http1Config};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let client = wreq::Client::builder()
        .configure_http1(
            Http1Config::builder()
                .preserve_header_case(true)
                .http09_responses(true)
                .build(),
        )
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
