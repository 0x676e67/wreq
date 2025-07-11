use wreq::Client;

#[tokio::main]
async fn main() -> Result<(), wreq::Error> {
    // Build a client to emulation Firefox136
    let client = Client::builder()
        .gzip(true)
        .brotli(false)
        .zstd(false)
        .deflate(false)
        .build()?;

    // Use the API you're already familiar with
    let respnose = client
        .get("https://httpbin.org/brotli")
        .header("Accept-Encoding", "gzip,br,zstd,deflate")
        .send()
        .await?;

    dbg!(&respnose.headers());

    println!("{}", respnose.text().await?);

    Ok(())
}
