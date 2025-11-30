//! This example demonstrates tracking the compressed (wire) size of HTTP responses.
//!
//! The `compressed_size()` method on responses tracks the number of bytes received
//! over the wire before decompression. This is useful for monitoring bandwidth usage,
//! analyzing compression efficiency, or implementing data transfer quotas.

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Make a request to a server that returns gzipped content
    // httpbin.org/gzip returns a gzip-compressed response
    let resp = wreq::get("https://httpbin.org/gzip").send().await?;

    // Get the CompressedSize tracker from the response
    // This returns a cloneable handle that tracks bytes as they're read
    let compressed_size = resp.compressed_size();

    println!("Reading response body...");

    // Read the entire body - bytes are counted as they flow through
    let body = resp.bytes().await?;

    // Now we can see both the compressed and decompressed sizes
    println!("✓ Response received");
    println!("  Compressed (wire) size: {} bytes", compressed_size.get());
    println!("  Decompressed size:      {} bytes", body.len());

    if compressed_size.get() > 0 {
        let ratio = body.len() as f64 / compressed_size.get() as f64;
        println!("  Compression ratio:      {:.2}x", ratio);
    }

    // You can also track size when streaming the response
    println!("\nStreaming example:");

    let resp = wreq::get("https://httpbin.org/gzip").send().await?;
    let compressed_size = resp.compressed_size();

    let mut total_bytes = 0;
    let mut resp = resp;

    while let Some(chunk) = resp.chunk().await? {
        total_bytes += chunk.len();
        println!(
            "  Chunk: {} bytes decompressed ({} compressed so far)",
            chunk.len(),
            compressed_size.get()
        );
    }

    println!("  Total: {} bytes decompressed ({} compressed)",
             total_bytes, compressed_size.get());

    // Example with a non-compressed response
    println!("\nNon-compressed response:");

    let resp = wreq::get("https://httpbin.org/bytes/1024").send().await?;
    let compressed_size = resp.compressed_size();
    let body = resp.bytes().await?;

    println!("  Wire size:         {} bytes", compressed_size.get());
    println!("  Decompressed size: {} bytes", body.len());
    println!("  (These should be roughly equal for non-compressed content)");

    Ok(())
}
