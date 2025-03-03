use rquest::Client;

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos"
))]
#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = Client::builder().build()?;

    let text = client
        .get("https://api.ip.sb/ip")
        .interface("utun4")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos"
)))]
fn main() {}
