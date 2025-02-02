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
    use http::{header, HeaderName};
    use rquest::{Client, Impersonate};

    const HEADER_ORDER: &[HeaderName] = &[
        header::ACCEPT_LANGUAGE,
        header::USER_AGENT,
        header::ACCEPT_ENCODING,
        header::HOST,
        header::COOKIE,
    ];

    // Build a client to impersonate Chrome131
    let client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    client
        .as_mut()
        .impersonate(Impersonate::Safari18)
        .headers_order(HEADER_ORDER)
        .interface("utun4")
        .base_url("https://tls.peet.ws")
        .apply()?;

    let text = client.get("/api/all").send().await?.text().await?;
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
