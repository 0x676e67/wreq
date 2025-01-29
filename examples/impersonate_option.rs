use rquest::{Client, Impersonate, ImpersonateOS, ImpersonateOption};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Firefox128
    let impersonate = ImpersonateOption::builder()
        .impersonate(Impersonate::Firefox128)
        .impersonate_os(ImpersonateOS::Windows)
        .skip_http2(true)
        .build();

    // Apply the impersonate to the client
    let client = Client::builder()
        .impersonate(impersonate)
        .http1_only()
        .build()?;

    // Use the API you're already familiar with
    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
