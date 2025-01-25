use rquest::{Client, Impersonate, ImpersonateOS};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    // Build a client to impersonate Firefox128
    let impersonate = Impersonate::builder()
        .impersonate(Impersonate::Firefox128)
        .impersonate_os(ImpersonateOS::Windows)
        .skip_http2(false)
        .skip_headers(false)
        .build();

    // Apply the impersonate to the client
    let client = Client::builder()
        .impersonate(impersonate)
        .http2_only()
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
