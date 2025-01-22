use rquest::{Client, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to impersonate Firefox128
    let client = Client::builder()
        .impersonate(Impersonate::Firefox128)
        .build()?;

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
