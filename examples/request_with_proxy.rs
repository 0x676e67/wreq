use rquest::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    // Build a client to impersonate Firefox133
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Firefox133)
        .build()?;

    let resp = client
        .get("https://tls.peet.ws/api/all")
        .proxy("http://127.0.0.1:6152")
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
