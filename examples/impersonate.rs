use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Firefox133
    let client = rquest::Client::builder()
        .impersonate_skip_headers(Impersonate::Firefox133)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);
    Ok(())
}
