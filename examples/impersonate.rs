use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Safari18_1_1
    let client = rquest::Client::builder()
        .impersonate(Impersonate::SafariIos18_1_1)
        .build()?;

    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
