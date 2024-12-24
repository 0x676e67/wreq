use rquest::{tls::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Edge131
    let mut client = Client::builder()
        .impersonate(Impersonate::Edge131)
        .base_url("https://httpbin.org")
        .build()?;

    // Send a request to httpbin.org /get
    let resp = client.get("/get").send().await?;
    println!("{}", resp.text().await?);

    // Send a request to httpbin.org /anything
    let resp = client.get("/anything").send().await?;
    println!("{}", resp.text().await?);

    // Reset the base url
    client.set_base_url("https://tls.peet.ws");

    // Send a request to tls.peet.ws /api/all
    let resp = client.get("/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
