use wreq::{Client, redirect::Policy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Create a client with redirect support
    let client = Client::builder()
        .history(true)
        .redirect(Policy::default())
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://google.com/").send().await?;

    // We can inspect the redirect history
    for (i, resp) in resp.history().enumerate() {
        println!(
            "Response #{}: status: {}, uri: {}, headers: {:#?}",
            i + 1,
            resp.status(),
            resp.uri(),
            resp.headers()
        );
    }
    Ok(())
}
