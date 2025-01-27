use rquest::{redirect::Policy, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Safari18
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;

    // Set the redirect policy
    client.as_mut().redirect(Policy::default());

    // Use the API you're already familiar with
    let text = client
        .get("http://google.com/")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
