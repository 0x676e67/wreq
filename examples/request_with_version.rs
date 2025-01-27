use http::Version;
use rquest::{redirect::Policy, Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Safari18
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;

    let resp = client
        .get("http://google.com/")
        .redirect(Policy::default())
        .version(Version::HTTP_11)
        .send()
        .await?;

    println!("{:?}", resp.version());
    println!("{}", resp.text().await?);

    Ok(())
}
