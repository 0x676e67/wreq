use http::Version;
use rquest::{redirect::Policy, Emulation};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to emulation Safari18
    let client = rquest::Client::builder()
        .emulation(Emulation::Safari18)
        .build()?;

    let resp = client
        .get("http://google.com/")
        .redirect(Policy::default())
        .version(Version::HTTP_11)
        .send()
        .await?;

    assert_eq!(resp.version(), Version::HTTP_11);
    println!("{}", resp.text().await?);

    Ok(())
}
