use rquest::{redirect::Policy, tls::Impersonate};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to mimic Safari18
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .build()?;

    let resp = client
        .get("http://google.com/")
        .redirect(Policy::default())
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
