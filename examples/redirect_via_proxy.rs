use rquest::{redirect::Policy, tls::Impersonate, Proxy};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to mimic Safari18
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Safari18)
        .proxy(Proxy::all("http://gngpp:gngpp123@127.0.0.1:1080")?)
        .redirect(Policy::default())
        .build()?;

    let resp = client.get("http://google.com/").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
