use rquest::{tls::Impersonate, Client};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to mimic Chrome130
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .build()?;

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    // Set the proxy
    // Proxy-level connection pool, two factors (host and authentication)
    // Continuously making requests will reuse the connection until the next proxy change
    {
        // option 1: set the proxies
        {
            let proxy = rquest::Proxy::all("socks5h://abc:123@127.0.0.1:6153")?;
            client.set_proxies(vec![proxy]);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);
        }

        // option 2:  the proxies
        {
            let proxy = rquest::Proxy::all("socks5h://abc:123@127.0.0.1:6153")?;
            client.set_proxies(vec![proxy]);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);

            let resp = client.get("https://api.ip.sb/ip").send().await?;
            println!("{}", resp.text().await?);
        }
    }

    Ok(())
}
