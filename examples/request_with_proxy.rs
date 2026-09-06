use wreq::Proxy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Use the API you're already familiar with
    let resp = wreq::get("https://api.ip.sb/ip")
        .proxy(Proxy::all("socks5h://localhost:6153")?)
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
