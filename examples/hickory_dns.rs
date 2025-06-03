use std::sync::Arc;
use wreq::dns::{HickoryDnsResolver, LookupIpStrategy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = wreq::Client::builder()
        .hickory_dns_strategy(LookupIpStrategy::Ipv4Only)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Custom dns resolve，Can be assigned to multiple clients
    let resolver = Arc::new(HickoryDnsResolver::new(LookupIpStrategy::Ipv4thenIpv6)?);

    // Build a client
    let client = wreq::Client::builder().dns_resolver(resolver).build()?;

    // Use the API you're already familiar with
    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
