use rquest::dns::{HickoryDnsResolver, LookupIpStrategy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = rquest::Client::builder()
        .hickory_dns_strategy(LookupIpStrategy::Ipv4Only)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Custom dns resolve，Can be assigned to multiple clients
    let resolver = Arc::new(HickoryDnsResolver::new(LookupIpStrategy::Ipv4thenIpv6)?);

    // Build a client
    let client = rquest::Client::builder().dns_resolver(resolver).build()?;

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
