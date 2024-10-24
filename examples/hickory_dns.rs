use rquest::{dns::hickory::HickoryDnsResolver, tls::Impersonate, Error, LookupIpStrategy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Build a client to mimic Chrome129
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .hickory_dns_strategy(LookupIpStrategy::Ipv4Only)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    // Custom dns resolve，Can be assigned to multiple clients
    let resolver = Arc::new(HickoryDnsResolver::new(LookupIpStrategy::Ipv4thenIpv6)?);

    // Build a client to mimic Chrome129
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .no_hickory_dns()
        .dns_resolver(resolver)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
