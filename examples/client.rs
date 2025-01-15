use http::{header, HeaderName, HeaderValue};
use rquest::{Client, Impersonate};
use std::net::Ipv4Addr;

const HEADER_ORDER: &[HeaderName] = &[
    header::ACCEPT_LANGUAGE,
    header::USER_AGENT,
    header::ACCEPT_ENCODING,
    header::HOST,
    header::COOKIE,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to impersonate Chrome131
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set the headers order
    {
        client.as_mut().headers_order(HEADER_ORDER);
        let resp = client.get(&url).send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Safari18
    {
        client.as_mut().impersonate(Impersonate::Safari18);
        let resp = client.get(&url).send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Edge127 without setting the headers
    {
        client.as_mut().impersonate(Impersonate::Edge127);

        // Set a header
        client
            .as_mut()
            .headers()
            .insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        // Set a cookie
        client.set_cookies(
            &url,
            vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
        );

        let resp = client.get(&url).send().await?;
        println!("{}", resp.text().await?);
    }

    // Set the local address
    {
        client
            .as_mut()
            .local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));
        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // Set the interface
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "ios",
        target_os = "visionos",
        target_os = "macos",
        target_os = "tvos",
        target_os = "watchos"
    ))]
    {
        client.as_mut().interface("eth0");
        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // If you need to preserve the original settings, you can clone the `Client`.
    // Cloning a `Client` is cheap, and while modifications won't affect the original `Client` instance,
    // they will share the same connection pool.
    let mut client2 = client.clone();

    // Set the impersonate to Chrome131
    // Expected: Chrome131
    {
        client2.as_mut().impersonate(Impersonate::Chrome131);
        let resp = client2.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // But not change the original client
    // Expected: Edge127
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
