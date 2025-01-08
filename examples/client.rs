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
    // Build a client to mimic Chrome131
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    let url = "https://tls.peet.ws/api/all".parse().expect("Invalid url");

    // Set the headers order
    {
        client.set_headers_order(HEADER_ORDER);
        let resp = client.get(&url).send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Safari18
    {
        client.set_impersonate(Impersonate::Safari18)?;
        let resp = client.get(&url).send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Edge127 without setting the headers
    {
        client.set_impersonate_skip_headers(Impersonate::Edge127)?;

        // Set a header
        client
            .headers_mut()
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
        client.set_local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));
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
        client.set_interface("eth0");
        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // ⚠️ Note: Methods like `set_impersonate` and `set_impersonate_without_headers` will reset all client settings,
    // including proxies, header information, and more. Use them carefully.
    // When using methods such as `set_headers_order`, `headers_mut`, `set_impersonate`, `set_impersonate_without_headers`,
    // `set_interface`, `set_local_address`, `set_local_addresses`, or `set_proxies`,
    // changes will only affect the current `Client` instance.
    // If you need to preserve the original settings, you can clone the `Client`.
    // Cloning a `Client` is cheap, and while modifications won't affect the original `Client` instance,
    // they will share the same connection pool.
    let mut client2 = client.clone();

    // Set the impersonate to Chrome131
    // Expected: Chrome131
    {
        client2.set_impersonate(Impersonate::Chrome131)?;
        let resp = client2.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // But not change the original client
    // Expected: Edge127
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
