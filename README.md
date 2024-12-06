# rquest

[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md)

An ergonomic, all-in-one `JA3`/`JA4`/`HTTP2` fingerprint `HTTP`/`WebSocket` client.

- Plain, JSON, urlencoded, multipart bodies
- Header Order
- Redirect policy
- Cookie Store
- `HTTPS`/`WebSocket` via BoringSSL
- Preconfigured `TLS`/`HTTP2` settings
- `HTTP`, `HTTPS`, `SOCKS4` and `SOCKS5` proxies
- [Changelog](https://github.com/penumbra-x/rquest/blob/main/CHANGELOG.md)

Additional learning resources include:

- [API Documentation](https://docs.rs/rquest)
- [Repository Examples](https://github.com/penumbra-x/rquest/tree/main/examples)

> &#9888; This crate is under active development and the API is not yet stable.

## Usage

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

HTTP

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.29"
```

```rust,no_run
use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

WebSocket

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = { version = "0.29", features = ["websocket"] }
```

```rust,no_run
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://echo.websocket.org")
        .send()
        .await?
        .into_websocket()
        .await?;

    let (mut tx, mut rx) = websocket.split();

    tokio::spawn(async move {
        for i in 1..11 {
            tx.send(Message::Text(format!("Hello, World! #{i}")))
                .await
                .unwrap();
        }
    });

    while let Some(message) = rx.try_next().await? {
        match message {
            Message::Text(text) => println!("received: {text}"),
            _ => {}
        }
    }

    Ok(())
}

```

Preconfigured `TLS`/`HTTP2`

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.29"
```

```rust
use boring::ssl::{SslConnector, SslCurve, SslMethod, SslOptions};
use http::{header, HeaderValue};
use rquest::{
    tls::{Http2Settings, ImpersonateSettings, TlsSettings, Version},
    HttpVersionPref,
};
use rquest::{PseudoOrder::*, SettingsOrder::*};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Create a pre-configured TLS settings
    let settings = ImpersonateSettings::builder()
        .tls(
            TlsSettings::builder()
                .connector(Box::new(|| {
                    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
                    builder.set_curves(&[SslCurve::SECP224R1, SslCurve::SECP521R1])?;
                    builder.set_options(SslOptions::NO_TICKET);
                    Ok(builder)
                }))
                .tls_sni(true)
                .http_version_pref(HttpVersionPref::All)
                .application_settings(true)
                .pre_shared_key(true)
                .enable_ech_grease(true)
                .permute_extensions(true)
                .min_tls_version(Version::TLS_1_0)
                .max_tls_version(Version::TLS_1_3)
                .build(),
        )
        .http2(
            Http2Settings::builder()
                .initial_stream_window_size(6291456)
                .initial_connection_window_size(15728640)
                .max_concurrent_streams(1000)
                .max_header_list_size(262144)
                .header_table_size(65536)
                .enable_push(false)
                .headers_priority((0, 255, true))
                .headers_pseudo_order([Method, Scheme, Authority, Path])
                .settings_order([
                    HeaderTableSize,
                    EnablePush,
                    MaxConcurrentStreams,
                    InitialWindowSize,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    UnknownSetting8,
                    UnknownSetting9,
                ])
                .build(),
        )
        .headers(Box::new(|headers| {
            headers.insert(header::USER_AGENT, HeaderValue::from_static("rquest"));
        }))
        .build();

    // Build a client with pre-configured TLS settings
    let client = rquest::Client::builder()
        .use_preconfigured_tls(settings)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}

```

Modify `Client` settings

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.29"
```

```rust
use http::{header, HeaderName, HeaderValue};
use rquest::{tls::Impersonate, Client};
use std::net::Ipv4Addr;

static HEADER_ORDER: [HeaderName; 6] = [
    header::ACCEPT_LANGUAGE,
    header::USER_AGENT,
    header::ACCEPT_ENCODING,
    header::HOST,
    header::COOKIE,
    HeaderName::from_static("priority"),
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to mimic Chrome131
    let mut client = Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Set the headers order
    {
        client.set_headers_order(&HEADER_ORDER);
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Safari18
    {
        client.set_impersonate(Impersonate::Safari18).await?;
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Edge127 without setting the headers
    {
        client
            .set_impersonate_without_headers(Impersonate::Edge127)
            .await?;

        // Set a header
        client
            .headers_mut()
            .insert(header::ACCEPT, "application/json".parse().unwrap());

        // Set a cookie
        client.set_cookies(
            vec![HeaderValue::from_static("foo=bar; Domain=tls.peet.ws")],
            "https://tls.peet.ws/api/all",
        )?;

        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    // Set the local address
    {
        client.set_local_address(Some(Ipv4Addr::new(172, 20, 10, 2).into()));
        let resp = client.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // Set the interface
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
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
        client2.set_impersonate(Impersonate::Chrome131).await?;

        let resp = client2.get("https://api.ip.sb/ip").send().await?;
        println!("{}", resp.text().await?);
    }

    // But not change the original client
    // Expected: Edge127
    let resp = client.get("https://api.ip.sb/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}

```

## Device

You can customize the `TLS`/`HTTP2` fingerprint parameters of the device. In addition, the basic device impersonation types are provided as follows:

- **Chrome**

`Chrome100`，`Chrome101`，`Chrome104`，`Chrome105`，`Chrome106`，`Chrome107`，`Chrome108`，`Chrome109`，`Chrome114`，`Chrome116`，`Chrome117`，`Chrome118`，`Chrome119`，`Chrome120`，`Chrome123`，`Chrome124`，`Chrome126`，`Chrome127`，`Chrome128`，`Chrome129`，`Chrome130`，`Chrome131`

- **Edge**

`Edge101`，`Edge122`，`Edge127`

- **Safari**

`SafariIos17_2`，`SafariIos17_4_1`，`SafariIos16_5`，`Safari15_3`，`Safari15_5`，`Safari15_6_1`，`Safari16`，`Safari16_5`，`Safari17_0`，`Safari17_2_1`，`Safari17_4_1`，`Safari17_5`，`Safari18`，`SafariIPad18`

- **OkHttp**

`OkHttp3_9`，`OkHttp3_11`，`OkHttp3_13`，`OkHttp3_14`，`OkHttp4_9`，`OkHttp4_10`，`OkHttp5`

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on `OpenSSL`; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

If both `OpenSSL` and `BoringSSL` are used as dependencies simultaneously, even if the compilation succeeds, strange issues may still arise.

## Building

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools -y

cargo build --release
```

You can also use [this GitHub Actions workflow](https://github.com/penumbra-x/rquest/blob/main/.github/compilation-guide/build.yml) to compile your project on **Linux**, **Windows**, and **macOS**.

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/penumbra-x/rquest/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/penumbra-x/rquest/issues)

## License

Apache-2.0 [LICENSE](LICENSE)

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
