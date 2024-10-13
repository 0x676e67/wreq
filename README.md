# rquest

[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

An ergonomic, all-in-one `JA3`/`JA4`/`HTTP2` fingerprint `HTTP`/`WebSocket` client.

- Async Client
- Plain, JSON, urlencoded, multipart bodies
- Headers Order
- Customizable redirect policy
- Cookie Store
- HTTP Proxies
- `HTTPS`/`WebSocket` via BoringSSL
- Preconfigured `TLS`/`HTTP2`/`Headers` settings
- [Changelog](https://github.com/penumbra-x/rquest/blob/main/CHANGELOG.md)

Additional learning resources include:

- [API Documentation](https://docs.rs/rquest)
- [Repository Examples](https://github.com/penumbra-x/rqeust/tree/main/examples)

## Usage

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

HTTP

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.22"
```

```rust,no_run
use std::error::Error;
use rquest::tls::Impersonate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome129
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
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
rquest = { version = "0.22", features = ["websocket"] }
```

```rust,no_run
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build a client to mimic Chrome129
    let client = Client::builder()
        .impersonate(Impersonate::Chrome129)
        .http1_only()
        .build()?;

    // Use the API you're already familiar with
    let websocket = client.get("wss://echo.websocket.org")
        .upgrade()
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
rquest = "0.22"
```

```rust
use boring::ssl::{SslConnector, SslMethod};
use http::{header, HeaderValue};
use rquest::{
    tls::{Http2Settings, ImpersonateSettings, TlsExtensionSettings},
    HttpVersionPref,
};
use rquest::{PseudoOrder::*, SettingsOrder::*};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a pre-configured TLS settings
    let settings = ImpersonateSettings::builder()
        .tls((
            SslConnector::builder(SslMethod::tls_client())?,
            TlsExtensionSettings::builder()
                .tls_sni(true)
                .http_version_pref(HttpVersionPref::Http2)
                .application_settings(true)
                .pre_shared_key(true)
                .enable_ech_grease(true)
                .permute_extensions(true)
                .build(),
        ))
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
                .settings_order(vec![
                    HeaderTableSize,
                    EnablePush,
                    MaxConcurrentStreams,
                    InitialWindowSize,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    EnableConnectProtocol,
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

## Device

Currently supported impersonate device types

- **Chrome**

`Chrome100`，`Chrome101`，`Chrome104`，`Chrome105`，`Chrome106`，`Chrome107`，`Chrome108`，`Chrome109`，`Chrome114`，`Chrome116`，`Chrome117`，`Chrome118`，`Chrome119`，`Chrome120`，`Chrome123`，`Chrome124`，`Chrome126`，`Chrome127`，`Chrome128`，`Chrome129`

- **Edge**

`Edge101`，`Edge122`，`Edge127`

- **Safari**

`SafariIos17_2`，`SafariIos17_4_1`，`SafariIos16_5`，`Safari15_3`，`Safari15_5`，`Safari15_6_1`，`Safari16`，`Safari16_5`，`Safari17_0`，`Safari17_2_1`，`Safari17_4_1`，`Safari17_5`，`Safari18`，`SafariIPad18`

- **OkHttp**

`OkHttp3_9`，`OkHttp3_11`，`OkHttp3_13`，`OkHttp3_14`，`OkHttp4_9`，`OkHttp4_10`，`OkHttp5`

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on OpenSSL; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

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
