# rquest

[![Email Badge](https://img.shields.io/badge/Gmail-Contact_Me-green?logo=gmail)](mailto:gngppz@gmail.com)
[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Documentation](https://docs.rs/rquest/badge.svg)](https://docs.rs/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

An fast asynchronous Rust `HTTP`/`WebSocket` Client with `TLS`/`JA3`/`JA4`/`HTTP2` fingerprint impersonate

- `Async` Client
- Plain, JSON, urlencoded, multipart bodies
- Headers Order
- Customizable redirect policy
- Cookie Store
- `HTTP`/`WebSocket` Proxies
- `HTTPS`/`WebSocket` via BoringSSL
- Preconfigured `TLS`/`HTTP2`/`Headers` settings
- [Changelog](https://github.com/0x676e67/rquest/blob/main/CHANGELOG.md)

Additional learning resources include:

- [API Documentation](https://docs.rs/rquest)
- [Repository Examples](https://github.com/0x676e67/rquest/tree/master/examples)

## Usage

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

HTTP

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "0.21"
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
rquest = { version = "0.21", features = ["websocket"] }
```

```rust,no_run
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let websocket = rquest::websocket("wss://echo.websocket.org").await?;

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
rquest = "0.21"
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

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on OpenSSL; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/0x676e67/rquest/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/0x676e67/rquest/issues)

## License

Apache-2.0 [LICENSE](LICENSE)

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
