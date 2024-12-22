# rquest

[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/rquest)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md)

An ergonomic, all-in-one `JA3`/`JA4`/`HTTP2` fingerprint `HTTP`/`WebSocket` client.

- Plain, JSON, urlencoded, multipart bodies
- Header order
- Redirect policy
- Cookie store
- Restrict pool [connections](https://docs.rs/rquest/latest/rquest/struct.ClientBuilder.html#method.pool_max_size)
- Proxy-level connection pool
- `HTTPS`/`WebSocket` via [BoringSSL](https://github.com/google/boringssl)
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
rquest = "0.33.0"
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
rquest = { version = "0.33.0", features = ["websocket"] }
futures-util = { version = "0.3.0", default-features = false, features = ["std"] }
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

> More examples can be found in the [examples](https://github.com/penumbra-x/rquest/tree/main/examples) directory.

## Root Certificate

By default, `rquest` uses Mozilla's root certificates through the `webpki-roots` crate. This is a static root certificate bundle that is not automatically updated. It also ignores any root certificates installed on the host running `rquest`, which may be a good thing or a bad thing, depending on your point of view. But you can turn off `default-features` to cancel the default certificate bundle, and the system default certificate path will be used to load the certificate. In addition, `rquest` also provides a certificate store for users to customize the update certificate.

- [source code details](https://github.com/penumbra-x/rquest/blob/main/examples/set_native_root_cert.rs)

## Device

You can customize the `TLS`/`HTTP2` fingerprint parameters of the device. In addition, the basic device impersonation types are provided as follows:

- **Chrome**

`Chrome100`，`Chrome101`，`Chrome104`，`Chrome105`，`Chrome106`，`Chrome107`，`Chrome108`，`Chrome109`，`Chrome114`，`Chrome116`，`Chrome117`，`Chrome118`，`Chrome119`，`Chrome120`，`Chrome123`，`Chrome124`，`Chrome126`，`Chrome127`，`Chrome128`，`Chrome129`，`Chrome130`，`Chrome131`

- **Edge**

`Edge101`，`Edge122`，`Edge127`，`Edge131`

- **Safari**

`SafariIos17_2`，`SafariIos17_4_1`，`SafariIos16_5`，`Safari15_3`，`Safari15_5`，`Safari15_6_1`，`Safari16`，`Safari16_5`，`Safari17_0`，`Safari17_2_1`，`Safari17_4_1`，`Safari17_5`，`Safari18`，`SafariIPad18`, `Safari18_2`, `Safari18_1_1`

- **OkHttp**

`OkHttp3_9`，`OkHttp3_11`，`OkHttp3_13`，`OkHttp3_14`，`OkHttp4_9`，`OkHttp4_10`，`OkHttp5`

- **Firefox**

`Firefox109`, `Firefox133`

> It is not supported for Firefox device that use http2 priority frames. If anyone is willing to help implement it, please submit a patch to the [h2](https://github.com/penumbra-x/h2) repository.

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on `OpenSSL`; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

If both `OpenSSL` and `BoringSSL` are used as dependencies simultaneously, even if the compilation succeeds, strange issues may still arise.

If you prefer compiling for the `musl target`, it is recommended to use the [tikv-jemallocator](https://github.com/tikv/jemallocator) memory allocator; otherwise, multithreaded performance may be suboptimal. Only available in version 0.6.0, details: https://github.com/tikv/jemallocator/pull/70

## Building

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools -y

cargo build --release
```

You can also use [this GitHub Actions workflow](https://github.com/penumbra-x/rquest/blob/main/.github/compilation-guide/build.yml) to compile your project on **Linux**, **Windows**, and **macOS**.

## About

The predecessor of rquest is [reqwest](https://github.com/seanmonstar/reqwest). rquest is a specialized adaptation based on the reqwest project, supporting [BoringSSL](https://github.com/google/boringssl) and related HTTP/2 fingerprints in requests.

It also optimizes commonly used APIs and enhances compatibility with connection pools, making it easier to switch proxies, IP addresses, and interfaces. You can directly migrate from a project using reqwest to rquest.

Due to limited time for maintaining the synchronous APIs, only asynchronous APIs are supported. I may have to give up maintenance; if possible, please consider [sponsoring me](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md).

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/penumbra-x/rquest/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/penumbra-x/rquest/issues)

## License

Apache-2.0 [LICENSE](LICENSE)

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
