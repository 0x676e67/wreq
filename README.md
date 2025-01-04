# rquest - `r`ust & `quest`

[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/rquest)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md)

An ergonomic, all-in-one `TLS`, `JA3`/`JA4`, and `HTTP2` fingerprint `HTTP` Client for spoofing any browser.

- Plain, JSON, urlencoded, multipart bodies
- Header Order
- Redirect Policy
- Cookie Store
- HTTP Proxies
- WebSocket Upgrade
- HTTPS via [BoringSSL](https://github.com/cloudflare/boring)
- Preconfigured TLS and HTTP2 settings
- Perfectly mimic Chrome, Safari, and Firefox

Additional learning resources include:

- [API Documentation](https://docs.rs/rquest)
- [Repository Examples](https://github.com/penumbra-x/rquest/tree/main/examples)

## Usage

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

HTTP

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "1.0.0"
```

```rust,no_run
use rquest::Impersonate;

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
rquest = { version = "1.0.0", features = ["websocket"] }
futures-util = { version = "0.3.0", default-features = false, features = ["std"] }
```

```rust,no_run
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{Impersonate, Client, Message};

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

## Overview

The predecessor of rquest is [reqwest](https://github.com/seanmonstar/reqwest). rquest is a specialized adaptation based on the reqwest project, supporting [BoringSSL](https://github.com/cloudflare/boring) and related `HTTP/2` fingerprints in requests.

It also optimizes commonly used APIs and enhances compatibility with connection pools, making it easier to switch proxies, `IP` addresses, and interfaces. You can directly migrate from a project using reqwest to rquest.

Due to limited time for maintaining the synchronous APIs, only asynchronous APIs are supported. I may have to give up maintenance; if possible, please consider [sponsoring me](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md).

## Connection Pool

Regarding the design strategy of the connection pool, `rquest` and `reqwest` are implemented differently. `rquest` reconstructs the entire connection layer, treating each host with the same proxy or bound `IP`/`Interface` as the same connection, while `reqwest` treats each host as an independent connection. Specifically, the connection pool of `rquest` is managed based on the host and `proxy`/`IP`/`Interface`, while the connection pool of `reqwest` is managed only by the host. In other words, when using `rquest`, you can flexibly switch between proxies, `IP` or `Interface` without affecting the management of the connection pool.

> `Interface` refers to the network interface of the device, such as `wlan0` or `eth0`.

## Root Certificate

By default, `rquest` uses Mozilla's root certificates through the `webpki-roots` crate. This is a static root certificate bundle that is not automatically updated. It also ignores any root certificates installed on the host running `rquest`, which may be a good thing or a bad thing, depending on your point of view. But you can turn off `default-features` to cancel the default certificate bundle, and the system default certificate path will be used to load the certificate. In addition, `rquest` also provides a certificate store for users to customize the update certificate.

- [source code details](https://github.com/penumbra-x/rquest/blob/main/examples/set_native_root_cert.rs)

## Fingerprint

- Customize TLS/HTTP2 fingerprint parameters

Supports custom TLS/HTTP2 fingerprint parameters (disabled by default). Unless you’re highly familiar with TLS and HTTP2, customization is not recommended, as it may cause unexpected issues. Basic device emulation types are provided by [default](https://github.com/penumbra-x/rquest/blob/07a18e81fdf1931e7c10bfbc23da622156a4dfae/src/mimic/mod.rs#L127).

- JA3/JA4/Akkmai Parsing

As `TLS` encryption technology becomes more and more sophisticated and HTTP2 becomes more popular, `JA3`/`JA4`/`Akkmai` fingerprints cannot simulate browser fingerprints very well, and the parsed parameters cannot perfectly imitate the browser's `TLS`/`HTTP2` configuration fingerprints. Therefore, `rquest` has not planned to support parsing `JA3`/`JA4`/`Akkmai` fingerprint strings for simulation, but encourages users to customize the configuration according to their own situation.

Most of the `Akkmai` fingerprint strings obtained by users are not fully calculated. For example, the website: <https://tls.peet.ws/api/all>, where the Headers Frame lacks Priority and Stream ID. If I were the server, it would be easy to detect this. For details, please refer to HTTP2 Frame [Parsing](https://github.com/penumbra-x/pingly/blob/main/src/track/inspector/http2.rs)


## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on `OpenSSL`; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

If both `OpenSSL` and `BoringSSL` are used as dependencies simultaneously, even if the compilation succeeds, strange issues may still arise.

If you prefer compiling for the `musl` target, it is recommended to use the [tikv-jemallocator](https://github.com/tikv/jemallocator) memory allocator; otherwise, multithreaded performance may be suboptimal. Only available in version 0.6.0, details: <https://github.com/tikv/jemallocator/pull/70>

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
