# rquest

[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/rquest)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/penumbra-x/.github/blob/main/profile/SPONSOR.md)

An ergonomic, all-in-one `JA3`/`JA4`/`HTTP2` fingerprint `HTTP`/`WebSocket` client.

- Plain, JSON, urlencoded, multipart bodies
- Header Order
- Redirect Policy
- Cookie Store
- HTTP Proxies
- Restrict pool [connections](https://docs.rs/rquest/latest/rquest/struct.ClientBuilder.html#method.pool_max_size)
- `HTTPS`/`WebSocket` via [BoringSSL](https://github.com/google/boringssl)
- Preconfigured `TLS`/`HTTP2` settings
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
rquest = "1.0.0-rc.2"
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
rquest = { version = "1.0.0-rc.2", features = ["websocket"] }
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

## Connection Pool

Regarding the design strategy of the connection pool, `rquest` and `reqwest` are implemented differently. `rquest` reconstructs the entire connection layer, treating each host with the same proxy or bound `IP`/`Interface` as the same connection, while `reqwest` treats each host as an independent connection. Specifically, the connection pool of `rquest` is managed based on the host and `proxy`/`IP`/`Interface`, while the connection pool of `reqwest` is managed only by the host. In other words, when using `rquest`, you can flexibly switch between proxies, `IP` or `Interface` without affecting the management of the connection pool.

> `Interface` refers to the network interface of the device, such as `wlan0` or `eth0`.

## Root Certificate

By default, `rquest` uses Mozilla's root certificates through the `webpki-roots` crate. This is a static root certificate bundle that is not automatically updated. It also ignores any root certificates installed on the host running `rquest`, which may be a good thing or a bad thing, depending on your point of view. But you can turn off `default-features` to cancel the default certificate bundle, and the system default certificate path will be used to load the certificate. In addition, `rquest` also provides a certificate store for users to customize the update certificate.

- [source code details](https://github.com/penumbra-x/rquest/blob/main/examples/set_native_root_cert.rs)

## Device

You can customize the `TLS`/`HTTP2` fingerprint parameters of the device. In addition, the basic device impersonation types are provided as follows:

| Browser                                                                                                                      | Version | Build         | OS               | Target Name         |
|------------------------------------------------------------------------------------------------------------------------------|---------|---------------|------------------|---------------------|
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome")                   | 100     | 100.0.4896.75 | Mac OS X 10_15_7 | `chrome_100`        |
|                                                                                                                              | 101     | 101.0.4951.67 | Mac OS X 10_15_7 | `chrome_101`        |
|                                                                                                                              | 104     | 104.0.0.0     | Mac OS X 10_15_7 | `chrome_104`        |
|                                                                                                                              | 105     | 105.0.0.0     | Mac OS X 10_15_7 | `chrome_105`        |
|                                                                                                                              | 106     | 106.0.0.0     | Mac OS X 10_15_7 | `chrome_106`        |
|                                                                                                                              | 107     | 107.0.0.0     | Mac OS X 10_15_7 | `chrome_107`        |
|                                                                                                                              | 108     | 108.0.0.0     | Mac OS X 10_15_7 | `chrome_108`        |
|                                                                                                                              | 109     | 109.0.0.0     | Mac OS X 10_15_7 | `chrome_109`        |
|                                                                                                                              | 114     | 114.0.0.0     | Mac OS X 10_15_7 | `chrome_114`        |
|                                                                                                                              | 116     | 116.0.0.0     | Mac OS X 10_15_7 | `chrome_116`        |
|                                                                                                                              | 117     | 117.0.0.0     | Mac OS X 10_15_7 | `chrome_117`        |
|                                                                                                                              | 118     | 118.0.0.0     | Mac OS X 10_15_7 | `chrome_118`        |
|                                                                                                                              | 119     | 119.0.0.0     | Mac OS X 10_15_7 | `chrome_119`        |
|                                                                                                                              | 120     | 120.0.0.0     | Mac OS X 10_15_7 | `chrome_120`        |
|                                                                                                                              | 123     | 123.0.0.0     | Mac OS X 10_15_7 | `chrome_123`        |
|                                                                                                                              | 124     | 124.0.0.0     | Mac OS X 10_15_7 | `chrome_124`        |
|                                                                                                                              | 126     | 126.0.0.0     | Mac OS X 10_15_7 | `chrome_126`        |
|                                                                                                                              | 127     | 127.0.0.0     | Mac OS X 10_15_7 | `chrome_127`        |
|                                                                                                                              | 128     | 128.0.0.0     | Mac OS X 10_15_7 | `chrome_128`        |
|                                                                                                                              | 129     | 129.0.0.0     | Mac OS X 10_15_7 | `chrome_129`        |
|                                                                                                                              | 130     | 130.0.0.0     | Mac OS X 10_15_7 | `chrome_130`        |
|                                                                                                                              | 131     | 131.0.0.0     | Mac OS X 10_15_7 | `chrome_131`        |
| ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge")                           | 101     | 101.0.1210.47 | Mac OS X 10_15_7 | `edge_101`          |
|                                                                                                                              | 122     | 122.0         | Mac OS X 10_15_7 | `edge_122`          |
|                                                                                                                              | 127     | 127.0         | Mac OS X 10_15_7 | `edge_127`          |
|                                                                                                                              | 131     | 131.0         | Mac OS X 10_15_7 | `edge_131`          |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox")               | 109     | 109.0         | Windows 10       | `firefox_109`       |
|                                                                                                                              | 133     | 133.0         | Mac OS X 10.15   | `firefox_133`       |
| ![Safari](https://raw.githubusercontent.com/alrra/browser-logos/main/src/safari/safari_24x24.png "Safari")                   | 15.3    | 605.1.15      | Mac OS X 10_15_7 | `safari_15.3`       |
|                                                                                                                              | 15.5    | 605.1.15      | Mac OS X 10_15_7 | `safari_15.5`       |
|                                                                                                                              | 15.6.1  | 605.1.15      | Mac OS X 10_15_7 | `safari_15.6.1`     |
|                                                                                                                              | 16.0    | 605.1.15      | Mac OS X 10_15_7 | `safari_16.0`       |
|                                                                                                                              | 16.5    | 605.1.15      | Mac OS X 10_15_7 | `safari_16.5`       |
|                                                                                                                              | 16.5    | 604.1         | iOS              | `safari_ios_16.5`   |
|                                                                                                                              | 17.0    | 605.1.15      | Mac OS X 10_15_7 | `safari_17.0`       |
|                                                                                                                              | 17.2.1  | 605.1.15      | Mac OS X 10_15_7 | `safari_17.2.1`     |
|                                                                                                                              | 17.4.1  | 605.1.15      | Mac OS X 10_15_7 | `safari_17.4.1`     |
|                                                                                                                              | 17.5    | 605.1.15      | Mac OS X 10_15_7 | `safari_17.5`       |
|                                                                                                                              | 17.2    | 604.1         | iOS              | `safari_ios_17.2`   |
|                                                                                                                              | 17.4.1  | 604.1         | iPadOS           | `safari_ios_17.4.1` |
|                                                                                                                              | 18.0    | 605.1.15      | Mac OS X 10_15_7 | `safari_18.0`       |
|                                                                                                                              | 18.0    | 604.1         | iPadOS           | `safari_ipad_18.0`  |
|                                                                                                                              | 18.1.1  | 604.1         | iOS              | `safari_ios_18.1.1` |
|                                                                                                                              | 18.2    | 605.1.15      | Mac OS X 10_15_7 | `safari_18.2`       |
| ![OkHttp](https://raw.githubusercontent.com/alrra/browser-logos/main/src/android-webview/android-webview_24x24.png "OkHttp") | 3.9     | 3.9.0         | Android 5.0      | `okhttp_3.9`        |
|                                                                                                                              | 3.11    | 3.11.0        | Android 12       | `okhttp_3.11`       |
|                                                                                                                              | 3.13    | 3.13.0        | Android 14       | `okhttp_3.13`       |
|                                                                                                                              | 3.14    | 3.14.0        | Android 11       | `okhttp_3.14`       |
|                                                                                                                              | 4.9     | 4.9           | Android 11       | `okhttp_4.9`        |
|                                                                                                                              | 4.10    | 4.10.0        | Android 13       | `okhttp_4.10`       |
|                                                                                                                              | 5.0     | 5.0.0-alpha2  | Android 14       | `okhttp_5.0`        |

> It is not supported for Firefox device that use http2 priority frames. If anyone is willing to help implement it, please submit a patch to the [h2](https://github.com/penumbra-x/h2) repository.

## Requirement

Install the environment required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md)

Do not compile with crates that depend on `OpenSSL`; their prefixing symbols are the same and may cause linking [failures](https://github.com/rustls/rustls/issues/2010).

If both `OpenSSL` and `BoringSSL` are used as dependencies simultaneously, even if the compilation succeeds, strange issues may still arise.

If you prefer compiling for the `musl target`, it is recommended to use the [tikv-jemallocator](https://github.com/tikv/jemallocator) memory allocator; otherwise, multithreaded performance may be suboptimal. Only available in version 0.6.0, details: https://github.com/tikv/jemallocator/pull/70

## Building

| Platform         | Architecture | Notes                                            |
|------------------|--------------|--------------------------------------------------|
| **Linux** 🐧     | `amd64`      |                                                  |
|                  | `aarch64`    | Needs manylinux_2_34 (Ubuntu ≥22.04, Debian ≥12) |
|                  | `armv7`      | Needs manylinux_2_34 (Ubuntu ≥22.04, Debian ≥12) |
| **MuslLinux** 🐧 | `amd64`      |                                                  |
|                  | `aarch64`    |                                                  |
| **Windows** 🪟   | `amd64`      |                                                  |
| **macOS** 🍎     | `amd64`      |                                                  |
|                  | `aarch64`    |                                                  |

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
