# rquest

[![CI](https://github.com/0x676e67/rquest/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/rquest/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

An ergonomic, all-in-one HTTP client for emulating any browser with TLS, JA3/JA4, and HTTP2 fingerprints.

## Features

- Plain, JSON, urlencoded, multipart bodies
- Header Order
- Redirect Policy
- Cookie Store
- HTTP Proxies
- WebSocket Upgrade
- HTTPS via BoringSSL
- Perfectly emulation Chrome, Safari, and Firefox

## Example

This asynchronous example uses [Tokio](https://tokio.rs) and enables some optional features. Your `Cargo.toml` could look like this:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "2.0.0"
```

And then the code:

```rust,no_run
use rquest::{Client, Emulation};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to emulation Firefox133
    let client = Client::builder()
        .emulation(Emulation::Firefox133)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

## FFI bindings

- [rnet](https://github.com/0x676e67/rnet): Python HTTP client with a touch of black magic.
- [ktor-emulation](https://github.com/rushiiMachine/ktor-emulation): KMP Ktor engine bindings for `rquest` to spoof JA3/JA4/H2 fingerprints.

## Emulation

- **HTTP/2 over TLS**

  **JA3**/**JA4**/**Akamai** fingerprints cannot accurately simulate browser fingerprints due to the sophistication of TLS encryption and the popularity of HTTP/2. `rquest` does not plan to support parsing these fingerprint strings for simulation. Users are encouraged to customize the configuration according to their own needs.

  Note: Many `Akamai` fingerprint strings are incomplete. For example, the [website](https://tls.peet.ws/api/all) lacks Priority and Stream ID in the Headers Frame, making it easy to detect. For details, refer to the HTTP/2 frame [parser](https://github.com/0x676e67/pingly/blob/main/src/track/inspector/http2.rs).

- **Emulation Device**

  In fact, most device models have the same `TLS`/`HTTP2` configuration, except that the `User-Agent` is changed.

    <details>

    <summary>Default device emulation types</summary>

  - **Chrome**

    `Chrome100`，`Chrome101`，`Chrome104`，`Chrome105`，`Chrome106`，`Chrome107`，`Chrome108`，`Chrome109`，`Chrome114`，`Chrome116`，`Chrome117`，`Chrome118`，`Chrome119`，`Chrome120`，`Chrome123`，`Chrome124`，`Chrome126`，`Chrome127`，`Chrome128`，`Chrome129`，`Chrome130`，`Chrome131`，`Chrome132`，`Chrome133`

  - **Edge**

    `Edge101`，`Edge122`，`Edge127`，`Edge131`

  - **Safari**

    `SafariIos17_2`，`SafariIos17_4_1`，`SafariIos16_5`，`Safari15_3`，`Safari15_5`，`Safari15_6_1`，`Safari16`，`Safari16_5`，`Safari17_0`，`Safari17_2_1`，`Safari17_4_1`，`Safari17_5`，`Safari18`，`SafariIPad18`, `Safari18_2`, `Safari18_1_1`

  - **OkHttp**

    `OkHttp3_9`，`OkHttp3_11`，`OkHttp3_13`，`OkHttp3_14`，`OkHttp4_9`，`OkHttp4_10`，`OkHttp5`

  - **Firefox**

    `Firefox109`, `Firefox117`, `Firefox128`, `Firefox133`

    </details>

## Building

Do not compile with packages that depend on openssl-sys; it links with the same prefix symbol as boring-sys, which can cause [link failures](https://github.com/cloudflare/boring/issues/197) and other problems. Even if compilation succeeds, using both `openssl-sys` and `boring-sys` as dependencies can cause memory segmentation faults.

Install the dependencies required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md#build-prerequisites)

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools -y

cargo build --release
```

This GitHub Actions [workflow](https://github.com/0x676e67/rquest/blob/main/.github/compilation-guide/build.yml) can be used to compile the project on **Linux**, **Windows**, and **macOS**.

## Contribution

If you would like to submit your contribution, please open a [Pull Request](https://github.com/0x676e67/rquest/pulls).

## License

Licensed under either of Apache-2.0 [License](LICENSE)

## Sponsors
Support this project by becoming a [sponsor](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md).

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
