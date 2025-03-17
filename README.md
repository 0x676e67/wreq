# rquest

[![CI](https://github.com/0x676e67/rquest/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/rquest/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/rquest)
[![crates.io](https://img.shields.io/crates/v/rquest.svg)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

An ergonomic all-in-one HTTP client for browser emulation with TLS, JA3/JA4, and HTTP/2 fingerprints.

## Features

- Plain bodies, JSON, urlencoded, multipart
- Cookie Store
- Header Order
- Redirect Policy
- Rotating Proxies
- WebSocket Upgrade
- HTTPS via [BoringSSL](#building)
- [Emulation](#emulation) Fingerprint

## Example

This asynchronous example utilizes [Tokio](https://tokio.rs) with optional features enabled, requiring the following configuration in Cargo.toml:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "3.0.5"
rquest-util = "0.2.5"
```

And then the code:

```rust,no_run
use rquest::Client;
use rquest_util::Emulation;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = Client::builder()
        .emulation(Emulation::Firefox135)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

## Emulation

- **HTTP/2 over TLS**

  **JA3**/**JA4**/**Akamai** fingerprints cannot accurately simulate browser fingerprints due to the sophistication of TLS encryption and the popularity of HTTP/2. `rquest` does not plan to support parsing these fingerprint strings for simulation. Users are encouraged to customize the configuration according to their own needs.

- **Emulation Device**

  In fact, most device models have the same `TLS`/`HTTP2` configuration, except that the `User-Agent` is changed.

  Device emulation is maintained by [rquest-util](https://github.com/0x676e67/rquest-util).

    <details>

    <summary>Default device emulation types</summary>

    | **Browser**   | **Versions**                                                                                     |
    |---------------|--------------------------------------------------------------------------------------------------|
    | **Chrome**    | `Chrome100`, `Chrome101`, `Chrome104`, `Chrome105`, `Chrome106`, `Chrome107`, `Chrome108`, `Chrome109`, `Chrome114`, `Chrome116`, `Chrome117`, `Chrome118`, `Chrome119`, `Chrome120`, `Chrome123`, `Chrome124`, `Chrome126`, `Chrome127`, `Chrome128`, `Chrome129`, `Chrome130`, `Chrome131`, `Chrome132`, `Chrome133` |
    | **Edge**      | `Edge101`, `Edge122`, `Edge127`, `Edge131`, `Edge134`                                                       |
    | **Safari**    | `SafariIos17_2`, `SafariIos17_4_1`, `SafariIos16_5`, `Safari15_3`, `Safari15_5`, `Safari15_6_1`, `Safari16`, `Safari16_5`, `Safari17_0`, `Safari17_2_1`, `Safari17_4_1`, `Safari17_5`, `Safari18`,             `SafariIPad18`, `Safari18_2`, `Safari18_1_1`, `Safari18_3` |
    | **OkHttp**    | `OkHttp3_9`, `OkHttp3_11`, `OkHttp3_13`, `OkHttp3_14`, `OkHttp4_9`, `OkHttp4_10`, `OkHttp4_12`, `OkHttp5`         |
    | **Firefox**   | `Firefox109`, `Firefox117`, `Firefox128`, `Firefox133`, `Firefox135`, `FirefoxPrivate135`, `FirefoxAndroid135`, `Firefox136`, `FirefoxPrivate136`|

    </details>

## Building

Avoid compiling with packages that depend on `openssl-sys`, as it shares the same prefix symbol with `boring-sys`, potentially leading to [link failures](https://github.com/cloudflare/boring/issues/197) and other issues. Even if compilation succeeds, using both `openssl-sys` and `boring-sys` together can result in memory segmentation faults. Until the upstream Boring resolves these linking conflicts, using `rustls` is the best workaround.

Install the dependencies required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md#build-prerequisites)

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools -y

cargo build --release
```

This GitHub Actions [workflow](.github/compilation-guide/build.yml) can be used to compile the project on **Linux**, **Windows**, and **macOS**.

## License

Released under the [Apache-2.0](./LICENSE) License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.

## Sponsors

Support this project by becoming a [sponsor](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md).

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
