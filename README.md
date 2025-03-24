# rquest

[![CI](https://github.com/0x676e67/rquest/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/rquest/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/rquest)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/rquest?logo=rust)
[![crates.io](https://img.shields.io/crates/v/rquest.svg?logo=rust)](https://crates.io/crates/rquest)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rquest)](https://crates.io/crates/rquest)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

An ergonomic all-in-one HTTP client for browser emulation with TLS, JA3/JA4, and HTTP/2 fingerprints.

## Features

- Plain bodies, JSON, urlencoded, multipart
- Cookie Store
- Header Order
- Redirect Policy
- Rotating Proxies
- Certificate Store
- WebSocket Upgrade
- HTTPS via BoringSSL
- HTTP/2 over TLS Emulation

## Example

This asynchronous example utilizes [Tokio](https://tokio.rs) with optional features enabled, requiring the following configuration in Cargo.toml:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rquest = "5"
rquest-util = "2"
```

And then the code:

```rust,no_run
use rquest::Client;
use rquest_util::Emulation;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = Client::builder()
        .emulation(Emulation::Firefox136)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

## Emulation

- **HTTP/2 over TLS**

  **JA3**/**JA4**/**Akamai** fingerprints cannot accurately simulate browser fingerprints due to the sophistication of TLS encryption and the popularity of HTTP/2. rquest does not plan to support parsing these fingerprint strings for simulation. Users are encouraged to customize the configuration according to their own needs.

- **Emulation Device**

  Most browser device models share the same TLS and HTTP/2 configuration, differing only in the User-Agent. The browser device emulation template is managed by [rquest-util](https://github.com/0x676e67/rquest-util).

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

<a href="https://dashboard.capsolver.com/passport/register?inviteCode=y7CtB_a-3X6d" target="_blank"><img src="https://raw.githubusercontent.com/0x676e67/rquest/main/.github/assets/capsolver.jpg" height="47" width="149"></a>

[CapSolver](https://www.capsolver.com/?utm_source=github&utm_medium=banner_repo&utm_campaign=rquest) uses AI-powered Auto Web Unblock to bypass Captchas for seamless data access. Fast, reliable, and cost-effective, it integrates with Colly, Puppeteer, and Playwright. 🎉 Use code **`RQUEST`** for a 6% bonus!

## Accolades

The project is based on a fork of [reqwest](https://github.com/seanmonstar/reqwest).
