# wreq

[![CI](https://github.com/0x676e67/wreq/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/wreq/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/wreq)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/wreq?logo=rust)
[![crates.io](https://img.shields.io/crates/v/wreq.svg?logo=rust)](https://crates.io/crates/wreq)
[![Documentation](https://docs.rs/wreq/badge.svg)](https://docs.rs/wreq)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

An ergonomic all-in-one HTTP client for browser emulation with TLS, JA3/JA4, and HTTP/2 fingerprints.

## Features

- Plain bodies, JSON, urlencoded, multipart
- Cookie Store
- Redirect Policy
- Original Header
- Rotating Proxies
- Certificate Store
- Tower Middleware
- WebSocket Upgrade
- HTTPS via BoringSSL
- HTTP/2 over TLS Emulation

## Example

This asynchronous example utilizes [Tokio](https://tokio.rs) with optional features enabled, requiring the following configuration in `Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
wreq = "5"
wreq-util = "2"
```

And then the code:

```rust,no_run
use wreq::Client;
use wreq_util::Emulation;

#[tokio::main]
async fn main() -> wreq::Result<()> {
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

Due to the complexity of TLS encryption and the widespread adoption of HTTP/2, browser fingerprints such as **JA3**, **JA4**, and **Akamai** cannot be reliably emulated using simple fingerprint strings. Instead of parsing and emulating these string-based fingerprints, `wreq` provides fine-grained control over TLS and HTTP/2 extensions and settings for precise browser behavior emulation.

- **Device Emulation**

Most browser device models share identical TLS and HTTP/2 configurations, differing only in the `User-Agent` string. Common browser device emulation templates are maintained in [`wreq-util`](https://github.com/0x676e67/wreq-util), a companion utility crate.

## Building

Avoid compiling with packages that depend on `openssl-sys`, as it shares the same prefix symbol with `boring-sys`, potentially leading to [link failures](https://github.com/cloudflare/boring/issues/197) and other issues. Even if compilation succeeds, using both `openssl-sys` and `boring-sys` together can result in memory segmentation faults. Until the upstream Boring resolves these linking conflicts, using `rustls` is the best workaround.

Install the dependencies required to build [BoringSSL](https://github.com/google/boringssl/blob/master/BUILDING.md#build-prerequisites)

```shell
sudo apt-get install build-essential cmake perl pkg-config libclang-dev musl-tools git -y

cargo build --release
```

This GitHub Actions [workflow](.github/compilation-guide/build.yml) can be used to compile the project on **Linux**, **Windows**, and **macOS**.

## License

Released under the [Apache-2.0](./LICENSE) License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.

## Sponsors

<a href="https://dashboard.capsolver.com/passport/register?inviteCode=y7CtB_a-3X6d" target="_blank"><img src="https://raw.githubusercontent.com/0x676e67/wreq/main/.github/assets/capsolver.jpg" height="47" width="149"></a>

[CapSolver](https://www.capsolver.com/?utm_source=github&utm_medium=banner_repo&utm_campaign=wreq) leverages AI-powered Auto Web Unblock to bypass Captchas effortlessly, providing fast, reliable, and cost-effective data access with seamless integration into Colly, Puppeteer, and Playwright—use code **`RQUEST`** for a 6% bonus!

## Accolades

A hard fork of [reqwest](https://github.com/seanmonstar/reqwest).
