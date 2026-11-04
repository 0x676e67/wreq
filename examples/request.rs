//! Request-level options with a shared client: `cargo run --example request`.
//!
//! Optional environment variables: `WREQ_PROXY` (SOCKS needs `--features socks`),
//! `WREQ_LOCAL_ADDRESS`, and `WREQ_INTERFACE` (on supported platforms).

use std::{env, error::Error, net::IpAddr, time::Duration};

use wreq::{
    Client, Emulation, Proxy, Version,
    header::{self, HeaderMap, HeaderValue, OrigHeaderMap},
    http2::Http2Options,
    redirect::Policy,
    tls::{AlpnProtocol, TlsOptions, TlsVersion},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::builder_tokio()
        .timeout(Duration::from_secs(30))
        .build()?;

    // See emulate.rs for a complete TLS and HTTP/2 fingerprint configuration.
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("wreq-example"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let mut orig_headers = OrigHeaderMap::new();
    orig_headers.insert("User-Agent");
    orig_headers.insert("Accept");

    let emulation = Emulation::builder()
        .config(
            TlsOptions::builder()
                .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
                .min_tls_version(TlsVersion::TLS_1_2)
                .build(),
        )
        .config(
            Http2Options::builder()
                .initial_window_size(16_777_216)
                .build(),
        )
        .headers(headers)
        .orig_headers(orig_headers)
        .build();

    // These settings apply to this request, leaving the client's defaults intact.
    let mut request = client
        .get("https://pingly.us.kg/api/all")
        .emulation(emulation)
        .version(Version::HTTP_2)
        .redirect(Policy::custom(|attempt| {
            println!("Redirecting ({}) to {}", attempt.status, attempt.uri);
            if attempt.previous.len() < 10 {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));

    if let Ok(proxy) = env::var("WREQ_PROXY") {
        request = request.proxy(Proxy::all(proxy)?);
    }

    if let Ok(address) = env::var("WREQ_LOCAL_ADDRESS") {
        request = request.local_address(address.parse::<IpAddr>()?);
    }

    if let Ok(_interface) = env::var("WREQ_INTERFACE") {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        {
            request = request.interface(_interface);
        }
    }

    let response = request.send().await?;
    println!(
        "{:?}\n{}\n{}",
        response.version(),
        response.status(),
        response.text().await?
    );
    Ok(())
}
