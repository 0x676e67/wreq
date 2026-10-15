//! Computes the client's own fingerprints from observed connection bytes with `pingly`.
//!
//! Compare the output with what a fingerprinting server reports:
//!
//! ```sh
//! cargo run --example fingerprint -- https://tls.peet.ws/api/all
//! ```

use std::sync::{Arc, Mutex};

use pingly::{
    h2::{AkamaiFingerprint, Frame, Http2Parser},
    tls::ClientHelloBuffer,
};
use wreq::observe::{ConnectionEvent, ConnectionObserver};

/// Captures the ClientHello and the HTTP/2 frames a client sends.
///
/// This example sends one request, so it does not separate events by connection id.
#[derive(Default)]
struct Fingerprint(Mutex<Capture>);

#[derive(Default)]
struct Capture {
    hello: ClientHelloBuffer,
    h2: Option<Http2Parser>,
    frames: Vec<Frame>,
}

impl ConnectionObserver for Fingerprint {
    fn observe(&self, event: ConnectionEvent<'_>) {
        let mut capture = self.0.lock().unwrap();
        match event {
            // Through an HTTPS proxy the origin handshake follows the proxy's; keep the last one.
            ConnectionEvent::TlsHandshake { .. } => capture.hello = ClientHelloBuffer::new(),
            ConnectionEvent::TlsWrite { bytes, .. } => {
                capture.hello.extend(bytes);
            }
            ConnectionEvent::Connected { alpn, .. } => {
                capture.h2 = (alpn == Some(b"h2")).then(Http2Parser::new);
            }
            ConnectionEvent::Write { bytes, .. } => {
                let Capture { h2, frames, .. } = &mut *capture;
                if let Some(h2) = h2 {
                    let _ = h2.push_into(bytes, frames);
                }
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://tls.peet.ws/api/all".to_owned());

    let fingerprint = Arc::new(Fingerprint::default());
    let client = wreq::Client::builder()
        .connection_observer(fingerprint.clone())
        .build()?;
    let response = client.get(url).send().await?;
    println!("{}\n", response.text().await?);

    let capture = fingerprint.0.lock().unwrap();
    if let Ok(Some(hello)) = capture.hello.try_parse() {
        let (ja3, ja4) = (hello.ja3(), hello.ja4());
        println!("JA3: {} ({})", ja3.raw, ja3.hash);
        println!("JA4: {} ({})", ja4.raw, ja4.fingerprint);
    }
    if let Some(akamai) = AkamaiFingerprint::from_frames(&capture.frames) {
        println!("Akamai: {} ({})", akamai.fingerprint, akamai.hash);
    }

    Ok(())
}
