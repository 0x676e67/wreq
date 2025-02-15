//! Run websocket server
//!
//! ```not_rust
//! git clone https://github.com/tokio-rs/axum && cd axum
//! cargo run -p example-websockets-http2
//! ```

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::header;
use rquest::{Client, Emulation, Message, Utf8Bytes};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to emulation Firefox133
    let client = Client::builder()
        .emulation(Emulation::Firefox133)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://127.0.0.1:3000/ws")
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .use_http2()
        .send()
        .await?;

    assert_eq!(websocket.version(), http::Version::HTTP_2);

    let (mut tx, mut rx) = websocket.into_websocket().await?.split();

    tokio::spawn(async move {
        for i in 1..11 {
            if let Err(err) = tx
                .send(Message::Text(Utf8Bytes::from(format!(
                    "Hello, World! #{i}"
                ))))
                .await
            {
                eprintln!("failed to send message: {err}");
            }
        }
    });

    while let Some(message) = rx.try_next().await? {
        if let Message::Text(text) = message {
            println!("received: {text}");
        }
    }

    Ok(())
}
