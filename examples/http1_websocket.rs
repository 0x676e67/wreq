use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::websocket::Message;
use rquest::{Client, header};
use std::time::Duration;

#[tokio::main]
async fn main() -> rquest::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client
    let client = Client::builder()
        .cert_verification(false)
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://echo.websocket.org")
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .read_buffer_size(1024 * 1024)
        .send()
        .await?;

    assert_eq!(websocket.version(), http::Version::HTTP_11);

    let (mut tx, mut rx) = websocket.into_websocket().await?.split();

    tokio::spawn(async move {
        for i in 1..11 {
            if let Err(err) = tx.send(Message::text(format!("Hello, World! {i}"))).await {
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
