use futures_util::{SinkExt, StreamExt, TryStreamExt};
use wreq::{header, ws::message::Message};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Use the API you're already familiar with
    let resp = wreq::websocket("wss://echo.websocket.org")
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .read_buffer_size(1024 * 1024)
        .send()
        .await?;

    assert_eq!(resp.version(), http::Version::HTTP_11);

    let websocket = resp.into_websocket().await?;
    if let Some(protocol) = websocket.protocol() {
        println!("WebSocket subprotocol: {:?}", protocol);
    }

    let (mut tx, mut rx) = websocket.split();

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
