use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::header;
use rquest::{Client, Message, Utf8Bytes};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://echo.websocket.org")
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .send()
        .await?;

    assert_eq!(websocket.version(), http::Version::HTTP_11);

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
