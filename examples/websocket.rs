use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::Message;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    let websocket = rquest::websocket("wss://echo.websocket.org").await?;

    let (mut tx, mut rx) = websocket.split();

    tokio::spawn(async move {
        for i in 1..11 {
            tx.send(Message::Text(format!("Hello, World! #{i}")))
                .await
                .unwrap();
        }
    });

    while let Some(message) = rx.try_next().await? {
        if let Message::Text(text) = message {
            println!("received: {text}")
        }
    }

    Ok(())
}
