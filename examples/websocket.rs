use std::time::Duration;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::header;
use rquest::{Client, Impersonate, Message, RequestBuilder};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to impersonate Firefox133
    let client = Client::builder()
        .impersonate(Impersonate::Firefox133)
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://echo.websocket.org")
        .configure_request(configure_request)
        .send()
        .await?
        .into_websocket()
        .await?;

    let (mut tx, mut rx) = websocket.split();

    tokio::spawn(async move {
        for i in 1..11 {
            tx.send(Message::Text(format!("Hello, World! #{i}")))
                .await
                .unwrap();
        }
    });

    while let Some(message) = rx.try_next().await? {
        match message {
            Message::Text(text) => println!("received: {text}"),
            _ => {}
        }
    }

    Ok(())
}

/// We can also set HTTP options here
fn configure_request(builder: RequestBuilder) -> RequestBuilder {
    builder
        .proxy("http://127.0.0.1:6152")
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .timeout(Duration::from_secs(10))
}
