use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::header;
use rquest::{Client, Impersonate, Message, RequestBuilder};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to impersonate Firefox133
    let client = Client::builder()
        .impersonate(Impersonate::Firefox133)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Use the API you're already familiar with
    let websocket = client
        .websocket("wss://127.0.0.1:3000/ws")
        .configure_request(configure_request)
        .http2_only()
        .send()
        .await?;

    assert_eq!(websocket.version(), http::Version::HTTP_2);

    let (mut tx, mut rx) = websocket.into_websocket().await?.split();

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
        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
        .timeout(Duration::from_secs(10))
}
