use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rquest::{tls::Impersonate, Client, Message, Proxy};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // Build a client to mimic Chrome130
    let websocket = Client::builder()
        .impersonate(Impersonate::Chrome130)
        .proxy(Proxy::https("socks5h://gngpp:gngpp123@127.0.0.1:1080")?)
        .build()?
        .websocket("wss://echo.websocket.org")
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
