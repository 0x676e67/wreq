//! This example illustrates the way to send and receive arbitrary JSON.
//!
//! This is useful for some ad-hoc experiments and situations when you don't
//! really care about the structure of the JSON and just need to display it or
//! process it at runtime.

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
use std::time::Duration;

use wreq::{Client, rt::tokio::TokioRuntime};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let echo_json: serde_json::Value = Client::new(TokioRuntime)
        .post("https://jsonplaceholder.typicode.com/posts")
        .timeout(Duration::from_secs(30))
        .json(&serde_json::json!({
            "title": "wreq.rs",
            "body": "https://docs.rs/wreq",
            "userId": 1
        }))
        .send()
        .await?
        .json()
        .await?;

    println!("{echo_json:#?}");
    // Object(
    //     {
    //         "body": String(
    //             "https://docs.rs/wreq"
    //         ),
    //         "id": Number(
    //             101
    //         ),
    //         "title": String(
    //             "wreq.rs"
    //         ),
    //         "userId": Number(
    //             1
    //         )
    //     }
    // )
    Ok(())
}
