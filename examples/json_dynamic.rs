//! This example illustrates the way to send and receive arbitrary JSON.
//!
//! This is useful for some ad-hoc experiments and situations when you don't
//! really care about the structure of the JSON and just need to display it or
//! process it at runtime.

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[tokio::main]
async fn main() -> wreq::Result<()> {
    let echo_json: serde_json::Value = wreq::post("https://jsonplaceholder.typicode.com/posts")
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
