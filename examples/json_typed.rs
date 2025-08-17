//! This example illustrates the way to send and receive statically typed JSON.
//!
//! In contrast to the arbitrary JSON example, this brings up the full power of
//! Rust compile-time type system guaranties though it requires a little bit
//! more code.

// These require the `serde` dependency.
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Post {
    id: Option<i32>,
    title: String,
    body: String,
    #[serde(rename = "userId")]
    user_id: i32,
}

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[tokio::main]
async fn main() -> wreq::Result<()> {
    let new_post = Post {
        id: None,
        title: "wreq.rs".into(),
        body: "https://docs.rs/wreq".into(),
        user_id: 1,
    };
    let new_post: Post = wreq::post("https://jsonplaceholder.typicode.com/posts")
        .json(&new_post)
        .send()
        .await?
        .json()
        .await?;

    println!("{new_post:#?}");
    // Post {
    //     id: Some(
    //         101
    //     ),
    //     title: "wreq.rs",
    //     body: "https://docs.rs/wreq",
    //     user_id: 1
    // }
    Ok(())
}
