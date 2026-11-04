// Short example of a POST request with form data.
//
// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
use std::time::Duration;

use wreq::{Client, rt::tokio::TokioRuntime};

#[tokio::main]
async fn main() {
    let response = Client::new(TokioRuntime)
        .post("http://www.baidu.com")
        .timeout(Duration::from_secs(30))
        .form(&[("one", "1")])
        .send()
        .await
        .expect("send");
    println!("Response status {}", response.status());
}
