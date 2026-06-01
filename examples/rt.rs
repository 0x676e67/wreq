use wreq::Client;
use wreq_rt::compio::CompioRuntime;

// Short example of a POST request with form data.
//
// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[compio::main]
async fn main() {
    let client = Client::builder()
        .runtime(CompioRuntime::new())
        .build()
        .expect("build client");

    let response = client
        .post("http://www.baidu.com")
        .send()
        .await
        .expect("send");
    println!("Response status {}", response.status());
}
