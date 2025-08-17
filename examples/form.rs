// Short example of a POST request with form data.
//
// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[tokio::main]
async fn main() {
    let response = wreq::post("http://www.baidu.com")
        .form(&[("one", "1")])
        .send()
        .await
        .expect("send");
    println!("Response status {}", response.status());
}
