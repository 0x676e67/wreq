use wreq::Client;
use wreq_rt::compio::CompioRuntime;

// Short example of a POST request with form data.
//
// This is using the `compio` runtime. You'll need the following dependency:
//
// `compio = { version = "*", features = ["runtime"] }`
// `wreq-rt = { version = "*", features = ["compio-rt"] }`
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
