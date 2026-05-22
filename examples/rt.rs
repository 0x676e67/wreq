use wreq::{Client, dns};
use wreq_rt::rt;

// Short example of a POST request with form data.
//
// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[compio::main]
async fn main() {
    Client::builder()
        .timer(rt::compio::CompioTimer::new())
        .executor(rt::compio::CompioExecutor::new())
        .dns_resolver(dns::GaiResolver::new())
        .build()
        .expect("build client");

    let response = wreq::post("http://www.baidu.com")
        .send()
        .await
        .expect("send");
    println!("Response status {}", response.status());
}
