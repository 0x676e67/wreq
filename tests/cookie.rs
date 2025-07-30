mod support;
use http::HeaderValue;
use support::server;
use wreq::cookie::{self, Cookie, CookieStore, Jar};

#[tokio::test]
async fn cookie_response_accessor() {
    let server = server::http(move |_req| async move {
        http::Response::builder()
            .header("Set-Cookie", "key=val")
            .header(
                "Set-Cookie",
                "expires=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            )
            .header("Set-Cookie", "path=1; Path=/the-path")
            .header("Set-Cookie", "maxage=1; Max-Age=100")
            .header("Set-Cookie", "domain=1; Domain=mydomain")
            .header("Set-Cookie", "secure=1; Secure")
            .header("Set-Cookie", "httponly=1; HttpOnly")
            .header("Set-Cookie", "samesitelax=1; SameSite=Lax")
            .header("Set-Cookie", "samesitestrict=1; SameSite=Strict")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::new();

    let url = format!("http://{}/", server.addr());
    let res = client.get(&url).send().await.unwrap();

    let cookies = res.cookies().collect::<Vec<_>>();

    // key=val
    assert_eq!(cookies[0].name(), "key");
    assert_eq!(cookies[0].value(), "val");

    // expires
    assert_eq!(cookies[1].name(), "expires");
    assert_eq!(
        cookies[1].expires().unwrap(),
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_445_412_480)
    );

    // path
    assert_eq!(cookies[2].name(), "path");
    assert_eq!(cookies[2].path().unwrap(), "/the-path");

    // max-age
    assert_eq!(cookies[3].name(), "maxage");
    assert_eq!(
        cookies[3].max_age().unwrap(),
        std::time::Duration::from_secs(100)
    );

    // domain
    assert_eq!(cookies[4].name(), "domain");
    assert_eq!(cookies[4].domain().unwrap(), "mydomain");

    // secure
    assert_eq!(cookies[5].name(), "secure");
    assert!(cookies[5].secure());

    // httponly
    assert_eq!(cookies[6].name(), "httponly");
    assert!(cookies[6].http_only());

    // samesitelax
    assert_eq!(cookies[7].name(), "samesitelax");
    assert!(cookies[7].same_site_lax());

    // samesitestrict
    assert_eq!(cookies[8].name(), "samesitestrict");
    assert!(cookies[8].same_site_strict());
}

#[tokio::test]
async fn cookie_store_simple() {
    let server = server::http(move |req| async move {
        if req.uri() == "/2" {
            assert_eq!(req.headers()["cookie"], "key=val");
        }
        http::Response::builder()
            .header("Set-Cookie", "key=val; HttpOnly")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr());
    client.get(&url).send().await.unwrap();

    let url = format!("http://{}/2", server.addr());
    client.get(&url).send().await.unwrap();
}

#[tokio::test]
async fn cookie_store_overwrite_existing() {
    let server = server::http(move |req| async move {
        if req.uri() == "/" {
            http::Response::builder()
                .header("Set-Cookie", "key=val")
                .body(Default::default())
                .unwrap()
        } else if req.uri() == "/2" {
            assert_eq!(req.headers()["cookie"], "key=val");
            http::Response::builder()
                .header("Set-Cookie", "key=val2")
                .body(Default::default())
                .unwrap()
        } else {
            assert_eq!(req.uri(), "/3");
            assert_eq!(req.headers()["cookie"], "key=val2");
            http::Response::default()
        }
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr());
    client.get(&url).send().await.unwrap();

    let url = format!("http://{}/2", server.addr());
    client.get(&url).send().await.unwrap();

    let url = format!("http://{}/3", server.addr());
    client.get(&url).send().await.unwrap();
}

#[tokio::test]
async fn cookie_store_max_age() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers().get("cookie"), None);
        http::Response::builder()
            .header("Set-Cookie", "key=val; Max-Age=0")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();
    let url = format!("http://{}/", server.addr());
    client.get(&url).send().await.unwrap();
    client.get(&url).send().await.unwrap();
}

#[tokio::test]
async fn cookie_store_expires() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers().get("cookie"), None);
        http::Response::builder()
            .header(
                "Set-Cookie",
                "key=val; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            )
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr());
    client.get(&url).send().await.unwrap();
    client.get(&url).send().await.unwrap();
}

#[tokio::test]
async fn cookie_store_path() {
    let server = server::http(move |req| async move {
        if req.uri() == "/" {
            assert_eq!(req.headers().get("cookie"), None);
            http::Response::builder()
                .header("Set-Cookie", "key=val; Path=/subpath")
                .body(Default::default())
                .unwrap()
        } else {
            assert_eq!(req.uri(), "/subpath");
            assert_eq!(req.headers()["cookie"], "key=val");
            http::Response::default()
        }
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr());
    client.get(&url).send().await.unwrap();
    client.get(&url).send().await.unwrap();

    let url = format!("http://{}/subpath", server.addr());
    client.get(&url).send().await.unwrap();
}

#[tokio::test]
async fn cookie_setter() {
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get("cookie"),
            Some(&HeaderValue::from_static("key1=val1"))
        );
        http::Response::builder()
            .header("Set-Cookie", "key2=val2")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr()).parse().unwrap();

    client.set_cookies(&url, [HeaderValue::from_static("key1=val1")]);

    client.get(&url).send().await.unwrap();

    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key1=val1; key2=val2" || value == "key2=val2; key1=val1");
}

#[tokio::test]
async fn clear_cookies() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers().get("cookie"), None);
        http::Response::builder()
            .header("Set-Cookie", "key=val")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr()).parse().unwrap();
    client.get(&url).send().await.unwrap();

    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key=val");

    client.clear_cookies();

    let cookies = client.get_cookies(&url);
    assert!(cookies.is_none());
}

#[tokio::test]
async fn set_cookie() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers().get("cookie"), None);
        http::Response::builder()
            .header("Set-Cookie", "key=val")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr()).parse().unwrap();
    client.get(&url).send().await.unwrap();

    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key=val");
    client.clear_cookies();

    let url = "https://google.com".parse().unwrap();
    let cookie = HeaderValue::from_static("key1=val1");
    client.set_cookie(&url, &cookie);
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key1=val1");
    client.clear_cookies();

    client.set_cookie(&url, cookie);
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key1=val1");
    client.clear_cookies();

    let cookie = Cookie::new("key3", "val3");
    client.set_cookie(&url, cookie);
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key3=val3");
    client.clear_cookies();

    let cookie = Cookie::builder("key4", "val4")
        .domain("google.com")
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(cookie::Duration::hours(1))
        .same_site(cookie::SameSite::Strict)
        .build();

    client.set_cookie(&url, &cookie);
    // The built-in cookie store implementation ignores some cookie attributes
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key4=val4");
    client.clear_cookies();

    client.set_cookie(&url, cookie);
    // The built-in cookie store implementation ignores some cookie attributes
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key4=val4");
    client.clear_cookies();
}

#[tokio::test]
async fn remove_cookie() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers().get("cookie"), None);
        http::Response::builder()
            .header("Set-Cookie", "key=val")
            .body(Default::default())
            .unwrap()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr()).parse().unwrap();
    client.get(&url).send().await.unwrap();

    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key=val");

    client.remove_cookie(&url, "key");

    let cookies = client.get_cookies(&url);
    assert!(cookies.is_none());

    let url = "https://google.com".parse().unwrap();
    client.set_cookies(&url, [HeaderValue::from_static("key=val")]);
    let cookies = client.get_cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert!(value == "key=val");

    client.remove_cookie(&url, "key");

    let cookies = client.get_cookies(&url);
    assert!(cookies.is_none());
}

#[tokio::test]
async fn cookie_string_format() {
    let url = "https://google.com".parse::<url::Url>().unwrap();
    let cookie = Cookie::builder("key", "val")
        .domain("google.com")
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(cookie::Duration::hours(1))
        .same_site(cookie::SameSite::Strict)
        .build();

    let jar = Jar::default();
    jar.set_cookie(&url, &cookie);
    let cookies = jar.cookies(&url).unwrap();
    let value = cookies.to_str().unwrap();
    assert_eq!(value, "key=val");
}

#[tokio::test]
async fn multiple_cookies() {
    let server = server::http(move |req| async move {
        let mut cookies = req.headers().get_all("cookie").iter();
        assert_eq!(cookies.next(), Some(&HeaderValue::from_static("key1=val1")));
        assert_eq!(cookies.next(), Some(&HeaderValue::from_static("key2=val2")));
        http::Response::default()
    });

    let client = wreq::Client::builder().cookie_store(true).build().unwrap();

    let url = format!("http://{}/", server.addr()).parse().unwrap();
    client.set_cookies(
        &url,
        [
            HeaderValue::from_static("key1=val1"),
            HeaderValue::from_static("key2=val2"),
        ],
    );

    client.get(&url).send().await.unwrap();
}
