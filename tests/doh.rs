mod support;

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use hickory_proto::{
    op::{Message, OpCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use http_body_util::BodyExt;
use support::server;
use wreq::{Client, dns::DohResolver};

/// Answers A queries for `app.test.` with 127.0.0.1 and returns an empty answer
/// for everything else.
fn doh_server(hits: Arc<AtomicUsize>) -> server::Server {
    server::http(move |req| {
        let hits = hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], "application/dns-message");
            assert_eq!(req.headers()["accept"], "application/dns-message");

            let body = req.into_body().collect().await.unwrap().to_bytes();
            let request = Message::from_vec(&body).unwrap();
            assert_eq!(request.metadata.id, 0);

            let query = request.queries[0].clone();
            let mut response = Message::response(0, OpCode::Query);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;

            if query.name().to_ascii() == "app.test." && query.query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    300,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
            }
            response.add_query(query);

            http::Response::builder()
                .header("content-type", "application/dns-message")
                .body(response.to_vec().unwrap().into())
                .unwrap()
        }
    })
}

fn resolver(doh: &server::Server, strict: bool) -> DohResolver {
    // `doh.test` only resolves through the bootstrap address.
    DohResolver::builder()
        .endpoint(format!("http://doh.test:{}/dns-query", doh.addr().port()))
        .bootstrap([IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .strict(strict)
        .build()
        .unwrap()
}

#[tokio::test]
async fn resolves_and_caches() {
    let hits = Arc::new(AtomicUsize::new(0));
    let doh = doh_server(hits.clone());
    let app = server::http(|_| async { http::Response::new("ok".into()) });
    let resolver = resolver(&doh, true);
    let url = format!("http://app.test:{}/", app.addr().port());

    // Separate clients do not share a connection pool, so each request has to
    // resolve the name. Only the first one should reach the DoH server.
    for _ in 0..2 {
        let client = Client::builder()
            .dns_resolver(resolver.clone())
            .no_proxy()
            .build()
            .unwrap();
        let text = client.get(&url).send().await.unwrap().text().await.unwrap();
        assert_eq!(text, "ok");
        // One A and one AAAA query.
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn concurrent_lookups_share_one_query() {
    use wreq::dns::{Name, Resolve};

    let hits = Arc::new(AtomicUsize::new(0));
    let doh = doh_server(hits.clone());
    let resolver = resolver(&doh, true);

    let lookups = (0..8).map(|_| resolver.resolve(Name::from("app.test")));
    for addrs in futures::future::join_all(lookups).await {
        let addrs: Vec<_> = addrs.unwrap().collect();
        assert_eq!(addrs, [(Ipv4Addr::LOCALHOST, 0).into()]);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

fn failing_server(hits: Arc<AtomicUsize>) -> server::Server {
    server::http(move |_| {
        hits.fetch_add(1, Ordering::SeqCst);
        async {
            http::Response::builder()
                .status(503)
                .body(wreq::Body::default())
                .unwrap()
        }
    })
}

#[tokio::test]
async fn failed_queries_are_not_cached() {
    use wreq::dns::{Name, Resolve};

    let hits = Arc::new(AtomicUsize::new(0));
    let doh = failing_server(hits.clone());
    let resolver = resolver(&doh, true);

    assert!(resolver.resolve(Name::from("app.test")).await.is_err());
    assert!(resolver.resolve(Name::from("app.test")).await.is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn falls_back_to_system_dns() {
    use wreq::dns::{Name, Resolve};

    let hits = Arc::new(AtomicUsize::new(0));
    let doh = failing_server(hits.clone());

    let addrs: Vec<_> = resolver(&doh, false)
        .resolve(Name::from("localhost"))
        .await
        .unwrap()
        .collect();
    assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
    assert!(!addrs.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn no_fallback_for_missing_names() {
    use wreq::dns::{Name, Resolve};

    let hits = Arc::new(AtomicUsize::new(0));
    let doh = doh_server(hits.clone());

    // The DoH server answers with no records, so the system resolver must not
    // be asked even though `localhost` would resolve there.
    let result = resolver(&doh, false).resolve(Name::from("localhost")).await;
    assert!(result.is_err());
}
