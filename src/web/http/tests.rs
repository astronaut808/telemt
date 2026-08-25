use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine as _;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use super::serve_connection;
use crate::config::{
    ProxyConfig, WebCarrier, WebClientIpSource, WebRuntimeConfig, WebRuntimeDecoy,
    WebRuntimeProfile, WebRuntimeVhost, WebSecretMode, WebStaticAsset, WebStaticSite,
};
use crate::maestro::generation::test_runtime_generation;
use crate::web::frame::{self, FrameType};
use crate::web::manager::WebProcessRuntime;

fn runtime_config(capability: [u8; 32], carrier: WebCarrier) -> ProxyConfig {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        public_addr: "203.0.113.10:443".parse().unwrap(),
        user: "alice".to_string(),
        secret_mode: WebSecretMode::Plain,
        carrier,
        capability,
        max_sessions: 4,
        max_streams: 16,
        max_streams_per_session: 4,
    });
    let mut assets = BTreeMap::new();
    assets.insert(
        "/index.html".to_string(),
        WebStaticAsset {
            body: Bytes::from_static(b"<!doctype html><title>decoy</title>"),
            content_type: "text/html; charset=utf-8",
            etag: "\"test\"".to_string(),
        },
    );
    let site = Arc::new(WebStaticSite {
        assets,
        index: "index.html".to_string(),
    });
    let vhost = Arc::new(WebRuntimeVhost {
        host: "proxy.example.com".to_string(),
        decoy: WebRuntimeDecoy::StaticDirectory(Arc::clone(&site)),
        decoy_header_secs: 1,
        profiles: vec![Arc::clone(&profile)],
    });
    let mut vhosts = BTreeMap::new();
    vhosts.insert("proxy.example.com".to_string(), vhost);
    vhosts.insert(
        "other.example.com".to_string(),
        Arc::new(WebRuntimeVhost {
            host: "other.example.com".to_string(),
            decoy: WebRuntimeDecoy::StaticDirectory(site),
            decoy_header_secs: 1,
            profiles: Vec::new(),
        }),
    );
    let mut config = ProxyConfig::default();
    config.web.enabled = true;
    config.web.carrier = carrier;
    config.web.limits.max_bootstraps_per_ip = 1;
    config.web.timeouts.shutdown_secs = 1;
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts,
        profiles: vec![profile],
    }));
    config
}

async fn request(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    request: Vec<u8>,
) -> Vec<u8> {
    let addr = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    let task = tokio::spawn(serve_connection(
        server,
        peer,
        WebClientIpSource::XForwardedFor,
        Arc::from(["127.0.0.1/32".parse().unwrap()]),
        Arc::clone(runtime),
        CancellationToken::new(),
        permit,
    ));
    client.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap();
    response
}

fn split_response(response: &[u8]) -> (&[u8], &[u8]) {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    (&response[..separator], &response[separator + 4..])
}

fn response_header<'a>(headers: &'a [u8], name: &str) -> &'a str {
    std::str::from_utf8(headers)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.trim()))
        .unwrap()
}

#[tokio::test]
async fn https_carrier_bootstraps_and_closes_one_session() {
    let capability = [7u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (root_headers, root_body) = split_response(&root_response);
    assert!(root_headers.starts_with(b"HTTP/1.1 200"));
    let root_body = std::str::from_utf8(root_body).unwrap();
    let bootstrap = root_body
        .split_once("bootstrap='")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(token, _)| token)
        .unwrap();
    assert_eq!(bootstrap.len(), 43);

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut wrong_host = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: other.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    wrong_host.extend_from_slice(&hello);
    let wrong_host_response = request(&listener, &runtime, wrong_host).await;
    assert!(wrong_host_response.starts_with(b"HTTP/1.1 404"));

    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    let create_retry = create.clone();
    create.extend_from_slice(&hello);
    let mut create_retry = create_retry;
    create_retry.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    let (create_headers, create_body) = split_response(&create_response);
    assert!(create_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(create_headers, "x-carrier-mode"), "https");
    assert_eq!(create_body, frame::encode(FrameType::Welcome, 0, &[]));
    let session = response_header(create_headers, "x-session-token");
    assert_eq!(session.len(), 43);

    let replacement =
        test_runtime_generation(2, runtime_config(capability, WebCarrier::HttpsLanes));
    active_runtime.store(Arc::clone(&replacement));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let retry_response = request(&listener, &runtime, create_retry).await;
    let (retry_headers, retry_body) = split_response(&retry_response);
    assert!(retry_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(retry_headers, "x-session-token"), session);
    assert_eq!(response_header(retry_headers, "x-carrier-mode"), "https");
    assert_eq!(retry_body, frame::encode(FrameType::Welcome, 0, &[]));

    let next_root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let next_root_response = request(&listener, &runtime, next_root).await;
    let (_, next_root_body) = split_response(&next_root_response);
    assert!(
        next_root_body
            .windows(11)
            .any(|value| value == b"bootstrap='")
    );
    assert!(
        next_root_body
            .windows(21)
            .any(|value| value == b"carrier='https-lanes'")
    );

    let close = format!(
        "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let close_retry = close.clone();
    let close_response = request(&listener, &runtime, close).await;
    assert!(close_response.starts_with(b"HTTP/1.1 204"));
    let close_retry_response = request(&listener, &runtime, close_retry).await;
    assert!(close_retry_response.starts_with(b"HTTP/1.1 204"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}

#[tokio::test]
async fn bootstrap_survives_client_address_family_change() {
    let capability = [8u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 2001:db8::10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (_, root_body) = split_response(&root_response);
    let root_body = std::str::from_utf8(root_body).unwrap();
    let bootstrap = root_body
        .split_once("bootstrap='")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(token, _)| token)
        .unwrap();

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    assert!(create_response.starts_with(b"HTTP/1.1 200"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn unused_bootstrap_survives_equivalent_runtime_generation_swap() {
    let capability = [10u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (_, root_body) = split_response(&root_response);
    let root_body = std::str::from_utf8(root_body).unwrap();
    let bootstrap = root_body
        .split_once("bootstrap='")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(token, _)| token)
        .unwrap();

    let replacement = test_runtime_generation(2, runtime_config(capability, WebCarrier::Https));
    active_runtime.store(Arc::clone(&replacement));
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    assert!(create_response.starts_with(b"HTTP/1.1 200"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}

#[tokio::test]
async fn unused_bootstrap_is_rejected_after_profile_identity_change() {
    let capability = [11u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (_, root_body) = split_response(&root_response);
    let root_body = std::str::from_utf8(root_body).unwrap();
    let bootstrap = root_body
        .split_once("bootstrap='")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(token, _)| token)
        .unwrap();

    let replacement =
        test_runtime_generation(2, runtime_config(capability, WebCarrier::HttpsLanes));
    active_runtime.store(Arc::clone(&replacement));
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    assert!(!create_response.starts_with(b"HTTP/1.1 200"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}

#[tokio::test]
async fn https_lanes_is_advertised_and_requires_canonical_lane_headers() {
    let capability = [9u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::HttpsLanes));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (_, root_body) = split_response(&root_response);
    let root_body = std::str::from_utf8(root_body).unwrap();
    assert!(root_body.contains("carrier='https-lanes'"));
    let bootstrap = root_body
        .split_once("bootstrap='")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(token, _)| token)
        .unwrap();

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    let (create_headers, _) = split_response(&create_response);
    assert_eq!(
        response_header(create_headers, "x-carrier-mode"),
        "https-lanes"
    );
    let session = response_header(create_headers, "x-session-token").to_string();

    let pong = frame::encode(FrameType::Pong, 0, &[]);
    let mut uplink = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nX-Lane-ID: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pong.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&pong);
    let uplink_response = request(&listener, &runtime, uplink).await;
    let (uplink_headers, _) = split_response(&uplink_response);
    assert!(uplink_headers.starts_with(b"HTTP/1.1 204"));
    assert_eq!(response_header(uplink_headers, "x-up-ack"), "1");
    assert!(
        !std::str::from_utf8(uplink_headers)
            .unwrap()
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("content-length:"))
    );

    let mut missing_lane = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pong.len()
    )
    .into_bytes();
    missing_lane.extend_from_slice(&pong);
    let missing_lane_response = request(&listener, &runtime, missing_lane).await;
    assert!(!missing_lane_response.starts_with(b"HTTP/1.1 204"));

    let mut aliased_lane = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 2\r\nX-Lane-ID: 00\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pong.len()
    )
    .into_bytes();
    aliased_lane.extend_from_slice(&pong);
    let aliased_lane_response = request(&listener, &runtime, aliased_lane).await;
    assert!(!aliased_lane_response.starts_with(b"HTTP/1.1 204"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn windows_restricted_webview_empty_cookie_preserves_the_carrier_flow() {
    for (index, carrier) in [WebCarrier::Https, WebCarrier::HttpsLanes]
        .into_iter()
        .enumerate()
    {
        let capability = [12 + index as u8; 32];
        let mut config = runtime_config(capability, carrier);
        config.web.timeouts.long_poll_secs = 0;
        let generation = test_runtime_generation(1, config);
        let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
        let runtime = WebProcessRuntime::start(active_runtime);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
        let root = format!(
            "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nCookie:\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let root_response = request(&listener, &runtime, root).await;
        let (root_headers, root_body) = split_response(&root_response);
        assert!(root_headers.starts_with(b"HTTP/1.1 200"));
        let root_body = std::str::from_utf8(root_body).unwrap();
        let bootstrap = root_body
            .split_once("bootstrap='")
            .and_then(|(_, suffix)| suffix.split_once('\''))
            .map(|(token, _)| token)
            .unwrap();

        let hello = frame::encode(FrameType::Hello, 0, &[1]);
        let create = |cookie: &str| {
            let mut request = format!(
                "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n",
                hello.len()
            )
            .into_bytes();
            request.extend_from_slice(&hello);
            request
        };
        let nonempty_cookie =
            request(&listener, &runtime, create("Cookie: state=unexpected\r\n")).await;
        assert!(!nonempty_cookie.starts_with(b"HTTP/1.1 200"));
        let duplicate_cookie = request(
            &listener,
            &runtime,
            create("Cookie:\r\nCookie: state=unexpected\r\n"),
        )
        .await;
        assert!(!duplicate_cookie.starts_with(b"HTTP/1.1 200"));

        let create_response = request(&listener, &runtime, create("Cookie:\r\n")).await;
        let (create_headers, create_body) = split_response(&create_response);
        assert!(create_headers.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            response_header(create_headers, "x-carrier-mode"),
            carrier.as_str()
        );
        assert_eq!(create_body, frame::encode(FrameType::Welcome, 0, &[]));
        let session = response_header(create_headers, "x-session-token").to_string();
        let lane = (carrier == WebCarrier::HttpsLanes)
            .then_some("X-Lane-ID: 0\r\n")
            .unwrap_or_default();

        let pong = frame::encode(FrameType::Pong, 0, &[]);
        let mut uplink = format!(
            "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nCookie:\r\nX-Up-Seq: 1\r\n{lane}Content-Length: {}\r\nConnection: close\r\n\r\n",
            pong.len()
        )
        .into_bytes();
        uplink.extend_from_slice(&pong);
        let uplink_response = request(&listener, &runtime, uplink).await;
        let (uplink_headers, _) = split_response(&uplink_response);
        assert!(uplink_headers.starts_with(b"HTTP/1.1 204"));
        assert_eq!(response_header(uplink_headers, "x-up-ack"), "1");

        let downlink = format!(
            "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nCookie:\r\nX-Down-Cursor: 0\r\n{lane}Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let downlink_response = request(&listener, &runtime, downlink).await;
        let (downlink_headers, _) = split_response(&downlink_response);
        assert!(downlink_headers.starts_with(b"HTTP/1.1 204"));
        assert_eq!(response_header(downlink_headers, "x-down-cursor"), "0");

        let close = format!(
            "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nCookie:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let close_response = request(&listener, &runtime, close).await;
        assert!(close_response.starts_with(b"HTTP/1.1 204"));

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
