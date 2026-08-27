use super::*;

async fn request_with_body_delay(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    head: Vec<u8>,
    body: &[u8],
    delay: std::time::Duration,
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
    client.write_all(&head).await.unwrap();
    tokio::time::sleep(delay).await;
    let _ = client.write_all(body).await;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap();
    response
}

#[tokio::test]
async fn live_session_body_and_closed_token_timeouts_survive_reload() {
    let capability = [21u8; 32];
    let mut initial_config = runtime_config(capability, WebCarrier::Https);
    initial_config.web.timeouts.body_secs = 3;
    initial_config.web.timeouts.bootstrap_lifetime_secs = 5;
    let generation = test_runtime_generation(1, initial_config);
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
    let bootstrap = std::str::from_utf8(root_body)
        .unwrap()
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token.to_string())
        .unwrap();
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let create_head = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    let mut create = create_head.clone();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    let (create_headers, _) = split_response(&create_response);
    assert!(create_headers.starts_with(b"HTTP/1.1 200"));
    let session = response_header(create_headers, "x-session-token").to_string();

    let mut replacement_config = runtime_config(capability, WebCarrier::Https);
    replacement_config.web.timeouts.body_secs = 1;
    replacement_config.web.timeouts.bootstrap_lifetime_secs = 1;
    let replacement = test_runtime_generation(2, replacement_config);
    active_runtime.store(Arc::clone(&replacement));

    let retry_response = request_with_body_delay(
        &listener,
        &runtime,
        create_head,
        &hello,
        std::time::Duration::from_millis(1200),
    )
    .await;
    let (retry_headers, _) = split_response(&retry_response);
    assert!(retry_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(retry_headers, "x-session-token"), session);

    let close = format!(
        "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let close_response = request(&listener, &runtime, close.clone()).await;
    assert!(close_response.starts_with(b"HTTP/1.1 204"));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let close_retry_response = request(&listener, &runtime, close).await;
    assert!(close_retry_response.starts_with(b"HTTP/1.1 204"));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
    replacement.stop_sessions().await;
    replacement.stop_background_tasks().await;
}
