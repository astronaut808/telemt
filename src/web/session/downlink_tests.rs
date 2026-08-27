use super::*;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::{
    ProxyConfig, WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::maestro::generation::test_runtime_generation;
use crate::web::manager::WebProcessRuntime;

fn session() -> (Arc<WebSession>, Arc<WebProcessRuntime>) {
    let generation = test_runtime_generation(1, ProxyConfig::default());
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation)));
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
        user: "alice".to_string(),
        secret_mode: WebSecretMode::Plain,
        carrier: WebCarrier::Https,
        carrier_negotiation_enabled: false,
        carrier_learning: false,
        carriers: Arc::from([WebCarrier::Https]),
        carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
        capability: [0; 32],
        key_fingerprint: "0000000000000000".to_string(),
        max_sessions: 1,
        max_streams: 1,
        max_streams_per_session: 1,
    });
    let timeouts = WebTimeoutsConfig {
        long_poll_secs: 1,
        ..WebTimeoutsConfig::default()
    };
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [2; 32],
        WebCarrier::Https,
        1,
        [3; 32],
        None,
        crate::web::manager::CarrierClientClass::Legacy,
        None,
        false,
        WebLimitsConfig::default(),
        timeouts,
    );
    (session, manager)
}

fn queue_close(session: &WebSession) {
    let mut state = session.state.lock();
    assert!(session.queue_control_locked(&mut state, FrameType::Close, 1, &[]));
}

#[tokio::test]
async fn downlink_replays_unacknowledged_batch_byte_for_byte() {
    let (session, manager) = session();
    queue_close(&session);
    let first = session.poll_down(0).await.unwrap();
    let replay = session.poll_down(0).await.unwrap();
    assert_eq!(first.next_cursor, 1);
    assert_eq!(replay.next_cursor, 1);
    assert_eq!(first.body, replay.body);
    drop(first);
    drop(replay);
    session.close();
    manager.shutdown().await;
}

#[tokio::test]
async fn acknowledged_response_stays_resident_until_the_last_body_clone_drops() {
    let (session, manager) = session();
    queue_close(&session);
    let response = session.poll_down(0).await.unwrap();
    let retained = response.body.clone();
    {
        let mut state = session.state.lock();
        session.release_unacked_locked(&mut state);
        assert_eq!(state.pending_bytes, 0);
    }
    assert!(session.resident.snapshot().bytes() > 0);
    drop(response);
    assert!(session.resident.snapshot().bytes() > 0);
    drop(retained);
    assert_eq!(session.resident.snapshot().bytes(), 0);
    session.close();
    manager.shutdown().await;
}

#[tokio::test]
async fn invalid_or_overflowing_cursor_closes_session() {
    let (invalid, invalid_manager) = session();
    assert!(matches!(
        invalid.poll_down(1).await,
        Err(ManagerError::Protocol)
    ));
    assert!(invalid.state.lock().closed);
    invalid_manager.shutdown().await;

    let (overflow, overflow_manager) = session();
    {
        let mut state = overflow.state.lock();
        state.down_cursor = u64::MAX;
    }
    queue_close(&overflow);
    assert!(matches!(
        overflow.poll_down(u64::MAX).await,
        Err(ManagerError::Protocol)
    ));
    assert!(overflow.state.lock().closed);
    overflow_manager.shutdown().await;
}

#[tokio::test]
async fn newer_poll_supersedes_older_poll_without_closing_session() {
    let (session, manager) = session();
    let first_session = Arc::clone(&session);
    let first = tokio::spawn(async move { first_session.poll_down(0).await });
    while session.state.lock().down_epoch < 1 {
        tokio::task::yield_now().await;
    }
    let second_session = Arc::clone(&session);
    let second = tokio::spawn(async move { second_session.poll_down(0).await });
    while session.state.lock().down_epoch < 2 {
        tokio::task::yield_now().await;
    }
    let superseded = tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(superseded.body.is_empty());
    assert_eq!(superseded.next_cursor, 0);
    assert!(!session.state.lock().closed);
    second.abort();
    session.close();
    manager.shutdown().await;
}
