use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::watch;

use super::*;
use crate::config::{ProxyConfig, WebRuntimeConfig, WebRuntimeProfile, WebSecretMode};
use crate::maestro::generation::{RuntimeGeneration, test_runtime_generation_with_admission};
use crate::web::frame::FrameType;
use crate::web::manager::WebProcessRuntime;

struct TestRuntime {
    session: Arc<WebSession>,
    manager: Arc<WebProcessRuntime>,
    generation: Arc<RuntimeGeneration>,
}

impl TestRuntime {
    async fn shutdown(self) {
        self.session.close();
        self.session.wait().await;
        self.manager.shutdown().await;
        self.generation.stop_sessions().await;
        self.generation.stop_background_tasks().await;
    }
}

fn runtime(admission: bool) -> TestRuntime {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        public_addr: "203.0.113.10:443".parse().unwrap(),
        user: "default".to_string(),
        secret_mode: WebSecretMode::Plain,
        carrier: WebCarrier::WebsocketLanes,
        capability: [7; 32],
        key_fingerprint: "0000000000000000".to_string(),
        max_sessions: 2,
        max_streams: 1,
        max_streams_per_session: 1,
    });
    let mut config = ProxyConfig::default();
    config.web.enabled = true;
    config.web.carrier = WebCarrier::WebsocketLanes;
    config.web.timeouts.shutdown_secs = 1;
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts: BTreeMap::new(),
        profiles: vec![Arc::clone(&profile)],
    }));
    config.rebuild_runtime_user_auth().unwrap();
    let limits = config.web.limits.clone();
    let timeouts = config.web.timeouts.clone();
    let (_admission_tx, admission_rx) = watch::channel(admission);
    let generation = test_runtime_generation_with_admission(1, config, admission_rx);
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [8; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [7; 32],
        limits,
        timeouts,
    );
    TestRuntime {
        session,
        manager,
        generation,
    }
}

#[tokio::test]
async fn rejected_open_retains_stream_quota_until_lane_socket_teardown() {
    let runtime = runtime(false);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    let open = frame::encode(FrameType::Open, 7, &[]);

    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &open),
        Err(ManagerError::Limit),
    );
    assert!(
        runtime
            .manager
            .try_acquire_stream(
                runtime.session.profile_key,
                runtime.session.profile.max_streams,
                runtime.session.client_ip,
                runtime.session.profile.public_addr,
            )
            .is_none()
    );

    runtime.session.close_websocket_lane(7);
    drop(reservation);
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.public_addr,
        )
        .unwrap();
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn malformed_lane_message_does_not_close_sibling_session_state() {
    let runtime = runtime(true);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    let data = frame::encode(FrameType::Data, 7, &[1]);

    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &data),
        Err(ManagerError::Protocol),
    );
    assert!(!runtime.session.state.lock().closed);

    runtime.session.close_websocket_lane(7);
    drop(reservation);
    assert!(runtime.session.reserve_websocket_lane(8).is_ok());
    runtime.shutdown().await;
}
