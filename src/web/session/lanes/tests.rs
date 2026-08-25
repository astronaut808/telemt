use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;

use super::*;
use crate::config::{WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig};
use crate::web::manager::WebProcessRuntime;

fn session_with_limits(limits: WebLimitsConfig) -> Arc<WebSession> {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
        user: "alice".to_string(),
        secret_mode: WebSecretMode::Plain,
        carrier: WebCarrier::HttpsLanes,
        capability: [0; 32],
        max_sessions: 1,
        max_streams: 2,
        max_streams_per_session: 2,
    });
    WebSession::new(
        std::sync::Weak::<WebProcessRuntime>::new(),
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        profile,
        [2; 32],
        limits,
        WebTimeoutsConfig::default(),
    )
}

fn session() -> Arc<WebSession> {
    session_with_limits(WebLimitsConfig::default())
}

#[test]
fn lane_uplink_sequences_are_independent_and_exactly_once() {
    let session = session();
    {
        let mut state = session.state.lock();
        for lane_id in [51, 52] {
            state.carrier_lanes.insert(lane_id, CarrierLane::new());
            state.closed_streams.insert(lane_id);
        }
    }
    let first = frame::encode(FrameType::Data, 51, b"first");
    let second = frame::encode(FrameType::Data, 52, b"second");
    assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
    assert_eq!(session.process_up_lane(52, 1, &second), Ok(1));
    assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
    assert_eq!(session.state.lock().carrier_lanes[&52].last_up_sequence, 1);
}

#[test]
fn cross_lane_frame_is_fatal_to_https_lane_session() {
    let session = session();
    let body = frame::encode(FrameType::Data, 52, b"wrong lane");
    assert_eq!(
        session.process_up_lane(51, 1, &body),
        Err(ManagerError::Protocol)
    );
    assert!(session.state.lock().closed);
}

#[tokio::test]
async fn drained_closed_lane_replays_then_signals_completion() {
    let session = session();
    {
        let mut state = session.state.lock();
        state.carrier_lanes.insert(7, CarrierLane::new());
        state.closed_streams.insert(7);
        let lane = state.carrier_lanes.get_mut(&7).unwrap();
        let encoded = frame::encode(FrameType::Close, 7, &[]);
        lane.pending_frames.push_back(QueuedFrame {
            encoded: BytesMut::from(encoded.as_ref()),
            frame_type: FrameType::Close,
            stream_id: 7,
            control: true,
            cost: frame::HEADER_BYTES + QUEUE_ITEM_COST,
        });
    }
    let first = session.poll_down_lane(7, 0).await.unwrap();
    let replay = session.poll_down_lane(7, 0).await.unwrap();
    assert_eq!(first.body, replay.body);
    assert!(!replay.lane_closed);
    let finished = session.poll_down_lane(7, 1).await.unwrap();
    assert!(finished.body.is_empty());
    assert!(finished.lane_closed);
}

#[test]
fn tombstone_eviction_releases_lane_budget_and_accepts_late_frames() {
    let limits = WebLimitsConfig {
        max_tombstones_per_session: 1,
        ..WebLimitsConfig::default()
    };
    let session = session_with_limits(limits);
    {
        let mut state = session.state.lock();
        state.carrier_lanes.insert(7, CarrierLane::new());
        let encoded = frame::encode(FrameType::Close, 7, &[]);
        let cost = encoded.len() + QUEUE_ITEM_COST;
        state
            .carrier_lanes
            .get_mut(&7)
            .unwrap()
            .pending_frames
            .push_back(QueuedFrame {
                encoded: BytesMut::from(encoded.as_ref()),
                frame_type: FrameType::Close,
                stream_id: 7,
                control: true,
                cost,
            });
        state.pending_bytes = cost;
        state.pending_items = 1;
        state.pending_control_bytes = cost;
        state.pending_control_items = 1;
        session.remember_closed_locked(&mut state, 7);
        state.carrier_lanes.insert(8, CarrierLane::new());
        session.remember_closed_locked(&mut state, 8);
        assert!(!state.carrier_lanes.contains_key(&7));
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.pending_items, 0);
    }
    let late = frame::encode(FrameType::Data, 7, b"late");
    assert_eq!(session.process_up_lane(7, 7, &late), Ok(7));
    assert!(!session.state.lock().closed);
}
