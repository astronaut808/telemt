use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    AdmissionDecision, DispatchAction, DispatchFeedback, PressureState, SchedulerDecision,
    WorkerFairnessConfig, WorkerFairnessState,
};

#[test]
fn single_large_stale_flow_is_not_penalized_without_worker_pressure() {
    let now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            base_quantum_bytes: 128 * 1024,
            penalized_quantum_bytes: 8 * 1024,
            pressured_quantum_bytes: 64 * 1024,
            standing_queue_min_age: Duration::from_millis(10),
            standing_queue_min_backlog_bytes: 64 * 1024,
            standing_stall_threshold: 3,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    assert_eq!(
        fairness.enqueue_data(1, 0, Bytes::from(vec![0u8; 96 * 1024]), now),
        AdmissionDecision::Admit
    );

    let decision = fairness.next_decision(now + Duration::from_millis(20));
    match decision {
        SchedulerDecision::Dispatch(candidate) => {
            assert_eq!(candidate.frame.conn_id, 1);
            assert_eq!(candidate.pressure_state, PressureState::Normal);
        }
        SchedulerDecision::Idle => {
            panic!("single stale flow was penalized without worker pressure")
        }
    }
}

#[test]
fn repeated_stalls_still_escalate_large_flow_into_backpressured_mode() {
    let now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            base_quantum_bytes: 128 * 1024,
            penalized_quantum_bytes: 8 * 1024,
            pressured_quantum_bytes: 64 * 1024,
            standing_queue_min_age: Duration::from_millis(10),
            standing_queue_min_backlog_bytes: 64 * 1024,
            standing_stall_threshold: 1,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    assert_eq!(
        fairness.enqueue_data(7, 0, Bytes::from(vec![0u8; 96 * 1024]), now),
        AdmissionDecision::Admit
    );

    let first = match fairness.next_decision(now + Duration::from_millis(20)) {
        SchedulerDecision::Dispatch(candidate) => candidate,
        SchedulerDecision::Idle => panic!("initial dispatch must be available"),
    };
    assert_eq!(first.frame.conn_id, 7);

    let action = fairness.apply_dispatch_feedback(
        7,
        first,
        DispatchFeedback::QueueFull,
        now + Duration::from_millis(21),
    );
    assert_eq!(action, DispatchAction::Continue);

    let snapshot = fairness.snapshot();
    assert_eq!(snapshot.backpressured_flows, 1);

    match fairness.next_decision(now + Duration::from_millis(22)) {
        SchedulerDecision::Idle => {}
        SchedulerDecision::Dispatch(_) => {
            panic!("stalled flow should not immediately bypass penalized scheduling")
        }
    }
}
