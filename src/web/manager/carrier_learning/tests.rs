use super::*;
use crate::web::manager::{CarrierCapabilities, CarrierRequest};

fn request(hash: u8) -> CarrierRequest {
    CarrierRequest::automatic(
        CarrierClientClass::Bridge,
        CarrierCapabilities::all(),
        1,
        None,
        [hash; 32],
    )
}

fn context(hash: u8) -> CarrierLearningContext {
    CarrierLearningContext {
        profile_key: [1; 32],
        client_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, hash)),
        class: CarrierClientClass::Bridge,
        user_agent_hash: [hash; 32],
        epoch: 1,
        ip_learning_eligible: true,
    }
}

#[test]
fn policy_epoch_rejects_late_outcomes_and_clears_state() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    learning.record_chain(now, epoch, context(1), &[], WebCarrier::Websocket);
    assert_eq!(learning.entries.len(), 3);
    let next = learning
        .apply_policy(
            now,
            false,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    assert_ne!(epoch, next);
    learning.record_chain(now, epoch, context(1), &[], WebCarrier::Https);
    assert!(learning.entries.is_empty());
}

#[test]
fn aggressive_policy_ranks_one_atomic_chain_sample() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    learning.record_chain(now, epoch, context(2), &[], WebCarrier::Websocket);
    let (ranked, scores) = learning.rank(
        now,
        &[
            WebCarrier::Https,
            WebCarrier::Websocket,
            WebCarrier::HttpsLanes,
        ],
        request(2),
        [1; 32],
        context(2).client_ip,
        true,
    );
    assert_eq!(
        ranked,
        [
            WebCarrier::Websocket,
            WebCarrier::Https,
            WebCarrier::HttpsLanes,
        ]
    );
    assert_eq!(scores[WebCarrier::Websocket.index()], 33);
}

#[test]
fn two_half_windows_expire_without_sliding_updates() {
    let start = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = learning
        .apply_policy(
            start,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    learning.record_chain(start, epoch, context(3), &[], WebCarrier::Websocket);
    learning.record_chain(
        start + Duration::from_secs(6),
        epoch,
        context(3),
        &[],
        WebCarrier::Websocket,
    );
    learning.prune(start + Duration::from_secs(11));
    assert_eq!(learning.entries.len(), 3);
    learning.prune(start + Duration::from_secs(16));
    assert!(learning.entries.is_empty());
}

#[test]
fn exhausted_epoch_and_insertion_identifiers_fail_closed() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    learning.epoch = Some(u64::MAX);
    assert_eq!(
        learning.apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        ),
        None
    );
    learning.record_chain(now, u64::MAX, context(4), &[], WebCarrier::Https);
    assert!(learning.entries.is_empty());

    learning.epoch = Some(1);
    learning.insertion_sequence = u64::MAX;
    learning.record_chain(now, 1, context(4), &[], WebCarrier::Https);
    assert!(learning.entries.is_empty());
}

#[test]
fn client_reported_failures_do_not_create_negative_evidence() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let epoch = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    learning.record_chain(
        now,
        epoch,
        context(5),
        &[WebCarrier::Websocket],
        WebCarrier::Https,
    );
    let (_, scores) = learning.rank(
        now,
        &[WebCarrier::Websocket, WebCarrier::HttpsLanes],
        request(5),
        [1; 32],
        context(5).client_ip,
        true,
    );
    assert_eq!(scores[WebCarrier::Websocket.index()], 0);
}

#[test]
fn old_new_old_policy_rejects_both_stale_epochs() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let old = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    let middle = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Balanced,
            Duration::from_secs(10),
        )
        .unwrap();
    let current = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    assert_ne!(old, middle);
    assert_ne!(middle, current);
    assert_ne!(old, current);
    learning.record_chain(now, old, context(6), &[], WebCarrier::Https);
    learning.record_chain(now, middle, context(6), &[], WebCarrier::Https);
    assert!(learning.entries.is_empty());
    learning.record_chain(now, current, context(6), &[], WebCarrier::Https);
    assert_eq!(learning.entries.len(), 3);
}

#[test]
fn fifo_metadata_stays_within_the_entry_capacity() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let epoch = learning
        .apply_policy(
            now,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
        )
        .unwrap();
    for hash in 1..=32 {
        learning.record_chain(now, epoch, context(hash), &[], WebCarrier::Https);
        assert!(learning.entries.len() <= 3);
        assert!(learning.insertion_order.len() <= 3);
    }
}

#[tokio::test]
async fn explicit_reset_preserves_policy_and_rejects_old_epoch_outcomes() {
    let generation = crate::maestro::generation::test_runtime_generation(
        1,
        crate::config::ProxyConfig::default(),
    );
    let runtime = crate::web::manager::WebProcessRuntime::start(std::sync::Arc::new(
        arc_swap::ArcSwap::from(generation.clone()),
    ));
    let now = Instant::now();
    let old_epoch = {
        let mut learning = runtime.learning.lock();
        let epoch = learning
            .apply_policy(
                now,
                true,
                WebCarrierNegotiationAggressiveness::Aggressive,
                Duration::from_secs(10),
            )
            .unwrap();
        learning.record_chain(now, epoch, context(7), &[], WebCarrier::Websocket);
        epoch
    };

    let outcome = runtime.reset_carrier_learning().unwrap();
    {
        let mut learning = runtime.learning.lock();
        learning.record_chain(
            Instant::now(),
            old_epoch,
            context(7),
            &[],
            WebCarrier::Https,
        );
        let status = learning.status(Instant::now());
        assert!(status.enabled);
        assert_eq!(
            status.aggressiveness,
            WebCarrierNegotiationAggressiveness::Aggressive
        );
        assert_eq!(status.entries, 0);
        assert_eq!(status.epoch, Some(outcome.epoch));
    }

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
