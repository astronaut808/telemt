use super::*;

fn store(records_capacity: usize, bytes_capacity: usize) -> Arc<WebTraceStore> {
    let policy = WebDebugConfig {
        enabled: true,
        ..Default::default()
    };
    let limits = WebLimitsConfig {
        debug_records_capacity: records_capacity,
        debug_bytes_global: bytes_capacity,
        ..Default::default()
    };
    WebTraceStore::new(policy, &limits)
}

#[test]
fn ring_evicts_oldest_records_and_snapshot_leases_survive_clear() {
    let store = store(2, 4 * BASE_RECORD_RESERVATION);
    for _ in 0..3 {
        store.record_lifecycle(
            None,
            Some("192.0.2.10".parse().unwrap()),
            TraceIdentity::default(),
            TraceLifecycleEvent::BridgeIssued,
            None,
            None,
        );
    }

    let snapshot = store.snapshot_matching(|_| true);
    assert_eq!(
        snapshot
            .iter()
            .map(|record| record.record.seq)
            .collect::<Vec<_>>(),
        vec![3, 2]
    );
    assert_eq!(store.status().evictions, 1);
    assert_eq!(store.status().used_bytes, 2 * BASE_RECORD_RESERVATION);

    let policy = WebDebugConfig::default();
    store.apply_policy(2, &policy);
    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, 2 * BASE_RECORD_RESERVATION);
    drop(snapshot);
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn capture_policy_epoch_rejects_an_inflight_old_policy_record() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    let request = hyper::Request::builder().uri("/").body(()).unwrap();
    let exchange = store
        .begin_http(&request, "192.0.2.20".parse().unwrap())
        .unwrap();

    let changed = WebDebugConfig {
        enabled: true,
        capture_headers: false,
        ..Default::default()
    };
    store.apply_policy(2, &changed);
    exchange.commit();

    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn stale_generation_cannot_restore_an_old_policy() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    let current = WebDebugConfig {
        enabled: true,
        capture_headers: false,
        ..Default::default()
    };
    store.apply_policy(3, &current);

    store.apply_policy(2, &WebDebugConfig::default());

    let status = store.status();
    assert_eq!(status.policy_generation, 3);
    assert_eq!(status.policy.as_ref(), &current);
}

#[test]
fn explicit_clear_fences_inflight_commits_and_preserves_snapshot_leases() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    store.record_lifecycle(
        None,
        Some("192.0.2.30".parse().unwrap()),
        TraceIdentity::default(),
        TraceLifecycleEvent::BridgeIssued,
        None,
        None,
    );
    let snapshot = store.snapshot_matching(|_| true);
    let request = hyper::Request::builder().uri("/").body(()).unwrap();
    let exchange = store
        .begin_http(&request, "192.0.2.30".parse().unwrap())
        .unwrap();

    let cleared = store.clear();
    exchange.commit();

    assert_eq!(cleared.records_cleared, 1);
    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, BASE_RECORD_RESERVATION);
    drop(snapshot);
    assert_eq!(store.status().used_bytes, 0);
}
