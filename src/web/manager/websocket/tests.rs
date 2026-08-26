use super::*;

fn entry(kind: WebSocketKind, opened: bool, peer_tick: u64) -> WebSocketEntry {
    let phase = if opened {
        WebSocketPhase::Active
    } else {
        WebSocketPhase::Claimed
    };
    WebSocketEntry {
        id: 1,
        owner: [0; 32],
        session_id: 1,
        claim: WebSocketClaimKey {
            session_hash: [0; 32],
            kind,
        },
        client_ip: "192.0.2.10".parse().unwrap(),
        kind,
        liveness_interval_ms: 10,
        created_tick: 1,
        last_peer_tick: AtomicU64::new(peer_tick),
        last_progress_tick: AtomicU64::new(peer_tick),
        phase: AtomicU8::new(phase as u8),
        closing: AtomicBool::new(false),
        cancel: CancellationToken::new(),
        released: CancellationToken::new(),
    }
}

#[test]
fn preopen_and_dead_entries_precede_live_lane_and_multiplex_victims() {
    let preopen = entry(WebSocketKind::Multiplex, false, 90);
    let dead = entry(WebSocketKind::Multiplex, true, 1);
    let lane = entry(WebSocketKind::Lane(7), true, 90);
    let multiplex = entry(WebSocketKind::Multiplex, true, 90);

    assert_eq!(entry_priority(&preopen, 100), 0);
    assert_eq!(entry_priority(&dead, 100), 0);
    assert_eq!(entry_priority(&lane, 100), 1);
    assert_eq!(entry_priority(&multiplex, 100), 2);
}

#[test]
fn dead_classification_keeps_each_connections_creation_time_interval() {
    let short_interval = entry(WebSocketKind::Multiplex, true, 80);
    let mut long_interval = entry(WebSocketKind::Multiplex, true, 80);
    long_interval.liveness_interval_ms = 100;

    assert_eq!(entry_priority(&short_interval, 100), 0);
    assert_eq!(entry_priority(&long_interval, 100), 2);
}
