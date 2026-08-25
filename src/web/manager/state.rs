use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{ProfileKey, TOKEN_BYTES, TokenHash};
use crate::config::{WebLimitsConfig, WebRuntimeConfig, WebRuntimeProfile};
use crate::maestro::generation::RuntimeGeneration;
use crate::web::session::WebSession;

/// One issued bootstrap and optional idempotent session-creation replay state.
pub(super) struct Bootstrap {
    /// Credential and replay-state expiry deadline.
    pub(super) expires_at: Instant,
    /// Stable ordering point used for bounded eviction.
    pub(super) issued_at: Instant,
    /// Issuing address charged for the unused-bootstrap quota.
    pub(super) issuance_ip: IpAddr,
    /// Immutable profile selected during capability validation.
    pub(super) profile: Arc<WebRuntimeProfile>,
    /// Digest of the accepted HELLO body for idempotent retry matching.
    pub(super) body_digest: TokenHash,
    /// Zeroizing copy returned only for an exact session-creation retry.
    pub(super) session_token: Zeroizing<String>,
    /// Created session retained while retry replay remains valid.
    pub(super) session: Option<Arc<WebSession>>,
    /// Distinguishes unused issuance quota from completed creation replay state.
    pub(super) used: bool,
}

/// Bounded replay marker for one explicitly or naturally closed session token.
pub(super) struct ClosedToken {
    /// Deadline after which the token hash may be forgotten.
    pub(super) expires_at: Instant,
    /// Canonical host that owned the session.
    pub(super) host: String,
}

/// Token-bucket state for one process-wide creation class.
#[derive(Default)]
pub(super) struct RateState {
    tokens: f64,
    last: Option<Instant>,
}

struct StreamPortState {
    active: HashSet<u16>,
    next: u16,
}

/// Process-wide WEB registries and quota accounting protected by one short lock.
#[derive(Default)]
pub(super) struct ManagerState {
    /// Bootstrap credentials indexed by their SHA-256 token hash.
    pub(super) bootstraps: HashMap<TokenHash, Bootstrap>,
    /// Unused bootstrap ownership counts by forwarded client address.
    pub(super) bootstraps_per_ip: HashMap<IpAddr, usize>,
    /// Live sessions indexed by bearer-token hash.
    pub(super) sessions: HashMap<TokenHash, Arc<WebSession>>,
    /// Recently closed token hashes retained for idempotent DELETE semantics.
    pub(super) closed_tokens: HashMap<TokenHash, ClosedToken>,
    /// Live session counts by forwarded client address.
    pub(super) sessions_per_ip: HashMap<IpAddr, usize>,
    /// Live session counts by stable profile key.
    pub(super) sessions_per_profile: HashMap<ProfileKey, usize>,
    /// Live relay-task counts by stable profile key.
    pub(super) streams_per_profile: HashMap<ProfileKey, usize>,
    /// Process-wide live relay-task count.
    pub(super) streams_live: usize,
    stream_ports: HashMap<(IpAddr, SocketAddr), StreamPortState>,
    /// Total process-wide queued byte reservation.
    pub(super) pending_bytes: usize,
    /// Total process-wide queued item reservation.
    pub(super) pending_items: usize,
    /// Portion of queued bytes charged to the control reserve.
    pub(super) pending_control_bytes: usize,
    /// Portion of queued items charged to the control reserve.
    pub(super) pending_control_items: usize,
    /// Bootstrap issuance rate limiter.
    pub(super) bootstrap_rate: RateState,
    /// Session creation rate limiter.
    pub(super) session_rate: RateState,
    /// Logical-stream creation rate limiter.
    pub(super) stream_rate: RateState,
    /// Process shutdown admission latch.
    pub(super) closed: bool,
}

/// Generates one collision-checked credential and its stable hash key.
pub(super) fn new_unique_token(
    generation: &RuntimeGeneration,
    state: &ManagerState,
) -> Option<(String, TokenHash)> {
    for _ in 0..8 {
        let mut raw = [0u8; TOKEN_BYTES];
        generation.rng.fill(&mut raw);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let hash = Sha256::digest(raw).into();
        if !state.bootstraps.contains_key(&hash)
            && !state.sessions.contains_key(&hash)
            && !state.closed_tokens.contains_key(&hash)
        {
            return Some((token, hash));
        }
    }
    None
}

/// Returns the precomputed capability as the stable process profile key.
pub(super) fn profile_key(profile: &WebRuntimeProfile) -> ProfileKey {
    profile.capability
}

/// Re-resolves an issued profile against the active generation without weakening identity.
pub(super) fn matching_profile(
    runtime: &WebRuntimeConfig,
    expected: &WebRuntimeProfile,
) -> Option<Arc<WebRuntimeProfile>> {
    runtime
        .profiles
        .iter()
        .find(|profile| {
            profile.host == expected.host
                && profile.public_addr == expected.public_addr
                && profile.user == expected.user
                && profile.secret_mode == expected.secret_mode
                && profile.carrier == expected.carrier
                && profile.capability == expected.capability
        })
        .cloned()
}

/// Applies one token-bucket admission decision at a caller-supplied monotonic time.
pub(super) fn allow_rate(state: &mut RateState, now: Instant, per_minute: u32, burst: u32) -> bool {
    let burst = f64::from(burst);
    if let Some(last) = state.last {
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * f64::from(per_minute) / 60.0).min(burst);
    } else {
        state.tokens = burst;
    }
    state.last = Some(now);
    if state.tokens < 1.0 {
        return false;
    }
    state.tokens -= 1.0;
    true
}

/// Evicts the oldest unused bootstrap while preserving used retry state.
pub(super) fn evict_oldest_unused_bootstrap(state: &mut ManagerState) -> bool {
    let Some(hash) = state
        .bootstraps
        .iter()
        .filter(|(_, bootstrap)| !bootstrap.used)
        .min_by_key(|(_, bootstrap)| bootstrap.issued_at)
        .map(|(hash, _)| *hash)
    else {
        return false;
    };
    remove_bootstrap_locked(state, hash);
    true
}

/// Removes expired bootstrap and closed-token entries while the manager lock is held.
pub(super) fn remove_expired_locked(state: &mut ManagerState, now: Instant) {
    let expired = state
        .bootstraps
        .iter()
        .filter_map(|(hash, bootstrap)| (now > bootstrap.expires_at).then_some(*hash))
        .collect::<Vec<_>>();
    for hash in expired {
        remove_bootstrap_locked(state, hash);
    }
    state
        .closed_tokens
        .retain(|_, closed| now <= closed.expires_at);
}

/// Removes one bootstrap and releases its per-address issuance quota when unused.
pub(super) fn remove_bootstrap_locked(state: &mut ManagerState, hash: TokenHash) {
    let Some(bootstrap) = state.bootstraps.remove(&hash) else {
        return;
    };
    if !bootstrap.used {
        decrement_map(&mut state.bootstraps_per_ip, &bootstrap.issuance_ip);
    }
}

/// Decrements one counted owner and removes its map entry at zero.
pub(super) fn decrement_map<K, Q>(values: &mut HashMap<K, usize>, key: &Q)
where
    K: std::borrow::Borrow<Q> + std::hash::Hash + Eq,
    Q: std::hash::Hash + Eq + ?Sized,
{
    let remove = if let Some(value) = values.get_mut(key) {
        *value = value.saturating_sub(1);
        *value == 0
    } else {
        false
    };
    if remove {
        values.remove(key);
    }
}

/// Computes the process-wide item reserve required for session control progress.
pub(super) fn control_item_reserve(limits: &WebLimitsConfig) -> usize {
    limits
        .max_sessions_global
        .saturating_mul(16usize.saturating_add(limits.max_streams_per_session.saturating_mul(3)))
}

/// Allocates a non-zero source port unique among live streams for one KDF route.
pub(super) fn allocate_stream_port(
    state: &mut ManagerState,
    client_ip: IpAddr,
    public_addr: SocketAddr,
) -> Option<u16> {
    let ports = state
        .stream_ports
        .entry((client_ip, public_addr))
        .or_insert_with(|| StreamPortState {
            active: HashSet::new(),
            next: 1,
        });
    for _ in 0..u16::MAX {
        let candidate = ports.next;
        ports.next = ports.next.checked_add(1).unwrap_or(1);
        if ports.active.insert(candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Releases one source port and reclaims empty per-route allocator state.
pub(super) fn release_stream_port(
    state: &mut ManagerState,
    client_ip: IpAddr,
    public_addr: SocketAddr,
    peer_port: u16,
) -> bool {
    let key = (client_ip, public_addr);
    let Some(ports) = state.stream_ports.get_mut(&key) else {
        return false;
    };
    let removed = ports.active.remove(&peer_port);
    if ports.active.is_empty() {
        state.stream_ports.remove(&key);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_ports_are_unique_per_live_route_and_state_is_reclaimed() {
        let mut state = ManagerState::default();
        let client_ip = "192.0.2.10".parse().unwrap();
        let public_addr = "203.0.113.10:443".parse().unwrap();
        let first = allocate_stream_port(&mut state, client_ip, public_addr).unwrap();
        let second = allocate_stream_port(&mut state, client_ip, public_addr).unwrap();

        assert_ne!(first, second);
        assert!(release_stream_port(
            &mut state,
            client_ip,
            public_addr,
            first,
        ));
        assert!(release_stream_port(
            &mut state,
            client_ip,
            public_addr,
            second,
        ));
        assert!(state.stream_ports.is_empty());
    }
}
