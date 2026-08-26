use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use super::{ManagerError, ProfileKey, WebProcessRuntime, WebSocketBudgetLease};

/// One process-owned WebSocket carrier class used for eviction priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WebSocketKind {
    /// One connection multiplexes every logical stream in a session.
    Multiplex,
    /// One connection owns exactly one logical stream lane.
    Lane(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct WebSocketClaimKey {
    session_hash: super::TokenHash,
    kind: WebSocketKind,
}

#[repr(u8)]
enum WebSocketPhase {
    Claimed,
    Upgraded,
    Active,
    Closing,
}

pub(super) struct WebSocketEntry {
    id: u64,
    owner: ProfileKey,
    session_id: u64,
    claim: WebSocketClaimKey,
    client_ip: IpAddr,
    kind: WebSocketKind,
    liveness_interval_ms: u64,
    created_tick: u64,
    last_peer_tick: AtomicU64,
    last_progress_tick: AtomicU64,
    phase: AtomicU8,
    closing: AtomicBool,
    cancel: CancellationToken,
    released: CancellationToken,
}

#[derive(Default)]
pub(super) struct WebSocketRegistry {
    entries: HashMap<u64, Arc<WebSocketEntry>>,
    claims: HashMap<WebSocketClaimKey, u64>,
    evictions_in_flight: usize,
    closed: bool,
}

/// Exact process-owned admission retained through the upgraded socket lifetime.
pub(crate) struct WebSocketConnection {
    runtime: std::sync::Weak<WebProcessRuntime>,
    entry: Arc<WebSocketEntry>,
    slot: Option<OwnedSemaphorePermit>,
    base_budget: Option<WebSocketBudgetLease>,
}

impl WebSocketConnection {
    /// Returns the cancellation signal used by shutdown and pressure eviction.
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }

    /// Returns the process-unique connection identifier used only for debugging.
    pub(crate) fn id(&self) -> u64 {
        self.entry.id
    }

    /// Returns the creation-time transport liveness interval.
    pub(crate) fn liveness_interval(&self) -> Duration {
        Duration::from_millis(self.entry.liveness_interval_ms)
    }

    /// Marks successful ownership transfer from HTTP to the WebSocket codec.
    pub(crate) fn mark_opened(&self) {
        self.entry
            .phase
            .store(WebSocketPhase::Upgraded as u8, Ordering::Release);
        self.mark_progress();
    }

    /// Marks the first validated carrier binary message as active progress.
    pub(crate) fn mark_active(&self) {
        self.entry
            .phase
            .store(WebSocketPhase::Active as u8, Ordering::Release);
        self.mark_peer_activity();
    }

    /// Refreshes the peer-liveness deadline after any received WebSocket message.
    pub(crate) fn mark_peer_activity(&self) {
        if let Some(runtime) = self.runtime.upgrade() {
            let now = runtime.websocket_tick();
            self.entry.last_peer_tick.store(now, Ordering::Release);
            self.entry.last_progress_tick.store(now, Ordering::Release);
        }
    }

    /// Refreshes least-recently-progressed ordering after a committed write.
    pub(crate) fn mark_progress(&self) {
        if let Some(runtime) = self.runtime.upgrade() {
            self.entry
                .last_progress_tick
                .store(runtime.websocket_tick(), Ordering::Release);
        }
    }
}

impl Drop for WebSocketConnection {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            let mut registry = runtime.websockets.lock();
            registry.entries.remove(&self.entry.id);
            if registry.claims.get(&self.entry.claim) == Some(&self.entry.id) {
                registry.claims.remove(&self.entry.claim);
            }
            if self.entry.closing.load(Ordering::Acquire) {
                registry.evictions_in_flight = registry.evictions_in_flight.saturating_sub(1);
            }
            drop(registry);
            self.entry.released.cancel();
            drop(self.base_budget.take());
            drop(self.slot.take());
            runtime.websocket_notify.notify_waiters();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn admit(
    runtime: &Arc<WebProcessRuntime>,
    owner: ProfileKey,
    session_id: u64,
    session_hash: super::TokenHash,
    client_ip: IpAddr,
    kind: WebSocketKind,
    base_bytes: usize,
    liveness_interval: Duration,
    eviction_timeout: Duration,
    parent_cancellation: CancellationToken,
) -> Result<WebSocketConnection, ManagerError> {
    let liveness_interval_ms = liveness_interval.as_millis().min(u128::from(u64::MAX)) as u64;
    match try_admit(
        runtime,
        owner,
        session_id,
        session_hash,
        client_ip,
        kind,
        base_bytes,
        liveness_interval_ms,
        &parent_cancellation,
    ) {
        Ok(connection) => return Ok(connection),
        Err(TryAdmitError::Conflict) => return Err(ManagerError::Concurrent),
        Err(TryAdmitError::Closed) => return Err(ManagerError::Closed),
        Err(TryAdmitError::Capacity) => {}
    }
    let Some(victim) = select_victim(runtime, owner, session_id, client_ip, None, true) else {
        runtime.record_limit_hit();
        return Err(ManagerError::Limit);
    };
    let released = victim.released.cancelled();
    victim.cancel.cancel();
    let _ = tokio::time::timeout(eviction_timeout, released).await;
    match try_admit(
        runtime,
        owner,
        session_id,
        session_hash,
        client_ip,
        kind,
        base_bytes,
        liveness_interval_ms,
        &parent_cancellation,
    ) {
        Ok(connection) => Ok(connection),
        Err(TryAdmitError::Conflict) => Err(ManagerError::Concurrent),
        Err(TryAdmitError::Closed) => Err(ManagerError::Closed),
        Err(TryAdmitError::Capacity) => {
            runtime.record_limit_hit();
            Err(ManagerError::Limit)
        }
    }
}

enum TryAdmitError {
    Capacity,
    Conflict,
    Closed,
}

fn try_admit(
    runtime: &Arc<WebProcessRuntime>,
    owner: ProfileKey,
    session_id: u64,
    session_hash: super::TokenHash,
    client_ip: IpAddr,
    kind: WebSocketKind,
    base_bytes: usize,
    liveness_interval_ms: u64,
    parent_cancellation: &CancellationToken,
) -> Result<WebSocketConnection, TryAdmitError> {
    let claim = WebSocketClaimKey { session_hash, kind };
    {
        let registry = runtime.websockets.lock();
        if registry.closed {
            return Err(TryAdmitError::Closed);
        }
        if registry.claims.contains_key(&claim) {
            return Err(TryAdmitError::Conflict);
        }
    }
    let slot = Arc::clone(&runtime.websocket_connections)
        .try_acquire_owned()
        .map_err(|_| TryAdmitError::Capacity)?;
    let base_budget = runtime
        .try_websocket_base_budget(owner, base_bytes)
        .ok_or(TryAdmitError::Capacity)?;
    let id = runtime
        .websocket_next_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| TryAdmitError::Capacity)?;
    let now = runtime.websocket_tick();
    let entry = Arc::new(WebSocketEntry {
        id,
        owner,
        session_id,
        claim,
        client_ip,
        kind,
        liveness_interval_ms,
        created_tick: now,
        last_peer_tick: AtomicU64::new(now),
        last_progress_tick: AtomicU64::new(now),
        phase: AtomicU8::new(WebSocketPhase::Claimed as u8),
        closing: AtomicBool::new(false),
        cancel: parent_cancellation.child_token(),
        released: CancellationToken::new(),
    });
    let mut registry = runtime.websockets.lock();
    if registry.closed {
        return Err(TryAdmitError::Closed);
    }
    if registry.claims.contains_key(&claim) {
        return Err(TryAdmitError::Conflict);
    }
    registry.claims.insert(claim, id);
    registry.entries.insert(id, Arc::clone(&entry));
    drop(registry);
    Ok(WebSocketConnection {
        runtime: Arc::downgrade(runtime),
        entry,
        slot: Some(slot),
        base_budget: Some(base_budget),
    })
}

impl WebProcessRuntime {
    pub(super) fn websocket_tick(&self) -> u64 {
        self.websocket_clock.elapsed().as_millis() as u64
    }

    pub(super) fn cleanup_websockets(&self) {
        let now = self.websocket_tick();
        let mut victims = self
            .websockets
            .lock()
            .entries
            .values()
            .filter(|entry| {
                now.saturating_sub(entry.last_peer_tick.load(Ordering::Acquire))
                    >= dead_after(entry)
            })
            .cloned()
            .collect::<Vec<_>>();
        if victims.is_empty()
            && self.data_budget.take_pressure()
            && let Some(victim) = select_pressure_victim(self, now)
        {
            victims.push(victim);
        }
        for victim in victims {
            victim.cancel.cancel();
        }
    }

    pub(super) fn close_websockets(&self) {
        let victims = {
            let mut registry = self.websockets.lock();
            registry.closed = true;
            registry.entries.values().cloned().collect::<Vec<_>>()
        };
        for victim in victims {
            victim.cancel.cancel();
        }
    }
}

fn select_victim(
    runtime: &WebProcessRuntime,
    owner: ProfileKey,
    session_id: u64,
    client_ip: IpAddr,
    excluded_id: Option<u64>,
) -> Option<Arc<WebSocketEntry>> {
    let fair_share = runtime.data_budget.fair_share(Some(owner));
    let requester_usage = runtime.data_budget.owner_usage(owner);
    let now = runtime.websocket_tick();
    runtime
        .websockets
        .lock()
        .entries
        .values()
        .filter(|entry| Some(entry.id) != excluded_id)
        .filter_map(|entry| {
            let owner_rank = if entry.session_id == session_id {
                0
            } else if entry.owner == owner {
                1
            } else if entry.client_ip == client_ip {
                2
            } else {
                if requester_usage >= fair_share
                    || runtime.data_budget.owner_usage(entry.owner) <= fair_share
                {
                    return None;
                }
                3
            };
            let priority = entry_priority(entry, now);
            Some((
                (
                    owner_rank,
                    priority,
                    entry.last_progress_tick.load(Ordering::Acquire),
                    entry.created_tick,
                    entry.id,
                ),
                Arc::clone(entry),
            ))
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, entry)| entry)
}

fn select_pressure_victim(runtime: &WebProcessRuntime, now: u64) -> Option<Arc<WebSocketEntry>> {
    runtime
        .websockets
        .lock()
        .entries
        .values()
        .map(|entry| {
            (
                (
                    entry_priority(entry, now),
                    entry.last_progress_tick.load(Ordering::Acquire),
                    entry.created_tick,
                    entry.id,
                ),
                Arc::clone(entry),
            )
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, entry)| entry)
}

fn entry_priority(entry: &WebSocketEntry, now: u64) -> u8 {
    if !entry.opened.load(Ordering::Acquire)
        || now.saturating_sub(entry.last_peer_tick.load(Ordering::Acquire)) >= dead_after(entry)
    {
        0
    } else if matches!(entry.kind, WebSocketKind::Lane(_)) {
        1
    } else {
        2
    }
}

fn dead_after(entry: &WebSocketEntry) -> u64 {
    entry.liveness_interval_ms.saturating_mul(2)
}

#[cfg(test)]
mod tests;
