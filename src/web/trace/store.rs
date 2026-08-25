use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::exchange::HttpTraceExchange;
use super::types::{
    TraceIdentity, TraceLifecycleEvent, TraceLifecycleRecord, TraceRecord, TraceRecordKind,
};
use crate::config::{WebDebugConfig, WebLimitsConfig};

const BASE_RECORD_RESERVATION: usize = 1024;

struct RingState {
    records: VecDeque<Arc<StoredTraceRecord>>,
}

/// One retained record whose lease survives status-page snapshots.
pub(crate) struct StoredTraceRecord {
    /// Immutable trace record.
    pub(crate) record: TraceRecord,
    bytes: usize,
    used_bytes: Arc<AtomicUsize>,
}

impl Drop for StoredTraceRecord {
    fn drop(&mut self) {
        self.used_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Point-in-time process-owned trace counters and ring bounds.
pub(crate) struct TraceStoreStatus {
    /// Current debug policy.
    pub(crate) policy: Arc<WebDebugConfig>,
    /// Retained record count.
    pub(crate) records: usize,
    /// Configured record capacity.
    pub(crate) records_capacity: usize,
    /// Retained plus in-flight byte leases.
    pub(crate) used_bytes: usize,
    /// Configured byte capacity.
    pub(crate) bytes_capacity: usize,
    /// Records dropped on commit-lock contention.
    pub(crate) contention_drops: u64,
    /// Oldest records evicted by ring capacity.
    pub(crate) evictions: u64,
    /// Body or metadata captures truncated by policy or byte capacity.
    pub(crate) byte_truncations: u64,
    /// Earliest retained record sequence.
    pub(crate) earliest_seq: Option<u64>,
    /// Latest retained record sequence.
    pub(crate) latest_seq: Option<u64>,
}

/// Process-owned bounded WEB debug trace store.
pub(crate) struct WebTraceStore {
    policy: ArcSwap<WebDebugConfig>,
    policy_update: Mutex<()>,
    enabled: AtomicBool,
    epoch: AtomicU64,
    records_capacity: usize,
    bytes_capacity: usize,
    max_carrier_body_bytes: usize,
    used_bytes: Arc<AtomicUsize>,
    ring: Mutex<RingState>,
    next_record_seq: AtomicU64,
    next_session_id: AtomicU64,
    contention_drops: AtomicU64,
    evictions: AtomicU64,
    byte_truncations: AtomicU64,
    renders: Arc<Semaphore>,
}

impl WebTraceStore {
    /// Creates a process-owned store from restart-only capacity and initial policy.
    pub(crate) fn new(policy: WebDebugConfig, limits: &WebLimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(policy.enabled),
            policy: ArcSwap::from_pointee(policy),
            policy_update: Mutex::new(()),
            epoch: AtomicU64::new(1),
            records_capacity: limits.debug_records_capacity,
            bytes_capacity: limits.debug_bytes_global,
            max_carrier_body_bytes: limits.max_body_bytes,
            used_bytes: Arc::new(AtomicUsize::new(0)),
            ring: Mutex::new(RingState {
                records: VecDeque::with_capacity(limits.debug_records_capacity),
            }),
            next_record_seq: AtomicU64::new(1),
            next_session_id: AtomicU64::new(1),
            contention_drops: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            byte_truncations: AtomicU64::new(0),
            renders: Arc::new(Semaphore::new(2)),
        })
    }

    /// Applies one hot policy and clears incompatible retained records.
    pub(crate) fn apply_policy(&self, policy: &WebDebugConfig) {
        let _policy_update = self.policy_update.lock();
        let current = self.policy.load_full();
        if current.as_ref() == policy {
            return;
        }
        let capture_changed = current.enabled != policy.enabled
            || current.capture_lifecycle != policy.capture_lifecycle
            || current.capture_headers != policy.capture_headers
            || current.capture_timings != policy.capture_timings
            || current.capture_frames != policy.capture_frames
            || current.body_capture != policy.body_capture
            || current.body_prefix_bytes != policy.body_prefix_bytes
            || current.decoy_body_prefix_bytes != policy.decoy_body_prefix_bytes;
        self.policy.store(Arc::new(policy.clone()));
        self.enabled.store(policy.enabled, Ordering::Release);
        if capture_changed {
            self.epoch.fetch_add(1, Ordering::AcqRel);
            self.ring.lock().records.clear();
        }
    }

    /// Allocates a process-unique monotonic WEB session trace identifier.
    pub(crate) fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Starts one HTTP exchange only when debugging is enabled and budgeted.
    pub(crate) fn begin_http<B>(
        self: &Arc<Self>,
        request: &hyper::Request<B>,
        peer_ip: IpAddr,
    ) -> Option<Arc<HttpTraceExchange>> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let policy = self.policy.load_full();
        if !policy.enabled || !self.try_reserve_record(BASE_RECORD_RESERVATION) {
            return None;
        }
        Some(HttpTraceExchange::new(
            Arc::clone(self),
            epoch,
            policy,
            request,
            peer_ip,
            BASE_RECORD_RESERVATION,
        ))
    }

    /// Records one typed lifecycle event without retaining dynamic error strings.
    pub(crate) fn record_lifecycle(
        &self,
        peer_ip: Option<IpAddr>,
        effective_ip: Option<IpAddr>,
        identity: TraceIdentity,
        event: TraceLifecycleEvent,
        stream_id: Option<u32>,
        reason: Option<&'static str>,
    ) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let policy = self.policy.load_full();
        let identity_bytes = identity
            .user
            .as_ref()
            .map_or(0, String::len)
            .checked_add(
                identity
                    .key_fingerprint
                    .as_ref()
                    .map_or(0, String::len),
            );
        let Some(reservation) = identity_bytes
            .and_then(|bytes| BASE_RECORD_RESERVATION.checked_add(bytes))
        else {
            self.record_truncation();
            return;
        };
        if !policy.enabled
            || !policy.capture_lifecycle
            || !self.try_reserve_record(reservation)
        {
            return;
        }
        let record = TraceRecord {
            seq: self.next_record_seq(),
            epoch_millis: epoch_millis(),
            peer_ip,
            effective_ip,
            user_agent: None,
            identity,
            kind: TraceRecordKind::Lifecycle(TraceLifecycleRecord {
                event,
                stream_id,
                reason,
            }),
        };
        if !self.try_commit(record, reservation, epoch) {
            self.release(reservation);
        }
    }

    /// Records lifecycle identity from a profile only after enabled-policy checks.
    pub(crate) fn record_profile_lifecycle(
        &self,
        effective_ip: IpAddr,
        session_id: Option<u64>,
        profile: &crate::config::WebRuntimeProfile,
        event: TraceLifecycleEvent,
        stream_id: Option<u32>,
        reason: Option<&'static str>,
    ) {
        if !self.enabled.load(Ordering::Acquire) || !self.policy.load().capture_lifecycle {
            return;
        }
        self.record_lifecycle(
            None,
            Some(effective_ip),
            TraceIdentity::from_optional_profile(session_id, profile),
            event,
            stream_id,
            reason,
        );
    }

    /// Returns records matching the supplied predicate in newest-first order.
    pub(crate) fn snapshot_matching<F>(&self, mut matches: F) -> Vec<Arc<StoredTraceRecord>>
    where
        F: FnMut(&TraceRecord) -> bool,
    {
        self.ring
            .lock()
            .records
            .iter()
            .rev()
            .filter(|record| matches(&record.record))
            .cloned()
            .collect()
    }

    /// Returns current bounds, counters, and retained sequence range.
    pub(crate) fn status(&self) -> TraceStoreStatus {
        let ring = self.ring.lock();
        TraceStoreStatus {
            policy: self.policy.load_full(),
            records: ring.records.len(),
            records_capacity: self.records_capacity,
            used_bytes: self.used_bytes.load(Ordering::Acquire),
            bytes_capacity: self.bytes_capacity,
            contention_drops: self.contention_drops.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            byte_truncations: self.byte_truncations.load(Ordering::Relaxed),
            earliest_seq: ring.records.front().map(|record| record.record.seq),
            latest_seq: ring.records.back().map(|record| record.record.seq),
        }
    }

    /// Reserves one of two bounded concurrent status-page render slots.
    pub(crate) fn try_render_permit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.renders).try_acquire_owned().ok()
    }

    /// Returns the current capture-policy epoch.
    pub(super) fn policy_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Returns the restart-frozen recognized carrier body ceiling.
    pub(super) fn max_carrier_body_bytes(&self) -> usize {
        self.max_carrier_body_bytes
    }

    /// Atomically reserves debug bytes or records one truncation.
    pub(super) fn try_reserve(&self, bytes: usize) -> bool {
        if self.try_reserve_inner(bytes) {
            true
        } else {
            self.byte_truncations.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn try_reserve_inner(&self, bytes: usize) -> bool {
        let mut current = self.used_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.bytes_capacity {
                return false;
            }
            match self.used_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn try_reserve_record(&self, bytes: usize) -> bool {
        if self.try_reserve_inner(bytes) {
            return true;
        }
        let Some(mut ring) = self.ring.try_lock() else {
            self.byte_truncations.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        while let Some(record) = ring.records.pop_front() {
            self.evictions.fetch_add(1, Ordering::Relaxed);
            drop(record);
            if self.try_reserve_inner(bytes) {
                return true;
            }
        }
        self.byte_truncations.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Releases an in-flight lease that was not transferred into a record.
    pub(super) fn release(&self, bytes: usize) {
        self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Increments the closed truncation counter.
    pub(super) fn record_truncation(&self) {
        self.byte_truncations.fetch_add(1, Ordering::Relaxed);
    }

    /// Allocates a process-monotonic record sequence number.
    pub(super) fn next_record_seq(&self) -> u64 {
        self.next_record_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Attempts one non-blocking ring commit under the originating policy epoch.
    pub(super) fn try_commit(&self, record: TraceRecord, bytes: usize, epoch: u64) -> bool {
        if epoch != self.policy_epoch() {
            return false;
        }
        let Some(mut ring) = self.ring.try_lock() else {
            self.contention_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if epoch != self.policy_epoch() {
            return false;
        }
        while ring.records.len() >= self.records_capacity {
            ring.records.pop_front();
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        ring.records.push_back(Arc::new(StoredTraceRecord {
            record,
            bytes,
            used_bytes: Arc::clone(&self.used_bytes),
        }));
        true
    }
}

/// Returns Unix epoch milliseconds with saturation for stored display timestamps.
pub(crate) fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(records_capacity: usize, bytes_capacity: usize) -> Arc<WebTraceStore> {
        let mut policy = WebDebugConfig::default();
        policy.enabled = true;
        let mut limits = WebLimitsConfig::default();
        limits.debug_records_capacity = records_capacity;
        limits.debug_bytes_global = bytes_capacity;
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
        store.apply_policy(&policy);
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

        let mut changed = WebDebugConfig::default();
        changed.enabled = true;
        changed.capture_headers = false;
        store.apply_policy(&changed);
        exchange.commit();

        assert_eq!(store.status().records, 0);
        assert_eq!(store.status().used_bytes, 0);
    }
}
