use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{WebCarrier, WebLimitsConfig};
use crate::maestro::generation::RuntimeGeneration;
use crate::web::trace::WebTraceStore;

// Credential maps, quotas, and token-bucket helpers remain private to the manager.
mod state;
// Bootstrap credentials and idempotent session creation are isolated from queue accounting.
mod credentials;
// Stream admission and synthetic tuple ownership are process-scoped.
mod admission;
// Shutdown and expiry work remain outside request-path coordination.
mod lifecycle;
use state::{ManagerState, control_item_reserve};

const TOKEN_BYTES: usize = 32;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// Stable hash key used for bootstrap and session credentials.
pub(crate) type TokenHash = [u8; TOKEN_BYTES];
/// Stable non-allocating key used for per-profile quotas.
pub(crate) type ProfileKey = [u8; TOKEN_BYTES];

/// WEB manager operation failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagerError {
    /// Credential, hostname, or ownership validation failed.
    Authentication,
    /// Bounded queue capacity is temporarily unavailable.
    Backpressure,
    /// A configured admission or rate ceiling was reached.
    Limit,
    /// Carrier framing or sequencing violated the protocol.
    Protocol,
    /// The operation conflicts with another in-flight operation.
    Concurrent,
    /// The process or session has stopped accepting work.
    Closed,
}

/// Successful idempotent session creation result.
pub(crate) struct CreateResult {
    /// Opaque bearer token for the created or replayed session.
    pub(crate) token: String,
    /// Carrier frozen into the created or replayed session.
    pub(crate) carrier: WebCarrier,
}

/// Successful bridge bootstrap issuance result.
pub(crate) struct BootstrapResult {
    /// Opaque one-use bootstrap credential.
    pub(crate) token: String,
    /// Process-unique non-secret trace identifier.
    pub(crate) trace_session_id: u64,
}

/// Process-owned bounded WEB credential, session, and memory coordinator.
pub(crate) struct WebProcessRuntime {
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    trace: Arc<WebTraceStore>,
    limits: WebLimitsConfig,
    state: Mutex<ManagerState>,
    http_connections: Arc<Semaphore>,
    http_handlers: Arc<Semaphore>,
    lane_polls: Arc<Semaphore>,
    body_readers: Arc<Semaphore>,
    body_bytes: Arc<Semaphore>,
    stream_handshakes: Arc<Semaphore>,
    budget_notify: Arc<Notify>,
    budget_saturated: AtomicBool,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    sessions_created: AtomicU64,
    sessions_closed: AtomicU64,
    streams_opened: AtomicU64,
    streams_rejected: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    limit_hits: AtomicU64,
}

impl WebProcessRuntime {
    /// Starts one process-scoped manager using immutable allocation ceilings.
    #[cfg(test)]
    pub(crate) fn start(active_runtime: Arc<ArcSwap<RuntimeGeneration>>) -> Arc<Self> {
        let config = active_runtime.load().config();
        let trace = WebTraceStore::new(config.web.debug.clone(), &config.web.limits);
        Self::start_with_trace(active_runtime, trace)
    }

    /// Starts one process-scoped manager with a shared API-visible trace store.
    pub(crate) fn start_with_trace(
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
        trace: Arc<WebTraceStore>,
    ) -> Arc<Self> {
        let limits = active_runtime.load().config().web.limits.clone();
        let runtime = Arc::new(Self {
            active_runtime,
            trace,
            http_connections: Arc::new(Semaphore::new(limits.max_http_connections)),
            http_handlers: Arc::new(Semaphore::new(limits.max_http_handlers)),
            lane_polls: Arc::new(Semaphore::new((limits.max_http_handlers / 2).max(1))),
            body_readers: Arc::new(Semaphore::new(limits.max_body_readers)),
            body_bytes: Arc::new(Semaphore::new(limits.max_body_bytes_global)),
            stream_handshakes: Arc::new(Semaphore::new(limits.max_stream_handshakes)),
            limits,
            state: Mutex::new(ManagerState::default()),
            budget_notify: Arc::new(Notify::new()),
            budget_saturated: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            sessions_created: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_rejected: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            limit_hits: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&runtime);
        let shutdown = runtime.shutdown.clone();
        runtime.tasks.spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let Some(runtime) = weak.upgrade() else {
                            break;
                        };
                        let policy = runtime.active_generation().config().web.debug.clone();
                        runtime.trace.apply_policy(&policy);
                        runtime.cleanup();
                    }
                }
            }
        });
        runtime
    }

    /// Loads the currently active generation without retaining older generations.
    pub(crate) fn active_generation(&self) -> Arc<RuntimeGeneration> {
        self.active_runtime.load_full()
    }

    /// Returns the process-owned WEB debug trace store.
    pub(crate) fn trace(&self) -> &Arc<WebTraceStore> {
        &self.trace
    }

    /// Reserves one accepted HTTP connection.
    pub(crate) fn try_http_connection(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.http_connections).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_limit_hit();
        }
        permit
    }

    /// Reserves one concurrently executing HTTP request handler.
    pub(crate) fn try_http_handler(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.http_handlers).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_limit_hit();
        }
        permit
    }

    /// Reserves one parked lane poll without exhausting all HTTP handlers.
    pub(crate) fn try_lane_poll(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.lane_polls).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_limit_hit();
        }
        permit
    }

    /// Reserves one logical stream in the inner MTProxy handshake phase.
    pub(crate) fn try_stream_handshake(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.stream_handshakes).try_acquire_owned().ok();
        if permit.is_none() {
            self.record_stream_rejected();
        }
        permit
    }

    /// Spawns one process-owned auxiliary task with shutdown cancellation.
    pub(crate) fn spawn_auxiliary<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let shutdown = self.shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = future => {}
            }
        });
    }

    /// Reserves one body reader and its declared bounded body allocation.
    pub(crate) fn try_body_budget(
        &self,
        bytes: usize,
    ) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let Some(bytes) = u32::try_from(bytes).ok() else {
            self.record_limit_hit();
            return None;
        };
        let Some(reader) = Arc::clone(&self.body_readers).try_acquire_owned().ok() else {
            self.record_limit_hit();
            return None;
        };
        let Some(body) = Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(bytes)
            .ok()
        else {
            self.record_limit_hit();
            return None;
        };
        Some((reader, body))
    }

    /// Reserves bounded process-wide queue capacity for data or control traffic.
    pub(crate) fn try_reserve_pending(
        &self,
        bytes: usize,
        items: usize,
        control: bool,
        downlink: bool,
    ) -> bool {
        let mut state = self.state.lock();
        let data_byte_limit = self
            .limits
            .pending_bytes_global
            .saturating_sub(self.limits.control_bytes_global);
        let control_item_reserve = control_item_reserve(&self.limits);
        let data_item_limit = self
            .limits
            .pending_items_global
            .saturating_sub(control_item_reserve);
        if state.closed {
            return false;
        }
        let fits = if control {
            bytes <= self.limits.control_bytes_global
                && items <= control_item_reserve
                && state.pending_bytes <= self.limits.pending_bytes_global.saturating_sub(bytes)
                && state.pending_items <= self.limits.pending_items_global.saturating_sub(items)
                && state.pending_control_bytes
                    <= self.limits.control_bytes_global.saturating_sub(bytes)
                && state.pending_control_items <= control_item_reserve.saturating_sub(items)
        } else {
            let data_bytes = state
                .pending_bytes
                .saturating_sub(state.pending_control_bytes);
            let data_items = state
                .pending_items
                .saturating_sub(state.pending_control_items);
            let (byte_limit, item_limit) = if downlink {
                let uplink_bytes = self.limits.max_body_bytes.saturating_add(
                    self.limits
                        .max_frames_per_body
                        .saturating_mul(crate::web::session::QUEUE_ITEM_COST),
                );
                (
                    data_byte_limit.saturating_sub(uplink_bytes),
                    data_item_limit.saturating_sub(self.limits.max_frames_per_body),
                )
            } else {
                (data_byte_limit, data_item_limit)
            };
            bytes <= byte_limit
                && items <= item_limit
                && data_bytes <= byte_limit - bytes
                && data_items <= item_limit - items
        };
        if !fits {
            self.budget_saturated.store(true, Ordering::Release);
            self.record_limit_hit();
            return false;
        }
        state.pending_bytes += bytes;
        state.pending_items += items;
        if control {
            state.pending_control_bytes += bytes;
            state.pending_control_items += items;
        }
        true
    }

    /// Releases process-wide queue capacity and wakes blocked relay writers.
    pub(crate) fn release_pending(&self, bytes: usize, items: usize, control: bool) {
        let mut state = self.state.lock();
        state.pending_bytes = state.pending_bytes.saturating_sub(bytes);
        state.pending_items = state.pending_items.saturating_sub(items);
        if control {
            state.pending_control_bytes = state.pending_control_bytes.saturating_sub(bytes);
            state.pending_control_items = state.pending_control_items.saturating_sub(items);
        }
        drop(state);
        if self.budget_saturated.swap(false, Ordering::AcqRel) {
            self.budget_notify.notify_waiters();
        }
    }

    /// Returns the shared notification source for global queue capacity changes.
    pub(crate) fn budget_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.budget_notify)
    }

    /// Accounts one successfully committed carrier uplink body.
    pub(crate) fn record_up(&self, bytes: usize) {
        self.bytes_up.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Accounts one emitted carrier downlink body.
    pub(crate) fn record_down(&self, bytes: usize) {
        self.bytes_down.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn record_limit_hit(&self) {
        self.limit_hits.fetch_add(1, Ordering::Relaxed);
    }
}
