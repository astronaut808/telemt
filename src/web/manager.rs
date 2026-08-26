use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
// Queue and WebSocket allocations share one process-owned data-plane budget.
mod budget;
// WebSocket admission, replacement, and liveness are process-scoped.
mod websocket;
pub(crate) use budget::WebSocketBudgetLease;
use budget::{WebDataBudget, WebSocketBudgetClass};
use state::ManagerState;
pub(crate) use websocket::{WebSocketConnection, WebSocketKind};

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
    websocket_connections: Arc<Semaphore>,
    websockets: Mutex<websocket::WebSocketRegistry>,
    websocket_next_id: AtomicU64,
    websocket_clock: std::time::Instant,
    websocket_notify: Arc<Notify>,
    data_budget: Arc<WebDataBudget>,
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
        let websocket_connections = limits
            .max_http_connections
            .saturating_sub(limits.websocket_http_connection_reserve);
        let runtime = Arc::new(Self {
            active_runtime,
            trace,
            http_connections: Arc::new(Semaphore::new(limits.max_http_connections)),
            http_handlers: Arc::new(Semaphore::new(limits.max_http_handlers)),
            lane_polls: Arc::new(Semaphore::new((limits.max_http_handlers / 2).max(1))),
            body_readers: Arc::new(Semaphore::new(limits.max_body_readers)),
            body_bytes: Arc::new(Semaphore::new(limits.max_body_bytes_global)),
            stream_handshakes: Arc::new(Semaphore::new(limits.max_stream_handshakes)),
            websocket_connections: Arc::new(Semaphore::new(websocket_connections)),
            websockets: Mutex::new(websocket::WebSocketRegistry::default()),
            websocket_next_id: AtomicU64::new(1),
            websocket_clock: std::time::Instant::now(),
            websocket_notify: Arc::new(Notify::new()),
            data_budget: WebDataBudget::new(limits.clone()),
            limits,
            state: Mutex::new(ManagerState::default()),
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
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
        downlink: bool,
    ) -> bool {
        if !self
            .data_budget
            .try_reserve_queue(owner, bytes, items, control, downlink)
        {
            self.record_limit_hit();
            return false;
        }
        true
    }

    /// Releases process-wide queue capacity and wakes blocked relay writers.
    pub(crate) fn release_pending(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) {
        self.data_budget.release_queue(owner, bytes, items, control);
    }

    /// Returns the shared notification source for global queue capacity changes.
    pub(crate) fn budget_notify(&self) -> Arc<Notify> {
        self.data_budget.notify()
    }

    /// Reserves fixed WebSocket driver memory below the admission watermark.
    pub(crate) fn try_websocket_base_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Base)
    }

    /// Reserves one transient WebSocket message below the eviction watermark.
    pub(crate) fn try_websocket_data_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Data)
    }

    /// Admits one WebSocket with owner-first bounded replacement.
    pub(crate) async fn admit_websocket(
        self: &Arc<Self>,
        owner: ProfileKey,
        session_id: u64,
        client_ip: IpAddr,
        kind: WebSocketKind,
        base_bytes: usize,
        liveness_interval: Duration,
        eviction_timeout: Duration,
    ) -> Result<WebSocketConnection, ManagerError> {
        websocket::admit(
            self,
            owner,
            session_id,
            client_ip,
            kind,
            base_bytes,
            liveness_interval,
            eviction_timeout,
        )
        .await
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
