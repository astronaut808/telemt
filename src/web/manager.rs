use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zeroize::Zeroizing;

use crate::config::{WebCarrier, WebLimitsConfig, WebRuntimeProfile};
use crate::maestro::generation::RuntimeGeneration;
use crate::web::frame;
use crate::web::session::WebSession;

// Credential maps, quotas, and token-bucket helpers remain private to the manager.
mod state;
// Stream admission and synthetic tuple ownership are process-scoped.
mod admission;
// Shutdown and expiry work remain outside request-path coordination.
mod lifecycle;
use state::{
    Bootstrap, ManagerState, allow_rate, control_item_reserve, decrement_map,
    evict_oldest_unused_bootstrap, matching_profile, new_unique_token, profile_key,
    remove_expired_locked,
};

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

/// Process-owned bounded WEB credential, session, and memory coordinator.
pub(crate) struct WebProcessRuntime {
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
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
    pub(crate) fn start(active_runtime: Arc<ArcSwap<RuntimeGeneration>>) -> Arc<Self> {
        let limits = active_runtime.load().config().web.limits.clone();
        let runtime = Arc::new(Self {
            active_runtime,
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

    /// Issues a one-use bootstrap credential for an active compatible profile.
    pub(crate) fn issue_bootstrap(
        &self,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<String, ManagerError> {
        let generation = self.active_generation();
        let config = generation.config();
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &profile))
            .ok_or(ManagerError::Authentication)?;
        if !config.web.enabled || !generation.proxy_shared.is_user_enabled(&profile.user) {
            return Err(ManagerError::Closed);
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        if state.closed
            || state
                .bootstraps_per_ip
                .get(&client_ip)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_bootstraps_per_ip
            || !allow_rate(
                &mut state.bootstrap_rate,
                now,
                self.limits.new_bootstraps_per_minute,
                self.limits.new_bootstraps_burst,
            )
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        if state.bootstraps.len() >= self.limits.max_bootstraps_global
            && !evict_oldest_unused_bootstrap(&mut state)
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        let Some((token, hash)) = new_unique_token(&generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        };
        state.bootstraps.insert(
            hash,
            Bootstrap {
                expires_at: now + Duration::from_secs(config.web.timeouts.bootstrap_lifetime_secs),
                issued_at: now,
                issuance_ip: client_ip,
                profile,
                body_digest: [0; TOKEN_BYTES],
                session_token: Zeroizing::new(String::new()),
                session: None,
                used: false,
            },
        );
        *state.bootstraps_per_ip.entry(client_ip).or_insert(0) += 1;
        Ok(token)
    }

    /// Checks whether a bootstrap token is live before reading a request body.
    pub(crate) fn has_bootstrap(&self, hash: TokenHash, host: &str) -> bool {
        let now = Instant::now();
        let state = self.state.lock();
        state
            .bootstraps
            .get(&hash)
            .is_some_and(|entry| entry.profile.host == host && now <= entry.expires_at)
    }

    /// Creates a session exactly once or replays the original successful result.
    pub(crate) fn create_session(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        host: &str,
        client_ip: IpAddr,
        body: &[u8],
    ) -> std::result::Result<CreateResult, ManagerError> {
        if !frame::validate_hello(body, &self.limits) {
            return Err(ManagerError::Protocol);
        }
        let body_digest: TokenHash = Sha256::digest(body).into();
        let generation = self.active_generation();
        let config = generation.config();
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        let Some(entry) = state.bootstraps.get(&bootstrap_hash) else {
            return Err(ManagerError::Authentication);
        };
        if entry.profile.host != host || now > entry.expires_at {
            return Err(ManagerError::Authentication);
        }
        if entry.used {
            let digest_matches = bool::from(entry.body_digest.ct_eq(&body_digest));
            if !digest_matches {
                return Err(ManagerError::Authentication);
            }
            let session = entry.session.as_ref().ok_or(ManagerError::Authentication)?;
            return Ok(CreateResult {
                token: entry.session_token.as_str().to_owned(),
                carrier: session.carrier(),
            });
        }
        if state.closed || !config.web.enabled {
            return Err(ManagerError::Closed);
        }
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &entry.profile))
            .filter(|profile| generation.proxy_shared.is_user_enabled(&profile.user))
            .ok_or(ManagerError::Authentication)?;
        let profile_key = profile_key(&profile);
        if state.sessions.len() >= self.limits.max_sessions_global
            || state.sessions_per_ip.get(&client_ip).copied().unwrap_or(0)
                >= self.limits.max_sessions_per_ip
            || state
                .sessions_per_profile
                .get(&profile_key)
                .copied()
                .unwrap_or(0)
                >= profile.max_sessions
            || !allow_rate(
                &mut state.session_rate,
                now,
                self.limits.new_sessions_per_minute,
                self.limits.new_sessions_burst,
            )
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        let Some((session_token, session_hash)) = new_unique_token(&generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        };
        let session = WebSession::new(
            Arc::downgrade(self),
            session_hash,
            client_ip,
            profile,
            profile_key,
            self.limits.clone(),
            config.web.timeouts.clone(),
        );
        state.sessions.insert(session_hash, Arc::clone(&session));
        *state.sessions_per_ip.entry(client_ip).or_insert(0) += 1;
        *state.sessions_per_profile.entry(profile_key).or_insert(0) += 1;
        let entry = state
            .bootstraps
            .get_mut(&bootstrap_hash)
            .ok_or(ManagerError::Authentication)?;
        entry.used = true;
        entry.body_digest = body_digest;
        entry.session_token = Zeroizing::new(session_token.clone());
        entry.session = Some(Arc::clone(&session));
        let issuance_ip = entry.issuance_ip;
        decrement_map(&mut state.bootstraps_per_ip, &issuance_ip);
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        Ok(CreateResult {
            token: session_token,
            carrier: session.carrier(),
        })
    }

    /// Resolves an authenticated session token.
    pub(crate) fn get_session(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<Arc<WebSession>, ManagerError> {
        self.state
            .lock()
            .sessions
            .get(&hash)
            .cloned()
            .filter(|session| session.matches_host(host))
            .ok_or(ManagerError::Authentication)
    }

    /// Closes a live token and accepts bounded tombstone retries.
    pub(crate) fn close_token(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<(), ManagerError> {
        let state = self.state.lock();
        let session = state
            .sessions
            .get(&hash)
            .filter(|session| session.matches_host(host))
            .cloned();
        let closed = state
            .closed_tokens
            .get(&hash)
            .is_some_and(|closed| closed.host == host);
        drop(state);
        if let Some(session) = session {
            session.close();
            return Ok(());
        }
        closed.then_some(()).ok_or(ManagerError::Authentication)
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
