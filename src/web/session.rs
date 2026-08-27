use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::ReadBuf;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::{WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebTimeoutsConfig};
use crate::web::frame::{self, FrameType};
use crate::web::manager::{
    CarrierClientClass, CarrierLearningContext, ProfileKey, TokenHash, WebProcessRuntime,
};

// Backend tasks own generation admission and authenticated MTProxy relay lifetimes.
mod backend;
// Downlink queues own cursor replay, flow control, and memory reservations.
mod downlink;
// Response ownership keeps detached batches charged until the last body clone drops.
mod resident;
// Read-only control-plane snapshots stay isolated from carrier operations.
mod status;
pub(crate) use status::WebSessionStatus;
// Lane carrier state isolates request sequencing and downlink replay per logical stream.
mod lanes;
// Lane batch staging transfers queue ownership without escaping process budgets.
mod lane_downlink;
// Lane uplink creation remains transactional across validation and queue reservations.
mod lane_uplink;
// WebSocket carrier state owns pre-OPEN lane reservations and failure isolation.
mod websocket;
pub(crate) use websocket::WebSocketLaneReservation;
pub(crate) use websocket::WebSocketProbeReservation;
// Carrier commit and health evidence share one session-locked state machine.
mod negotiation;
// Session closure and carrier-attempt transitions share one cancellation boundary.
mod lifecycle;
// Uplink batches own exactly-once sequencing and client-frame validation.
mod uplink;

/// Conservative allocator and container overhead charged to every queued item.
pub(crate) const QUEUE_ITEM_COST: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingClass {
    Uplink,
    Downlink,
    Control,
}

struct InboundChunk {
    bytes: Bytes,
    offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamIdentity {
    pub(crate) id: u32,
    pub(crate) instance: u64,
}

/// Exact server-local identity of one carrier-lane incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierLaneIdentity {
    /// Numeric lane identifier carried on the wire.
    pub(crate) lane_id: u32,
    /// Monotonic server-local incarnation of that numeric lane.
    pub(crate) instance: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WebSocketLaneClaim {
    lane: CarrierLaneIdentity,
    peer_port: u16,
    connection_id: Option<u64>,
}

struct StreamState {
    instance: u64,
    inbound: VecDeque<InboundChunk>,
    receive_window: u32,
    send_credit: u64,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct QueuedFrame {
    encoded: BytesMut,
    frame_type: FrameType,
    stream_id: u32,
    control: bool,
    cost: usize,
}

struct DownBatch {
    body: Bytes,
    lease: Arc<resident::PendingResponseLease>,
    base_cursor: u64,
    next_cursor: u64,
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
    carrier_health_eligible: bool,
}

struct CarrierLane {
    instance: u64,
    pending_bytes: usize,
    pending_items: usize,
    resident: Arc<resident::ResidentCounters>,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    unacked: Option<DownBatch>,
    down_cursor: u64,
    down_epoch: u64,
    last_up_sequence: u64,
    last_up_digest: TokenHash,
    up_active: bool,
    notify: Arc<Notify>,
}

impl CarrierLane {
    fn new(instance: u64) -> Self {
        Self {
            instance,
            pending_bytes: 0,
            pending_items: 0,
            resident: Arc::new(resident::ResidentCounters::default()),
            pending_frames: VecDeque::new(),
            pending_windows: HashMap::new(),
            unacked: None,
            down_cursor: 0,
            down_epoch: 0,
            last_up_sequence: 0,
            last_up_digest: [0; 32],
            up_active: false,
            notify: Arc::new(Notify::new()),
        }
    }
}

struct SessionState {
    streams: HashMap<u32, StreamState>,
    closing_streams: HashMap<u32, u64>,
    next_stream_instance: u64,
    active_peer_ports: HashSet<u16>,
    closed_streams: HashSet<u32>,
    closed_order: VecDeque<u32>,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    unacked: Option<DownBatch>,
    down_cursor: u64,
    down_epoch: u64,
    last_up_sequence: u64,
    last_up_digest: TokenHash,
    carrier_lanes: HashMap<u32, CarrierLane>,
    lane_open_waits: usize,
    next_lane_instance: u64,
    websocket_lane_reservations: HashMap<u32, WebSocketLaneClaim>,
    pending_bytes: usize,
    pending_items: usize,
    pending_control_bytes: usize,
    pending_control_items: usize,
    last_activity: Instant,
    negotiation_phase: SessionNegotiationPhase,
    carrier_health_due_at: Option<Instant>,
    carrier_health_activity_at: Option<Instant>,
    carrier_health_uplink: bool,
    carrier_health_downlink: bool,
    carrier_commit_published: bool,
    carrier_health_reported: bool,
    websocket_carrier_active: bool,
    websocket_commit_ack_pending: bool,
    websocket_commit_ack_owner: Option<u64>,
    websocket_commit_ack_written: bool,
    websocket_probe_claimed: bool,
    close_requested: bool,
    closed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionNegotiationPhase {
    Uncommitted,
    Replacing,
    Committed,
    Superseded,
}

/// One bounded WEB carrier session containing logical MTProxy streams.
pub(crate) struct WebSession {
    manager: std::sync::Weak<WebProcessRuntime>,
    token_hash: TokenHash,
    client_ip: IpAddr,
    trace_session_id: u64,
    profile: Arc<WebRuntimeProfile>,
    profile_key: ProfileKey,
    selected_carrier: WebCarrier,
    carrier_attempt: u8,
    bootstrap_hash: TokenHash,
    carrier_deadline_at: Option<Instant>,
    carrier_class: CarrierClientClass,
    learning_context: Option<CarrierLearningContext>,
    automatic_carrier: bool,
    created_at: Instant,
    limits: WebLimitsConfig,
    timeouts: WebTimeoutsConfig,
    state: Mutex<SessionState>,
    down_notify: Arc<Notify>,
    lane_open_notify: Arc<Notify>,
    cancel: CancellationToken,
    tasks_live: AtomicUsize,
    tasks_done: Arc<Notify>,
    resident: Arc<resident::ResidentCounters>,
    finished: AtomicBool,
    up_active: AtomicBool,
}

/// One successful downlink poll result.
pub(crate) struct PollResult {
    /// Encoded downlink frame batch, or an empty long-poll result.
    pub(crate) body: Bytes,
    /// Cursor the client must present on its next downlink request.
    pub(crate) next_cursor: u64,
    /// Indicates that a drained non-zero lane no longer needs polling.
    pub(crate) lane_closed: bool,
}

impl WebSession {
    #[allow(clippy::too_many_arguments)]
    /// Creates one carrier session with immutable ownership and allocation policy.
    pub(crate) fn new(
        manager: std::sync::Weak<WebProcessRuntime>,
        token_hash: TokenHash,
        client_ip: IpAddr,
        trace_session_id: u64,
        profile: Arc<WebRuntimeProfile>,
        profile_key: ProfileKey,
        selected_carrier: WebCarrier,
        carrier_attempt: u8,
        bootstrap_hash: TokenHash,
        carrier_deadline_at: Option<Instant>,
        carrier_class: CarrierClientClass,
        learning_context: Option<CarrierLearningContext>,
        automatic_carrier: bool,
        limits: WebLimitsConfig,
        timeouts: WebTimeoutsConfig,
    ) -> Arc<Self> {
        let mut carrier_lanes = HashMap::new();
        let mut next_lane_instance = 1;
        if selected_carrier == WebCarrier::HttpsLanes {
            carrier_lanes.insert(0, CarrierLane::new(next_lane_instance));
            next_lane_instance += 1;
        }
        Arc::new(Self {
            manager,
            token_hash,
            client_ip,
            trace_session_id,
            profile,
            profile_key,
            selected_carrier,
            carrier_attempt,
            bootstrap_hash,
            carrier_deadline_at,
            carrier_class,
            learning_context,
            automatic_carrier,
            created_at: Instant::now(),
            limits,
            timeouts,
            state: Mutex::new(SessionState {
                streams: HashMap::new(),
                closing_streams: HashMap::new(),
                next_stream_instance: 1,
                active_peer_ports: HashSet::new(),
                closed_streams: HashSet::new(),
                closed_order: VecDeque::new(),
                pending_frames: VecDeque::new(),
                pending_windows: HashMap::new(),
                unacked: None,
                down_cursor: 0,
                down_epoch: 0,
                last_up_sequence: 0,
                last_up_digest: [0; 32],
                carrier_lanes,
                lane_open_waits: 0,
                next_lane_instance,
                websocket_lane_reservations: HashMap::new(),
                pending_bytes: 0,
                pending_items: 0,
                pending_control_bytes: 0,
                pending_control_items: 0,
                last_activity: Instant::now(),
                negotiation_phase: SessionNegotiationPhase::Uncommitted,
                carrier_health_due_at: None,
                carrier_health_activity_at: None,
                carrier_health_uplink: false,
                carrier_health_downlink: false,
                carrier_commit_published: false,
                carrier_health_reported: false,
                websocket_carrier_active: false,
                websocket_commit_ack_pending: false,
                websocket_commit_ack_owner: None,
                websocket_commit_ack_written: false,
                websocket_probe_claimed: false,
                close_requested: false,
                closed: false,
            }),
            down_notify: Arc::new(Notify::new()),
            lane_open_notify: Arc::new(Notify::new()),
            cancel: CancellationToken::new(),
            tasks_live: AtomicUsize::new(0),
            tasks_done: Arc::new(Notify::new()),
            resident: Arc::new(resident::ResidentCounters::default()),
            finished: AtomicBool::new(false),
            up_active: AtomicBool::new(false),
        })
    }

    /// Returns the stable hashed token identity without exposing the credential.
    pub(crate) fn token_hash(&self) -> TokenHash {
        self.token_hash
    }

    /// Checks the canonical virtual host that owns this bearer session.
    pub(crate) fn matches_host(&self, host: &str) -> bool {
        self.profile.host == host
    }

    /// Returns the immutable carrier selected when this session was created.
    pub(crate) fn carrier(&self) -> WebCarrier {
        self.selected_carrier
    }

    /// Returns the stable quota owner without exposing profile credentials.
    pub(crate) fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// Returns the process-unique non-secret trace identifier.
    pub(crate) fn trace_session_id(&self) -> u64 {
        self.trace_session_id
    }

    /// Returns the immutable carrier-attempt incarnation number.
    pub(crate) fn carrier_attempt(&self) -> u8 {
        self.carrier_attempt
    }

    /// Creates a child cancellation boundary for one owned carrier task.
    pub(crate) fn carrier_cancellation(&self) -> CancellationToken {
        self.cancel.child_token()
    }

    /// Returns a cloned non-secret identity only for enabled debug capture.
    pub(crate) fn trace_identity(&self) -> crate::web::trace::TraceIdentity {
        crate::web::trace::TraceIdentity::from_profile(self.trace_session_id, &self.profile)
    }

    /// Records one typed lifecycle event without exposing session credentials.
    pub(super) fn trace_lifecycle(
        &self,
        event: crate::web::trace::TraceLifecycleEvent,
        stream_id: Option<u32>,
        reason: Option<&'static str>,
    ) {
        if let Some(manager) = self.manager.upgrade() {
            manager.trace().record_profile_lifecycle(
                self.client_ip,
                Some(self.trace_session_id),
                &self.profile,
                event,
                stream_id,
                reason,
            );
        }
    }

    /// Returns the immutable limits frozen when this carrier chain was created.
    pub(crate) fn limits(&self) -> &WebLimitsConfig {
        &self.limits
    }

    /// Returns the immutable timeouts frozen when this carrier chain was created.
    pub(crate) fn timeouts(&self) -> &WebTimeoutsConfig {
        &self.timeouts
    }

    /// Polls client-to-server bytes and returns consumed flow-control credit.
    pub(super) fn poll_read(
        &self,
        stream: StreamIdentity,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock();
        let (count, finished) = {
            let Some(stream_state) = state
                .streams
                .get_mut(&stream.id)
                .filter(|state| state.instance == stream.instance)
            else {
                return Poll::Ready(Ok(()));
            };
            let Some(chunk) = stream_state.inbound.front_mut() else {
                stream_state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let available = &chunk.bytes[chunk.offset..];
            let count = available.len().min(output.remaining());
            output.put_slice(&available[..count]);
            chunk.offset += count;
            let finished = chunk.offset == chunk.bytes.len();
            if finished {
                stream_state.inbound.pop_front();
            }
            stream_state.receive_window = stream_state.receive_window.saturating_add(count as u32);
            (count, finished)
        };
        let overhead = if finished { QUEUE_ITEM_COST } else { 0 };
        self.release_locked(&mut state, count + overhead, usize::from(finished), false);
        if !self.queue_window_locked(&mut state, stream.id, count as u32) {
            drop(state);
            self.close();
            return Poll::Ready(Err(io::Error::other(
                "WEB session control budget exhausted",
            )));
        }
        Poll::Ready(Ok(()))
    }

    /// Polls server-to-client writes against stream credit and bounded queues.
    pub(super) fn poll_write(
        &self,
        stream: StreamIdentity,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.state.lock();
        let Some(stream_state) = state
            .streams
            .get_mut(&stream.id)
            .filter(|state| state.instance == stream.instance)
        else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WEB logical stream is closed",
            )));
        };
        let count = input
            .len()
            .min(frame::DATA_CHUNK_BYTES)
            .min(self.limits.max_frame_payload_bytes)
            .min(if self.carrier().uses_lanes() {
                self.limits
                    .pending_bytes_per_lane
                    .saturating_sub(frame::HEADER_BYTES + QUEUE_ITEM_COST)
            } else {
                usize::MAX
            })
            .min(stream_state.send_credit as usize);
        if count == 0 {
            stream_state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if !self.queue_data_locked(&mut state, stream.id, &input[..count]) {
            if let Some(stream_state) = state
                .streams
                .get_mut(&stream.id)
                .filter(|state| state.instance == stream.instance)
            {
                stream_state.write_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let Some(stream_state) = state
            .streams
            .get_mut(&stream.id)
            .filter(|state| state.instance == stream.instance)
        else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WEB logical stream is closed",
            )));
        };
        stream_state.send_credit -= count as u64;
        state.last_activity = Instant::now();
        drop(state);
        if self.carrier().is_multiplexed() {
            self.down_notify.notify_waiters();
        }
        Poll::Ready(Ok(count))
    }

    /// Returns the process queue-capacity notification source while the manager lives.
    pub(super) fn budget_notify(&self) -> Option<Arc<Notify>> {
        self.manager
            .upgrade()
            .map(|manager| manager.budget_notify())
    }
}

fn inbound_queue_cost(queue: &VecDeque<InboundChunk>) -> (usize, usize) {
    let bytes = queue.iter().fold(0usize, |total, chunk| {
        total.saturating_add(chunk.bytes.len().saturating_sub(chunk.offset) + QUEUE_ITEM_COST)
    });
    (bytes, queue.len())
}

fn remember_closed(state: &mut SessionState, stream_id: u32, limit: usize) -> Option<u32> {
    if !state.closed_streams.insert(stream_id) {
        return None;
    }
    state.closed_order.push_back(stream_id);
    let mut evicted = None;
    while state.closed_order.len() > limit {
        if let Some(oldest) = state.closed_order.pop_front() {
            state.closed_streams.remove(&oldest);
            evicted = Some(oldest);
        }
    }
    evicted
}

fn insert_carrier_lane(state: &mut SessionState, lane_id: u32) -> Option<CarrierLaneIdentity> {
    if state.carrier_lanes.contains_key(&lane_id) {
        return None;
    }
    let instance = state.next_lane_instance;
    state.next_lane_instance = instance.checked_add(1)?;
    state
        .carrier_lanes
        .insert(lane_id, CarrierLane::new(instance));
    Some(CarrierLaneIdentity { lane_id, instance })
}
