use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::ReadBuf;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::{WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebTimeoutsConfig};
use crate::web::frame::{self, FrameType};
use crate::web::manager::{ProfileKey, TokenHash, WebProcessRuntime};

// Backend tasks own generation admission and authenticated MTProxy relay lifetimes.
mod backend;
// Downlink queues own cursor replay, flow control, and memory reservations.
mod downlink;
// Lane carrier state isolates request sequencing and downlink replay per logical stream.
mod lanes;
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

struct StreamState {
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
    base_cursor: u64,
    next_cursor: u64,
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
}

struct CarrierLane {
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
    fn new() -> Self {
        Self {
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
    pending_bytes: usize,
    pending_items: usize,
    pending_control_bytes: usize,
    pending_control_items: usize,
    last_activity: Instant,
    closed: bool,
}

/// One bounded WEB carrier session containing logical MTProxy streams.
pub(crate) struct WebSession {
    manager: std::sync::Weak<WebProcessRuntime>,
    token_hash: TokenHash,
    client_ip: IpAddr,
    profile: Arc<WebRuntimeProfile>,
    profile_key: ProfileKey,
    limits: WebLimitsConfig,
    timeouts: WebTimeoutsConfig,
    state: Mutex<SessionState>,
    down_notify: Arc<Notify>,
    cancel: CancellationToken,
    tasks_live: AtomicUsize,
    tasks_done: Arc<Notify>,
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
        profile: Arc<WebRuntimeProfile>,
        profile_key: ProfileKey,
        limits: WebLimitsConfig,
        timeouts: WebTimeoutsConfig,
    ) -> Arc<Self> {
        let mut carrier_lanes = HashMap::new();
        if profile.carrier == WebCarrier::HttpsLanes {
            carrier_lanes.insert(0, CarrierLane::new());
        }
        Arc::new(Self {
            manager,
            token_hash,
            client_ip,
            profile,
            profile_key,
            limits,
            timeouts,
            state: Mutex::new(SessionState {
                streams: HashMap::new(),
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
                pending_bytes: 0,
                pending_items: 0,
                pending_control_bytes: 0,
                pending_control_items: 0,
                last_activity: Instant::now(),
                closed: false,
            }),
            down_notify: Arc::new(Notify::new()),
            cancel: CancellationToken::new(),
            tasks_live: AtomicUsize::new(0),
            tasks_done: Arc::new(Notify::new()),
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
        self.profile.carrier
    }

    /// Closes carrier state while relay tasks retain their admission until exit.
    pub(crate) fn close(&self) {
        let (data_bytes, data_items, control_bytes, control_items) = {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            state.closed = true;
            for stream in state.streams.values_mut() {
                if let Some(waker) = stream.read_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = stream.write_waker.take() {
                    waker.wake();
                }
            }
            state.streams.clear();
            state.pending_frames.clear();
            state.pending_windows.clear();
            state.unacked = None;
            for lane in state.carrier_lanes.values() {
                lane.notify.notify_waiters();
            }
            state.carrier_lanes.clear();
            let control_bytes = state.pending_control_bytes;
            let control_items = state.pending_control_items;
            let data_bytes = state.pending_bytes.saturating_sub(control_bytes);
            let data_items = state.pending_items.saturating_sub(control_items);
            state.pending_bytes = 0;
            state.pending_items = 0;
            state.pending_control_bytes = 0;
            state.pending_control_items = 0;
            (data_bytes, data_items, control_bytes, control_items)
        };
        self.cancel.cancel();
        if self.carrier() == WebCarrier::Https {
            self.down_notify.notify_waiters();
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.release_pending(data_bytes, data_items, false);
            manager.release_pending(control_bytes, control_items, true);
            if !self.finished.swap(true, Ordering::AcqRel) {
                manager.session_finished(
                    self.token_hash,
                    self.client_ip,
                    self.profile_key,
                    &self.profile.host,
                );
            }
        }
    }

    /// Waits for all logical-stream tasks after admission has closed.
    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.tasks_done.notified();
            if self.tasks_live.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Returns whether reconnect grace elapsed without activity.
    pub(crate) fn is_idle(&self, now: Instant) -> bool {
        let state = self.state.lock();
        !state.closed
            && now.saturating_duration_since(state.last_activity)
                >= Duration::from_secs(self.timeouts.reconnect_grace_secs)
    }

    /// Polls client-to-server bytes and returns consumed flow-control credit.
    pub(super) fn poll_read(
        &self,
        stream_id: u32,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock();
        let (count, finished) = {
            let Some(stream) = state.streams.get_mut(&stream_id) else {
                return Poll::Ready(Ok(()));
            };
            let Some(chunk) = stream.inbound.front_mut() else {
                stream.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let available = &chunk.bytes[chunk.offset..];
            let count = available.len().min(output.remaining());
            output.put_slice(&available[..count]);
            chunk.offset += count;
            let finished = chunk.offset == chunk.bytes.len();
            if finished {
                stream.inbound.pop_front();
            }
            stream.receive_window = stream.receive_window.saturating_add(count as u32);
            (count, finished)
        };
        let overhead = if finished { QUEUE_ITEM_COST } else { 0 };
        self.release_locked(&mut state, count + overhead, usize::from(finished), false);
        if !self.queue_window_locked(&mut state, stream_id, count as u32) {
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
        stream_id: u32,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.state.lock();
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WEB logical stream is closed",
            )));
        };
        let count = input
            .len()
            .min(frame::DATA_CHUNK_BYTES)
            .min(self.limits.max_frame_payload_bytes)
            .min(stream.send_credit as usize);
        if count == 0 {
            stream.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if !self.queue_data_locked(&mut state, stream_id, &input[..count]) {
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.write_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WEB logical stream is closed",
            )));
        };
        stream.send_credit -= count as u64;
        state.last_activity = Instant::now();
        drop(state);
        if self.carrier() == WebCarrier::Https {
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

    fn release_stream_reservation(&self, peer_port: u16) {
        let removed = self.state.lock().active_peer_ports.remove(&peer_port);
        if removed && let Some(manager) = self.manager.upgrade() {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
        }
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
