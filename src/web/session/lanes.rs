use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::uplink::{inbound_reservation, validate_batch};
use super::{
    CarrierLane, DownBatch, PendingClass, PollResult, QUEUE_ITEM_COST, QueuedFrame, SessionState,
    WebSession, remember_closed,
};
use crate::config::{WebCarrier, WebLimitsConfig};
use crate::web::frame::{self, Frame, FrameType};
use crate::web::manager::{ManagerError, TokenHash};

impl WebSession {
    /// Applies one exactly-once uplink batch to an independent HTTPS lane.
    pub(crate) fn process_up_lane(
        self: &Arc<Self>,
        lane_id: u32,
        sequence: u64,
        body: &[u8],
    ) -> Result<u64, ManagerError> {
        if self.carrier() != WebCarrier::HttpsLanes || lane_id > frame::MAX_STREAM_ID {
            return Err(ManagerError::Protocol);
        }
        let frames = match frame::parse_all(body, &self.limits) {
            Ok(frames) => frames,
            Err(_) => {
                self.close();
                return Err(ManagerError::Protocol);
            }
        };
        if frames
            .iter()
            .copied()
            .any(|value| value.stream_id != lane_id || frame::validate_client_shape(value).is_err())
        {
            self.close();
            return Err(ManagerError::Protocol);
        }
        let digest: TokenHash = Sha256::digest(body).into();
        let mut opened = Vec::new();
        let result = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            state.last_activity = Instant::now();
            if !state.carrier_lanes.contains_key(&lane_id) {
                if lane_id != 0
                    && frames
                        .first()
                        .is_some_and(|value| value.frame_type != FrameType::Open)
                    && only_late_frames(&frames)
                {
                    return Ok(sequence);
                }
                if lane_id == 0
                    || frames
                        .first()
                        .is_none_or(|value| value.frame_type != FrameType::Open)
                {
                    drop(state);
                    self.close();
                    return Err(ManagerError::Protocol);
                }
                state.carrier_lanes.insert(lane_id, CarrierLane::new());
            }
            let lane = state
                .carrier_lanes
                .get_mut(&lane_id)
                .ok_or(ManagerError::Protocol)?;
            if sequence == lane.last_up_sequence && sequence != 0 {
                return if bool::from(lane.last_up_digest.ct_eq(&digest)) {
                    Ok(sequence)
                } else {
                    drop(state);
                    self.close();
                    Err(ManagerError::Protocol)
                };
            }
            if sequence == 0 || sequence != lane.last_up_sequence.saturating_add(1) {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            if lane.up_active {
                return Err(ManagerError::Concurrent);
            }
            lane.up_active = true;
            if !validate_batch(&state, &frames) {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            let (reserve_bytes, reserve_items) = inbound_reservation(&state, &frames);
            if !self.reserve_locked(
                &mut state,
                reserve_bytes,
                reserve_items,
                PendingClass::Uplink,
            ) {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                return Err(ManagerError::Backpressure);
            }
            let mut unused_bytes = reserve_bytes;
            let mut unused_items = reserve_items;
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut opened,
                &mut unused_bytes,
                &mut unused_items,
            );
            self.release_locked(&mut state, unused_bytes, unused_items, false);
            if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                lane.up_active = false;
                if applied {
                    lane.last_up_sequence = sequence;
                    lane.last_up_digest = digest;
                }
            }
            applied.then_some(sequence).ok_or(ManagerError::Closed)
        };
        if matches!(result, Err(ManagerError::Backpressure)) {
            return result;
        }
        if result.is_err() {
            self.close();
            for (_, peer_port) in opened {
                self.release_stream_reservation(peer_port);
            }
            return result;
        }
        for (stream_id, peer_port) in opened {
            self.spawn_stream(stream_id, peer_port);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        result
    }

    /// Polls one lane with independent cursor replay and newest-poll-wins semantics.
    pub(crate) async fn poll_down_lane(
        &self,
        lane_id: u32,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        if self.carrier() != WebCarrier::HttpsLanes || lane_id > frame::MAX_STREAM_ID {
            return Err(ManagerError::Protocol);
        }
        let (epoch, notify) = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            let acknowledged = {
                let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                    return Err(ManagerError::Protocol);
                };
                if let Some(unacked) = &lane.unacked {
                    if cursor == unacked.base_cursor {
                        return Ok(PollResult {
                            body: unacked.body.clone(),
                            next_cursor: unacked.next_cursor,
                            lane_closed: false,
                        });
                    }
                    if cursor != unacked.next_cursor {
                        drop(state);
                        self.close();
                        return Err(ManagerError::Protocol);
                    }
                    lane.unacked.take()
                } else {
                    if cursor != lane.down_cursor {
                        drop(state);
                        self.close();
                        return Err(ManagerError::Protocol);
                    }
                    None
                }
            };
            if let Some(batch) = acknowledged {
                self.release_locked(&mut state, batch.data_bytes, batch.data_items, false);
                self.release_locked(&mut state, batch.control_bytes, batch.control_items, true);
                if let Some(stream) = state.streams.get_mut(&lane_id)
                    && let Some(waker) = stream.write_waker.take()
                {
                    waker.wake();
                }
            }
            state.last_activity = Instant::now();
            let lane = state
                .carrier_lanes
                .get_mut(&lane_id)
                .ok_or(ManagerError::Protocol)?;
            lane.down_epoch = lane.down_epoch.wrapping_add(1).max(1);
            (lane.down_epoch, Arc::clone(&lane.notify))
        };
        notify.notify_waiters();

        let deadline = Duration::from_secs(self.timeouts.long_poll_secs);
        let poll = async {
            loop {
                let notified = notify.notified();
                {
                    let mut state = self.state.lock();
                    if state.closed {
                        return Err(ManagerError::Closed);
                    }
                    let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    };
                    if lane.down_epoch != epoch {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: false,
                        });
                    }
                    if !lane.pending_frames.is_empty() {
                        let batch = match take_lane_down_batch(&self.limits, lane, cursor) {
                            Ok(batch) => batch,
                            Err(error) => {
                                drop(state);
                                self.close();
                                return Err(error);
                            }
                        };
                        let result = PollResult {
                            body: batch.body.clone(),
                            next_cursor: batch.next_cursor,
                            lane_closed: false,
                        };
                        lane.unacked = Some(batch);
                        drop(state);
                        if let Some(manager) = self.manager.upgrade() {
                            manager.record_down(result.body.len());
                        }
                        return Ok(result);
                    }
                    if lane_id != 0
                        && !state.streams.contains_key(&lane_id)
                        && state.closed_streams.contains(&lane_id)
                    {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                }
                notified.await;
            }
        };
        match tokio::time::timeout(deadline, poll).await {
            Ok(result) => result,
            Err(_) => {
                let mut state = self.state.lock();
                if state.closed {
                    return Err(ManagerError::Closed);
                }
                if !state.carrier_lanes.contains_key(&lane_id) {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if lane_id != 0
                    && !state.streams.contains_key(&lane_id)
                    && state.closed_streams.contains(&lane_id)
                {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if state
                    .carrier_lanes
                    .get(&lane_id)
                    .is_some_and(|lane| lane.down_epoch == epoch)
                {
                    state.last_activity = Instant::now();
                }
                Ok(PollResult {
                    body: Bytes::new(),
                    next_cursor: cursor,
                    lane_closed: false,
                })
            }
        }
    }

    pub(super) fn queue_lane_frame_locked(
        &self,
        state: &mut SessionState,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
        control: bool,
    ) -> bool {
        if !state.carrier_lanes.contains_key(&stream_id) {
            return false;
        }
        if frame_type == FrameType::Window {
            let coalesced = state.carrier_lanes.get(&stream_id).and_then(|lane| {
                let index = lane.pending_windows.get(&stream_id).copied()?;
                let queued = lane.pending_frames.get(index)?;
                let previous = u32::from_be_bytes(
                    queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                previous
                    .checked_add(frame::window_amount(payload).unwrap_or(0))
                    .map(|total| (index, total))
            });
            if let Some((index, total)) = coalesced
                && let Some(lane) = state.carrier_lanes.get_mut(&stream_id)
                && let Some(queued) = lane.pending_frames.get_mut(index)
            {
                queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                    .copy_from_slice(&total.to_be_bytes());
                lane.notify.notify_waiters();
                return true;
            }
        }
        let can_coalesce = frame_type == FrameType::Data
            && state
                .carrier_lanes
                .get(&stream_id)
                .and_then(|lane| lane.pending_frames.back())
                .is_some_and(|last| {
                    last.frame_type == FrameType::Data
                        && last.stream_id == stream_id
                        && last.encoded.len() - frame::HEADER_BYTES + payload.len()
                            <= self.limits.max_frame_payload_bytes
                });
        if can_coalesce {
            if !self.reserve_locked(state, payload.len(), 0, PendingClass::Downlink) {
                return false;
            }
            let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
                self.release_locked(state, payload.len(), 0, false);
                return false;
            };
            let Some(last) = lane.pending_frames.back_mut() else {
                self.release_locked(state, payload.len(), 0, false);
                return false;
            };
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len();
            let payload_len = (last.encoded.len() - frame::HEADER_BYTES) as u32;
            last.encoded[4..8].copy_from_slice(&payload_len.to_be_bytes());
            lane.notify.notify_waiters();
            return true;
        }
        let cost = frame::HEADER_BYTES + payload.len() + QUEUE_ITEM_COST;
        let class = if control {
            PendingClass::Control
        } else {
            PendingClass::Downlink
        };
        if !self.reserve_locked(state, cost, 1, class) {
            return false;
        }
        let mut encoded = BytesMut::with_capacity(frame::HEADER_BYTES + payload.len());
        encoded.put_u8(frame_type as u8);
        encoded.put_u8((stream_id >> 16) as u8);
        encoded.put_u8((stream_id >> 8) as u8);
        encoded.put_u8(stream_id as u8);
        encoded.put_u32(payload.len() as u32);
        encoded.extend_from_slice(payload);
        let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
            self.release_locked(state, cost, 1, control);
            return false;
        };
        let index = lane.pending_frames.len();
        lane.pending_frames.push_back(QueuedFrame {
            encoded,
            frame_type,
            stream_id,
            control,
            cost,
        });
        if frame_type == FrameType::Window {
            lane.pending_windows.insert(stream_id, index);
        }
        lane.notify.notify_waiters();
        true
    }

    pub(super) fn remember_closed_locked(&self, state: &mut SessionState, stream_id: u32) {
        let evicted = remember_closed(state, stream_id, self.limits.max_tombstones_per_session);
        if self.carrier() != WebCarrier::HttpsLanes {
            return;
        }
        if let Some(evicted) = evicted {
            self.release_lane_locked(state, evicted);
        }
        if let Some(lane) = state.carrier_lanes.get(&stream_id) {
            lane.notify.notify_waiters();
        }
    }

    fn release_lane_locked(&self, state: &mut SessionState, lane_id: u32) {
        let Some(mut lane) = state.carrier_lanes.remove(&lane_id) else {
            return;
        };
        lane.notify.notify_waiters();
        let mut data_bytes = 0usize;
        let mut data_items = 0usize;
        let mut control_bytes = 0usize;
        let mut control_items = 0usize;
        for queued in lane.pending_frames.drain(..) {
            if queued.control {
                control_bytes = control_bytes.saturating_add(queued.cost);
                control_items = control_items.saturating_add(1);
            } else {
                data_bytes = data_bytes.saturating_add(queued.cost);
                data_items = data_items.saturating_add(1);
            }
        }
        if let Some(batch) = lane.unacked.take() {
            data_bytes = data_bytes.saturating_add(batch.data_bytes);
            data_items = data_items.saturating_add(batch.data_items);
            control_bytes = control_bytes.saturating_add(batch.control_bytes);
            control_items = control_items.saturating_add(batch.control_items);
        }
        self.release_locked(state, data_bytes, data_items, false);
        self.release_locked(state, control_bytes, control_items, true);
    }
}

fn only_late_frames(frames: &[Frame<'_>]) -> bool {
    frames.iter().all(|value| {
        matches!(
            value.frame_type,
            FrameType::Data | FrameType::Window | FrameType::Close
        )
    })
}

fn take_lane_down_batch(
    limits: &WebLimitsConfig,
    lane: &mut CarrierLane,
    cursor: u64,
) -> Result<DownBatch, ManagerError> {
    let next_cursor = lane
        .down_cursor
        .checked_add(1)
        .ok_or(ManagerError::Protocol)?;
    let mut count = 0usize;
    let mut body_len = 0usize;
    for queued in &lane.pending_frames {
        if count >= limits.max_frames_per_body
            || (count != 0
                && body_len.saturating_add(queued.encoded.len()) > limits.carrier_batch_bytes)
        {
            break;
        }
        body_len += queued.encoded.len();
        count += 1;
    }
    let mut body = BytesMut::with_capacity(body_len);
    let mut data_bytes = 0usize;
    let mut data_items = 0usize;
    let mut control_bytes = 0usize;
    let mut control_items = 0usize;
    for index in 0..count {
        let Some(queued) = lane.pending_frames.get(index) else {
            break;
        };
        if queued.frame_type == FrameType::Window
            && lane.pending_windows.get(&queued.stream_id) == Some(&index)
        {
            lane.pending_windows.remove(&queued.stream_id);
        }
    }
    for _ in 0..count {
        let Some(queued) = lane.pending_frames.pop_front() else {
            break;
        };
        body.extend_from_slice(&queued.encoded);
        if queued.control {
            control_bytes += queued.cost;
            control_items += 1;
        } else {
            data_bytes += queued.cost;
            data_items += 1;
        }
    }
    for index in lane.pending_windows.values_mut() {
        *index = index.saturating_sub(count);
    }
    lane.down_cursor = next_cursor;
    Ok(DownBatch {
        body: body.freeze(),
        base_cursor: cursor,
        next_cursor,
        data_bytes,
        data_items,
        control_bytes,
        control_items,
    })
}

// Lane-specific protocol, replay, and lifecycle tests.
#[cfg(test)]
mod tests;
