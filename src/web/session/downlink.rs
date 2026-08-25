use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use super::{
    DownBatch, PendingClass, PollResult, QUEUE_ITEM_COST, QueuedFrame, SessionState, WebSession,
};
use crate::config::WebCarrier;
use crate::web::frame::{self, FrameType};
use crate::web::manager::ManagerError;

impl WebSession {
    /// Polls pending downlink frames with cursor replay and newest-poll-wins semantics.
    pub(crate) async fn poll_down(&self, cursor: u64) -> Result<PollResult, ManagerError> {
        if self.carrier() != WebCarrier::Https {
            return Err(ManagerError::Protocol);
        }
        let epoch = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            state.last_activity = Instant::now();
            if let Some(unacked) = &state.unacked {
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
                self.release_unacked_locked(&mut state);
            } else if cursor != state.down_cursor {
                drop(state);
                self.close();
                return Err(ManagerError::Protocol);
            }
            state.down_epoch = state.down_epoch.wrapping_add(1).max(1);
            state.down_epoch
        };
        self.down_notify.notify_waiters();

        let deadline = Duration::from_secs(self.timeouts.long_poll_secs);
        let poll = async {
            loop {
                let notified = self.down_notify.notified();
                {
                    let mut state = self.state.lock();
                    if state.down_epoch != epoch {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: false,
                        });
                    }
                    if !state.pending_frames.is_empty() {
                        let batch = match self.take_down_batch_locked(&mut state, cursor) {
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
                        if let Some(manager) = self.manager.upgrade() {
                            manager.record_down(result.body.len());
                        }
                        state.unacked = Some(batch);
                        return Ok(result);
                    }
                    if state.closed {
                        return Err(ManagerError::Closed);
                    }
                }
                notified.await;
            }
        };
        match tokio::time::timeout(deadline, poll).await {
            Ok(result) => result,
            Err(_) => {
                let mut state = self.state.lock();
                if state.down_epoch == epoch {
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

    /// Reserves session and process queue capacity while the session lock is held.
    pub(super) fn reserve_locked(
        &self,
        state: &mut SessionState,
        bytes: usize,
        items: usize,
        class: PendingClass,
    ) -> bool {
        if bytes == 0 && items == 0 {
            return true;
        }
        let data_byte_limit = self
            .limits
            .pending_bytes_per_session
            .saturating_sub(self.limits.control_bytes_per_session);
        let item_reserve =
            16usize.saturating_add(self.limits.max_streams_per_session.saturating_mul(3));
        let data_item_limit = self
            .limits
            .pending_items_per_session
            .saturating_sub(item_reserve);
        if state.closed {
            return false;
        }
        let control = class == PendingClass::Control;
        let fits = if control {
            bytes <= self.limits.control_bytes_per_session
                && items <= item_reserve
                && state.pending_bytes
                    <= self.limits.pending_bytes_per_session.saturating_sub(bytes)
                && state.pending_items
                    <= self.limits.pending_items_per_session.saturating_sub(items)
                && state.pending_control_bytes
                    <= self.limits.control_bytes_per_session.saturating_sub(bytes)
                && state.pending_control_items <= item_reserve.saturating_sub(items)
        } else {
            let data_bytes = state
                .pending_bytes
                .saturating_sub(state.pending_control_bytes);
            let data_items = state
                .pending_items
                .saturating_sub(state.pending_control_items);
            let (byte_limit, item_limit) = if class == PendingClass::Downlink {
                let uplink_bytes = self.limits.max_body_bytes.saturating_add(
                    self.limits
                        .max_frames_per_body
                        .saturating_mul(QUEUE_ITEM_COST),
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
            return false;
        }
        let Some(manager) = self.manager.upgrade() else {
            return false;
        };
        if !manager.try_reserve_pending(bytes, items, control, class == PendingClass::Downlink) {
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

    /// Releases session and process queue capacity while the session lock is held.
    pub(super) fn release_locked(
        &self,
        state: &mut SessionState,
        bytes: usize,
        items: usize,
        control: bool,
    ) {
        state.pending_bytes = state.pending_bytes.saturating_sub(bytes);
        state.pending_items = state.pending_items.saturating_sub(items);
        if control {
            state.pending_control_bytes = state.pending_control_bytes.saturating_sub(bytes);
            state.pending_control_items = state.pending_control_items.saturating_sub(items);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.release_pending(bytes, items, control);
        }
    }

    /// Coalesces one flow-control update into the bounded control queue.
    pub(super) fn queue_window_locked(
        &self,
        state: &mut SessionState,
        stream_id: u32,
        amount: u32,
    ) -> bool {
        if amount == 0 {
            return true;
        }
        if self.carrier() == WebCarrier::HttpsLanes {
            return self.queue_control_locked(
                state,
                FrameType::Window,
                stream_id,
                &frame::window_payload(amount),
            );
        }
        if let Some(index) = state.pending_windows.get(&stream_id).copied()
            && let Some(queued) = state.pending_frames.get_mut(index)
        {
            let previous = u32::from_be_bytes(
                queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            if let Some(total) = previous.checked_add(amount) {
                queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                    .copy_from_slice(&total.to_be_bytes());
                self.down_notify.notify_waiters();
                return true;
            }
        }
        self.queue_control_locked(
            state,
            FrameType::Window,
            stream_id,
            &frame::window_payload(amount),
        )
    }

    /// Appends one control frame under both reserved queue budgets.
    pub(super) fn queue_control_locked(
        &self,
        state: &mut SessionState,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
    ) -> bool {
        self.queue_frame_locked(state, frame_type, stream_id, payload, true)
    }

    /// Appends one server-to-client DATA frame under downlink data budgets.
    pub(super) fn queue_data_locked(
        &self,
        state: &mut SessionState,
        stream_id: u32,
        payload: &[u8],
    ) -> bool {
        if self.carrier() == WebCarrier::HttpsLanes {
            return self.queue_frame_locked(state, FrameType::Data, stream_id, payload, false);
        }
        let can_coalesce = state.pending_frames.back().is_some_and(|last| {
            last.frame_type == FrameType::Data
                && last.stream_id == stream_id
                && last.encoded.len() - frame::HEADER_BYTES + payload.len()
                    <= self.limits.max_frame_payload_bytes
        });
        if can_coalesce {
            if !self.reserve_locked(state, payload.len(), 0, PendingClass::Downlink) {
                return false;
            }
            let Some(last) = state.pending_frames.back_mut() else {
                return false;
            };
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len();
            let payload_len = (last.encoded.len() - frame::HEADER_BYTES) as u32;
            last.encoded[4..8].copy_from_slice(&payload_len.to_be_bytes());
            return true;
        }
        self.queue_frame_locked(state, FrameType::Data, stream_id, payload, false)
    }

    fn queue_frame_locked(
        &self,
        state: &mut SessionState,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
        control: bool,
    ) -> bool {
        if self.carrier() == WebCarrier::HttpsLanes {
            return self.queue_lane_frame_locked(state, frame_type, stream_id, payload, control);
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
        let index = state.pending_frames.len();
        state.pending_frames.push_back(QueuedFrame {
            encoded,
            frame_type,
            stream_id,
            control,
            cost,
        });
        if frame_type == FrameType::Window {
            state.pending_windows.insert(stream_id, index);
        }
        self.down_notify.notify_waiters();
        true
    }

    fn take_down_batch_locked(
        &self,
        state: &mut SessionState,
        cursor: u64,
    ) -> Result<DownBatch, ManagerError> {
        let next_cursor = state
            .down_cursor
            .checked_add(1)
            .ok_or(ManagerError::Protocol)?;
        let mut count = 0usize;
        let mut body_len = 0usize;
        for queued in &state.pending_frames {
            if count >= self.limits.max_frames_per_body
                || (count != 0
                    && body_len.saturating_add(queued.encoded.len())
                        > self.limits.carrier_batch_bytes)
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
            let Some(queued) = state.pending_frames.get(index) else {
                break;
            };
            if queued.frame_type == FrameType::Window
                && state.pending_windows.get(&queued.stream_id) == Some(&index)
            {
                state.pending_windows.remove(&queued.stream_id);
            }
        }
        for _ in 0..count {
            let Some(queued) = state.pending_frames.pop_front() else {
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
        for index in state.pending_windows.values_mut() {
            *index = index.saturating_sub(count);
        }
        state.down_cursor = next_cursor;
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

    fn release_unacked_locked(&self, state: &mut SessionState) {
        let Some(batch) = state.unacked.take() else {
            return;
        };
        self.release_locked(state, batch.data_bytes, batch.data_items, false);
        self.release_locked(state, batch.control_bytes, batch.control_items, true);
        for stream in state.streams.values_mut() {
            if let Some(waker) = stream.write_waker.take() {
                waker.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::config::{WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig};
    use crate::web::manager::WebProcessRuntime;

    fn session() -> Arc<WebSession> {
        let profile = Arc::new(WebRuntimeProfile {
            host: "proxy.example.com".to_string(),
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::Https,
            capability: [0; 32],
            max_sessions: 1,
            max_streams: 1,
            max_streams_per_session: 1,
        });
        WebSession::new(
            std::sync::Weak::<WebProcessRuntime>::new(),
            [1; 32],
            "192.0.2.10".parse().unwrap(),
            profile,
            [2; 32],
            WebLimitsConfig::default(),
            WebTimeoutsConfig::default(),
        )
    }

    fn queue_close(session: &WebSession) {
        let encoded = frame::encode(FrameType::Close, 1, &[]);
        session.state.lock().pending_frames.push_back(QueuedFrame {
            encoded: BytesMut::from(encoded.as_ref()),
            frame_type: FrameType::Close,
            stream_id: 1,
            control: true,
            cost: frame::HEADER_BYTES + QUEUE_ITEM_COST,
        });
    }

    #[tokio::test]
    async fn downlink_replays_unacknowledged_batch_byte_for_byte() {
        let session = session();
        queue_close(&session);
        let first = session.poll_down(0).await.unwrap();
        let replay = session.poll_down(0).await.unwrap();
        assert_eq!(first.next_cursor, 1);
        assert_eq!(replay.next_cursor, 1);
        assert_eq!(first.body, replay.body);
    }

    #[tokio::test]
    async fn invalid_or_overflowing_cursor_closes_session() {
        let invalid = session();
        assert!(matches!(
            invalid.poll_down(1).await,
            Err(ManagerError::Protocol)
        ));
        assert!(invalid.state.lock().closed);

        let overflow = session();
        {
            let mut state = overflow.state.lock();
            state.down_cursor = u64::MAX;
        }
        queue_close(&overflow);
        assert!(matches!(
            overflow.poll_down(u64::MAX).await,
            Err(ManagerError::Protocol)
        ));
        assert!(overflow.state.lock().closed);
    }

    #[tokio::test]
    async fn newer_poll_supersedes_older_poll_without_closing_session() {
        let session = session();
        let first_session = Arc::clone(&session);
        let first = tokio::spawn(async move { first_session.poll_down(0).await });
        while session.state.lock().down_epoch < 1 {
            tokio::task::yield_now().await;
        }
        let second_session = Arc::clone(&session);
        let second = tokio::spawn(async move { second_session.poll_down(0).await });
        while session.state.lock().down_epoch < 2 {
            tokio::task::yield_now().await;
        }
        let superseded = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(superseded.body.is_empty());
        assert_eq!(superseded.next_cursor, 0);
        assert!(!session.state.lock().closed);
        second.abort();
    }
}
