use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::uplink::{inbound_reservation, validate_batch};
use super::{PendingClass, WebSession, inbound_queue_cost, insert_carrier_lane};
use crate::config::WebCarrier;
use crate::web::frame;
use crate::web::manager::ManagerError;

/// Pre-OPEN stream quota and synthetic tuple ownership for one WebSocket lane.
pub(crate) struct WebSocketLaneReservation {
    session: Arc<WebSession>,
    lane_id: u32,
    peer_port: u16,
    transferred: bool,
}

impl WebSocketLaneReservation {
    /// Returns the logical stream owned by this connection.
    pub(crate) fn lane_id(&self) -> u32 {
        self.lane_id
    }

    fn transfer_to_stream(&mut self) {
        let removed = self
            .session
            .state
            .lock()
            .websocket_lane_reservations
            .remove(&self.lane_id);
        if removed == Some(self.peer_port) {
            self.transferred = true;
        }
    }
}

impl Drop for WebSocketLaneReservation {
    fn drop(&mut self) {
        if !self.transferred {
            self.session
                .release_websocket_lane_reservation(self.lane_id, self.peer_port);
        }
    }
}

impl WebSession {
    /// Acquires stream quota and tuple ownership before a lane returns HTTP 101.
    pub(crate) fn reserve_websocket_lane(
        self: &Arc<Self>,
        lane_id: u32,
    ) -> Result<WebSocketLaneReservation, ManagerError> {
        if self.carrier() != WebCarrier::WebsocketLanes
            || lane_id == 0
            || lane_id > frame::MAX_STREAM_ID
        {
            return Err(ManagerError::Protocol);
        }
        let mut state = self.state.lock();
        if state.closed {
            return Err(ManagerError::Closed);
        }
        if state.active_peer_ports.len() >= self.profile.max_streams_per_session
            || state.streams.contains_key(&lane_id)
            || state.closed_streams.contains(&lane_id)
            || state.websocket_lane_reservations.contains_key(&lane_id)
        {
            return Err(ManagerError::Limit);
        }
        let Some(manager) = self.manager.upgrade() else {
            return Err(ManagerError::Closed);
        };
        let Some(peer_port) = manager.try_acquire_stream(
            self.profile_key,
            self.profile.max_streams,
            self.client_ip,
            self.profile.public_addr,
        ) else {
            return Err(ManagerError::Limit);
        };
        if !state.active_peer_ports.insert(peer_port) {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
            return Err(ManagerError::Limit);
        }
        state.websocket_lane_reservations.insert(lane_id, peer_port);
        if insert_carrier_lane(&mut state, lane_id).is_none() {
            state.websocket_lane_reservations.remove(&lane_id);
            state.active_peer_ports.remove(&peer_port);
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
            return Err(ManagerError::Protocol);
        }
        drop(state);
        self.lane_open_notify.notify_waiters();
        Ok(WebSocketLaneReservation {
            session: Arc::clone(self),
            lane_id,
            peer_port,
            transferred: false,
        })
    }

    /// Applies one ordered WebSocket lane message without closing sibling lanes.
    pub(crate) fn process_websocket_lane(
        self: &Arc<Self>,
        reservation: &mut WebSocketLaneReservation,
        sequence: u64,
        body: &[u8],
    ) -> Result<(), ManagerError> {
        if !Arc::ptr_eq(self, &reservation.session)
            || reservation.lane_id == 0
            || reservation.lane_id > frame::MAX_STREAM_ID
        {
            return Err(ManagerError::Protocol);
        }
        let lane_id = reservation.lane_id;
        let frames = frame::parse_all(body, &self.limits).map_err(|_| ManagerError::Protocol)?;
        if frames
            .iter()
            .copied()
            .any(|value| value.stream_id != lane_id || frame::validate_client_shape(value).is_err())
        {
            return Err(ManagerError::Protocol);
        }
        let digest = Sha256::digest(body).into();
        let progress = frames
            .iter()
            .any(|frame| matches!(frame.frame_type, frame::FrameType::Open | frame::FrameType::Data));
        let mut opened = Vec::new();
        let mut committed = false;
        let result = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            self.ensure_carrier_active_locked(&state)?;
            if !reservation.transferred
                && state.websocket_lane_reservations.get(&lane_id) != Some(&reservation.peer_port)
            {
                return Err(ManagerError::Closed);
            }
            let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                return Err(ManagerError::Closed);
            };
            if sequence == 0 || sequence != lane.last_up_sequence.saturating_add(1) {
                return Err(ManagerError::Protocol);
            }
            if lane.up_active {
                return Err(ManagerError::Concurrent);
            }
            lane.up_active = true;
            if !validate_batch(&state, &frames) {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
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
            let mut reserved_open =
                (!reservation.transferred).then_some((lane_id, reservation.peer_port));
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut opened,
                &mut reserved_open,
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
            state.last_activity = Instant::now();
            if applied {
                committed = self.commit_carrier_locked(&mut state, progress);
            }
            applied.then_some(()).ok_or(ManagerError::Protocol)
        };
        result?;
        if committed {
            self.finish_carrier_commit();
        }
        for completion in opened {
            if completion.stream.id != lane_id || completion.peer_port != reservation.peer_port {
                return Err(ManagerError::Protocol);
            }
            if !self.spawn_stream(completion, true) {
                return Err(ManagerError::Limit);
            }
            reservation.transfer_to_stream();
        }
        if !reservation.transferred {
            return Err(ManagerError::Protocol);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        Ok(())
    }

    /// Ends one failed or disconnected lane without closing its parent session.
    pub(crate) fn close_websocket_lane(&self, lane_id: u32) {
        let reserved = {
            let mut state = self.state.lock();
            let reserved = state.websocket_lane_reservations.remove(&lane_id);
            if let Some(stream) = state.streams.remove(&lane_id) {
                state.closing_streams.insert(lane_id, stream.instance);
                let (bytes, items) = inbound_queue_cost(&stream.inbound);
                self.release_locked(&mut state, bytes, items, false);
                if let Some(waker) = stream.read_waker {
                    waker.wake();
                }
                if let Some(waker) = stream.write_waker {
                    waker.wake();
                }
            }
            self.remember_closed_locked(&mut state, lane_id);
            self.release_lane_locked(&mut state, lane_id);
            reserved
        };
        if let Some(peer_port) = reserved {
            self.release_websocket_lane_reservation(lane_id, peer_port);
        }
        self.lane_open_notify.notify_waiters();
    }

    fn release_websocket_lane_reservation(&self, lane_id: u32, peer_port: u16) {
        let removed = {
            let mut state = self.state.lock();
            if state.websocket_lane_reservations.get(&lane_id) == Some(&peer_port) {
                state.websocket_lane_reservations.remove(&lane_id);
            }
            self.release_lane_locked(&mut state, lane_id);
            state.active_peer_ports.remove(&peer_port)
        };
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

#[cfg(test)]
mod tests;
