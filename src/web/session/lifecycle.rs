use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{SessionNegotiationPhase, WebSession};

struct ReleasedQueues {
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
}

impl WebSession {
    /// Closes carrier state while relay tasks retain their admission until exit.
    pub(crate) fn close(&self) {
        let Some(released) = self.begin_close(false, None) else {
            return;
        };
        self.finish_close(released, false);
    }

    /// Atomically prevents first-frame commit while one successor is prepared.
    pub(crate) fn begin_carrier_supersede(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed || state.close_requested {
            return false;
        }
        match state.negotiation_phase {
            SessionNegotiationPhase::Uncommitted => {
                state.negotiation_phase = SessionNegotiationPhase::Replacing;
                true
            }
            SessionNegotiationPhase::Replacing
            | SessionNegotiationPhase::Committed
            | SessionNegotiationPhase::Superseded => false,
        }
    }

    /// Restores an uncommitted attempt after successor admission failed.
    pub(crate) fn cancel_carrier_supersede(&self) {
        let close_requested = {
            let mut state = self.state.lock();
            if !state.closed && state.negotiation_phase == SessionNegotiationPhase::Replacing {
                state.negotiation_phase = SessionNegotiationPhase::Uncommitted;
            }
            state.close_requested
        };
        if close_requested {
            self.close();
        }
    }

    /// Completes manager-owned replacement without unregistering the old session twice.
    pub(crate) fn finish_carrier_supersede(&self) -> bool {
        let close_requested = self.state.lock().close_requested;
        let Some(released) = self.begin_close(true, None) else {
            return close_requested;
        };
        self.finish_close(released, true);
        close_requested
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

    /// Atomically closes a session only when reconnect grace is still due.
    pub(crate) fn close_if_due(&self, now: Instant) -> bool {
        let Some(released) = self.begin_close(false, Some(now)) else {
            return false;
        };
        self.finish_close(released, false);
        true
    }

    fn begin_close(&self, superseded: bool, idle_now: Option<Instant>) -> Option<ReleasedQueues> {
        let mut state = self.state.lock();
        if state.closed || (superseded && state.negotiation_phase != SessionNegotiationPhase::Replacing) {
            return None;
        }
        if let Some(now) = idle_now
            && (state.negotiation_phase == SessionNegotiationPhase::Replacing
                || now.saturating_duration_since(state.last_activity)
                    < Duration::from_secs(self.timeouts.reconnect_grace_secs))
        {
            return None;
        }
        if !superseded && state.negotiation_phase == SessionNegotiationPhase::Replacing {
            state.close_requested = true;
            return None;
        }
        state.closed = true;
        if superseded {
            state.negotiation_phase = SessionNegotiationPhase::Superseded;
        }
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
        Some(ReleasedQueues {
            data_bytes,
            data_items,
            control_bytes,
            control_items,
        })
    }

    fn finish_close(&self, released: ReleasedQueues, superseded: bool) {
        self.cancel.cancel();
        if self.carrier().is_multiplexed() {
            self.down_notify.notify_waiters();
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.release_pending(
                self.profile_key,
                released.data_bytes,
                released.data_items,
                false,
            );
            manager.release_pending(
                self.profile_key,
                released.control_bytes,
                released.control_items,
                true,
            );
            if !self.finished.swap(true, Ordering::AcqRel) {
                self.trace_lifecycle(
                    crate::web::trace::TraceLifecycleEvent::SessionClosed,
                    None,
                    Some(if superseded { "superseded" } else { "closed" }),
                );
                if !superseded {
                    manager.session_finished(
                        self.token_hash,
                        self.client_ip,
                        self.profile_key,
                        &self.profile.host,
                    );
                }
            }
        }
    }
}
