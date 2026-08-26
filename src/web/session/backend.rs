use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::proxy::shared_state::ConntrackClosePolicy;
use crate::web::frame::FrameType;
use crate::web::stream::WebLogicalStream;

use super::{WebSession, inbound_queue_cost};

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;

impl WebSession {
    /// Starts one owned inner handshake and relay task for an admitted stream.
    pub(super) fn spawn_stream(
        self: &Arc<Self>,
        stream_id: u32,
        peer_port: u16,
        retain_reservation_on_reject: bool,
    ) -> bool {
        let Some(manager) = self.manager.upgrade() else {
            self.stream_rejected_before_spawn(stream_id, peer_port, retain_reservation_on_reject);
            return false;
        };
        let generation = manager.active_generation();
        if !*generation.admission_rx.borrow() {
            self.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamRejected,
                Some(stream_id),
                Some("admission_closed"),
            );
            self.stream_rejected_before_spawn(stream_id, peer_port, retain_reservation_on_reject);
            return false;
        }
        let Ok(connection_permit) = generation.max_connections.clone().try_acquire_owned() else {
            manager.record_stream_rejected();
            self.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamRejected,
                Some(stream_id),
                Some("connection_limit"),
            );
            self.stream_rejected_before_spawn(stream_id, peer_port, retain_reservation_on_reject);
            return false;
        };
        let deps = generation.client_runtime_deps();
        let replay_checker = Arc::clone(&generation.replay_checker);
        let session = Arc::clone(self);
        let cancel = self.cancel.clone();
        let retain_rejected = Arc::new(AtomicBool::new(false));
        self.tasks_live.fetch_add(1, Ordering::AcqRel);
        let completion = StreamCompletion {
            session: Arc::clone(&session),
            stream_id,
            peer_port,
            retain_rejected: Arc::clone(&retain_rejected),
        };
        let future = async move {
            let _connection_permit = connection_permit;
            let _completion = completion;
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamAdmitted,
                Some(stream_id),
                None,
            );
            let stream = WebLogicalStream::new(Arc::clone(&session), stream_id);
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = run_stream(
                    Arc::clone(&session),
                    stream_id,
                    stream,
                    deps,
                    replay_checker,
                    peer_port,
                ) => {}
            }
        };
        if let Err(future) = generation.try_spawn_session(future) {
            retain_rejected.store(retain_reservation_on_reject, Ordering::Release);
            self.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::StreamRejected,
                Some(stream_id),
                Some("generation_closed"),
            );
            drop(future);
            return false;
        }
        true
    }

    fn stream_rejected_before_spawn(
        &self,
        stream_id: u32,
        peer_port: u16,
        retain_reservation: bool,
    ) {
        if !retain_reservation {
            self.stream_finished(stream_id, peer_port);
            return;
        }
        let queued = {
            let mut state = self.state.lock();
            state.streams.remove(&stream_id).map(|stream| {
                let (bytes, items) = inbound_queue_cost(&stream.inbound);
                self.release_locked(&mut state, bytes, items, false);
                self.remember_closed_locked(&mut state, stream_id);
                self.queue_control_locked(&mut state, FrameType::Close, stream_id, &[])
            })
        };
        if queued.is_some_and(|queued| !queued) {
            self.close();
        }
    }

    fn stream_finished(&self, stream_id: u32, peer_port: u16) {
        let (queued, reserved) = {
            let mut state = self.state.lock();
            let reserved = state.active_peer_ports.remove(&peer_port);
            let queued = state.streams.remove(&stream_id).map(|stream| {
                let (bytes, items) = inbound_queue_cost(&stream.inbound);
                self.release_locked(&mut state, bytes, items, false);
                self.remember_closed_locked(&mut state, stream_id);
                self.queue_control_locked(&mut state, FrameType::Close, stream_id, &[])
            });
            (queued, reserved)
        };
        if reserved && let Some(manager) = self.manager.upgrade() {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
        }
        if let Some(queued) = queued {
            if !queued {
                self.close();
            }
            if self.carrier().is_multiplexed() {
                self.down_notify.notify_waiters();
            }
        }
    }
}

struct StreamCompletion {
    session: Arc<WebSession>,
    stream_id: u32,
    peer_port: u16,
    retain_rejected: Arc<AtomicBool>,
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        self.session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::StreamClosed,
            Some(self.stream_id),
            None,
        );
        if self.retain_rejected.load(Ordering::Acquire) {
            self.session
                .stream_rejected_before_spawn(self.stream_id, self.peer_port, true);
        } else {
            self.session.stream_finished(self.stream_id, self.peer_port);
        }
        if self.session.tasks_live.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.session.tasks_done.notify_waiters();
        }
    }
}

async fn run_stream(
    session: Arc<WebSession>,
    stream_id: u32,
    stream: WebLogicalStream,
    deps: crate::proxy::authenticated::ClientRuntimeDeps,
    replay_checker: Arc<crate::stats::ReplayChecker>,
    peer_port: u16,
) {
    use tokio::io::AsyncReadExt;

    use crate::protocol::constants::HANDSHAKE_LEN;
    use crate::proxy::authenticated::run_authenticated;
    use crate::proxy::handshake::handle_mtproto_handshake_for_web_user;

    let (mut reader, writer) = tokio::io::split(stream);
    let mut handshake = [0u8; HANDSHAKE_LEN];
    let peer = std::net::SocketAddr::new(session.client_ip, peer_port);
    deps.stats.increment_connects_all();

    // A carrier may publish OPEN before the local MTProto socket writes its
    // first byte. Session and stream quotas bound this idle phase without
    // consuming the process-wide active-handshake budget.
    if reader.read_exact(&mut handshake[..1]).await.is_err() {
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::HandshakeIo,
            Some(stream_id),
            Some("first_byte_io"),
        );
        deps.stats
            .increment_connects_bad_with_class("web_mtproto_handshake_io");
        return;
    }
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::StreamFirstByte,
        Some(stream_id),
        None,
    );
    let Some(manager) = session.manager.upgrade() else {
        return;
    };
    let Some(handshake_permit) = manager.try_stream_handshake() else {
        session.trace_lifecycle(
            crate::web::trace::TraceLifecycleEvent::StreamRejected,
            Some(stream_id),
            Some("handshake_limit"),
        );
        return;
    };
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(session.timeouts.stream_handshake_secs),
        async {
            reader.read_exact(&mut handshake[1..]).await?;
            Ok::<_, io::Error>(
                handle_mtproto_handshake_for_web_user(
                    &handshake,
                    reader,
                    writer,
                    peer,
                    &deps.config,
                    &replay_checker,
                    &session.profile.user,
                    session.profile.secret_mode,
                    &deps.shared,
                )
                .await,
            )
        },
    )
    .await;
    drop(handshake_permit);
    let (reader, writer, success) = match handshake_result {
        Err(_) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeTimeout,
                Some(stream_id),
                Some("timeout"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_handshake_timeout");
            deps.stats.increment_handshake_timeouts();
            deps.stats.increment_handshake_failure_class("timeout");
            return;
        }
        Ok(Err(_)) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeIo,
                Some(stream_id),
                Some("io"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_handshake_io");
            return;
        }
        Ok(Ok(crate::error::HandshakeResult::Success((reader, writer, success)))) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeSucceeded,
                Some(stream_id),
                None,
            );
            (reader, writer, success)
        }
        Ok(Ok(_)) => {
            session.trace_lifecycle(
                crate::web::trace::TraceLifecycleEvent::HandshakeRejected,
                Some(stream_id),
                Some("bad_client"),
            );
            deps.stats
                .increment_connects_bad_with_class("web_mtproto_bad_client");
            return;
        }
    };
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::RelayStarted,
        Some(stream_id),
        None,
    );
    let relay_result = run_authenticated(
        reader,
        writer,
        success,
        deps,
        session.profile.public_addr,
        peer,
        ConntrackClosePolicy::Suppress,
    )
    .await;
    session.trace_lifecycle(
        crate::web::trace::TraceLifecycleEvent::RelayEnded,
        Some(stream_id),
        Some(if relay_result.is_ok() {
            "completed"
        } else {
            "error"
        }),
    );
}
