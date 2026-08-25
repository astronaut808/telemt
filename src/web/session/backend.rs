use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::proxy::shared_state::ConntrackClosePolicy;
use crate::web::frame::FrameType;
use crate::web::stream::WebLogicalStream;

use super::{WebSession, inbound_queue_cost};

impl WebSession {
    /// Starts one owned inner handshake and relay task for an admitted stream.
    pub(super) fn spawn_stream(self: &Arc<Self>, stream_id: u32, peer_port: u16) {
        let Some(manager) = self.manager.upgrade() else {
            self.stream_finished(stream_id, peer_port);
            return;
        };
        let generation = manager.active_generation();
        let Ok(connection_permit) = generation.max_connections.clone().try_acquire_owned() else {
            manager.record_stream_rejected();
            self.stream_finished(stream_id, peer_port);
            return;
        };
        let Some(handshake_permit) = manager.try_stream_handshake() else {
            self.stream_finished(stream_id, peer_port);
            return;
        };
        let deps = generation.client_runtime_deps();
        let replay_checker = Arc::clone(&generation.replay_checker);
        let session = Arc::clone(self);
        let cancel = self.cancel.clone();
        self.tasks_live.fetch_add(1, Ordering::AcqRel);
        let spawned = generation.spawn_session(async move {
            let _connection_permit = connection_permit;
            let _completion = StreamCompletion {
                session: Arc::clone(&session),
                stream_id,
                peer_port,
            };
            let stream = WebLogicalStream::new(Arc::clone(&session), stream_id);
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = run_stream(
                    Arc::clone(&session),
                    stream,
                    deps,
                    replay_checker,
                    handshake_permit,
                    peer_port,
                ) => {}
            }
        });
        if !spawned {
            self.tasks_live.fetch_sub(1, Ordering::AcqRel);
            self.stream_finished(stream_id, peer_port);
            self.tasks_done.notify_waiters();
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
            if self.carrier() == crate::config::WebCarrier::Https {
                self.down_notify.notify_waiters();
            }
        }
    }
}

struct StreamCompletion {
    session: Arc<WebSession>,
    stream_id: u32,
    peer_port: u16,
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        self.session.stream_finished(self.stream_id, self.peer_port);
        if self.session.tasks_live.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.session.tasks_done.notify_waiters();
        }
    }
}

async fn run_stream(
    session: Arc<WebSession>,
    stream: WebLogicalStream,
    deps: crate::proxy::authenticated::ClientRuntimeDeps,
    replay_checker: Arc<crate::stats::ReplayChecker>,
    handshake_permit: tokio::sync::OwnedSemaphorePermit,
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
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(session.timeouts.stream_handshake_secs),
        async {
            reader.read_exact(&mut handshake).await?;
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
    let Ok(Ok(crate::error::HandshakeResult::Success((reader, writer, success)))) =
        handshake_result
    else {
        deps.stats
            .increment_connects_bad_with_class("web_mtproto_bad_client");
        return;
    };
    let _ = run_authenticated(
        reader,
        writer,
        success,
        deps,
        session.profile.public_addr,
        peer,
        ConntrackClosePolicy::Suppress,
    )
    .await;
}
