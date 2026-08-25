use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::info;

use super::state::{ClosedToken, decrement_map, remove_bootstrap_locked, remove_expired_locked};
use super::{ProfileKey, TokenHash, WebProcessRuntime};

impl WebProcessRuntime {
    /// Removes one closed session and retains a bounded host-bound replay marker.
    pub(crate) fn session_finished(
        &self,
        hash: TokenHash,
        client_ip: IpAddr,
        profile_key: ProfileKey,
        profile_host: &str,
    ) {
        let mut state = self.state.lock();
        if state.sessions.remove(&hash).is_none() {
            return;
        }
        decrement_map(&mut state.sessions_per_ip, &client_ip);
        decrement_map(&mut state.sessions_per_profile, &profile_key);
        let expiry = Instant::now()
            + Duration::from_secs(
                self.active_runtime
                    .load()
                    .config()
                    .web
                    .timeouts
                    .bootstrap_lifetime_secs,
            );
        state.closed_tokens.insert(
            hash,
            ClosedToken {
                expires_at: expiry,
                host: profile_host.to_string(),
            },
        );
        while state.closed_tokens.len() > self.limits.max_sessions_global.saturating_mul(16) {
            let Some(oldest) = state
                .closed_tokens
                .iter()
                .min_by_key(|(_, closed)| closed.expires_at)
                .map(|(hash, _)| *hash)
            else {
                break;
            };
            state.closed_tokens.remove(&oldest);
        }
        let bootstrap_hashes = state
            .bootstraps
            .iter()
            .filter_map(|(bootstrap_hash, bootstrap)| {
                bootstrap
                    .session
                    .as_ref()
                    .is_some_and(|session| session.token_hash() == hash)
                    .then_some(*bootstrap_hash)
            })
            .collect::<Vec<_>>();
        for bootstrap_hash in bootstrap_hashes {
            remove_bootstrap_locked(&mut state, bootstrap_hash);
        }
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Stops issuance, closes all sessions, and joins bounded child work.
    pub(crate) async fn shutdown(&self) {
        self.shutdown.cancel();
        let sessions = {
            let mut state = self.state.lock();
            state.closed = true;
            state.bootstraps.clear();
            state.bootstraps_per_ip.clear();
            state.sessions.values().cloned().collect::<Vec<_>>()
        };
        for session in &sessions {
            session.close();
        }
        let timeout_secs = self
            .active_runtime
            .load()
            .config()
            .web
            .timeouts
            .shutdown_secs;
        let waits = async {
            for session in sessions {
                session.wait().await;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), waits).await;
        self.tasks.close();
        let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), self.tasks.wait()).await;
        let (sessions_live, streams_live, pending_bytes, pending_items) = {
            let state = self.state.lock();
            (
                state.sessions.len(),
                state.streams_live,
                state.pending_bytes,
                state.pending_items,
            )
        };
        info!(
            target: "telemt::web",
            sessions_created = self.sessions_created.load(Ordering::Relaxed),
            sessions_closed = self.sessions_closed.load(Ordering::Relaxed),
            sessions_live,
            streams_opened = self.streams_opened.load(Ordering::Relaxed),
            streams_rejected = self.streams_rejected.load(Ordering::Relaxed),
            streams_live,
            pending_bytes,
            pending_items,
            bytes_up = self.bytes_up.load(Ordering::Relaxed),
            bytes_down = self.bytes_down.load(Ordering::Relaxed),
            limit_hits = self.limit_hits.load(Ordering::Relaxed),
            "WEB runtime stopped"
        );
    }

    /// Expires credentials and closes idle sessions without holding locks across callbacks.
    pub(super) fn cleanup(&self) {
        let now = Instant::now();
        let sessions = {
            let mut state = self.state.lock();
            remove_expired_locked(&mut state, now);
            state.sessions.values().cloned().collect::<Vec<_>>()
        };
        for session in sessions.into_iter().filter(|session| session.is_idle(now)) {
            session.close();
        }
    }
}
