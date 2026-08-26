use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::info;

use super::state::{
    decrement_map, remember_closed_token_locked, remove_bootstrap_locked, remove_expired_locked,
};
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
        remember_closed_token_locked(
            &mut state,
            hash,
            profile_host,
            Duration::from_secs(
                self.active_runtime
                    .load()
                    .config()
                    .web
                    .timeouts
                    .bootstrap_lifetime_secs,
            ),
            self.limits.max_sessions_global.saturating_mul(16),
        );
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
        self.close_websockets();
        self.data_budget.close();
        let sessions = {
            let mut state = self.state.lock();
            state.closed = true;
            state.bootstraps.clear();
            state.bootstraps_per_ip.clear();
            state.sessions.values().cloned().collect::<Vec<_>>()
        };
        self.stream_admission.lock().closed = true;
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
        let sessions_live = self.state.lock().sessions.len();
        let streams_live = self.stream_admission.lock().streams_live;
        let budget = self.data_budget.snapshot();
        info!(
            target: "telemt::web",
            sessions_created = self.sessions_created.load(Ordering::Relaxed),
            sessions_closed = self.sessions_closed.load(Ordering::Relaxed),
            sessions_live,
            streams_opened = self.streams_opened.load(Ordering::Relaxed),
            streams_rejected = self.streams_rejected.load(Ordering::Relaxed),
            streams_live,
            pending_bytes = budget.queue_bytes,
            pending_items = budget.queue_items,
            websocket_bytes = budget.websocket_bytes,
            data_high_water_bytes = budget.high_water_bytes,
            bytes_up = self.bytes_up.load(Ordering::Relaxed),
            bytes_down = self.bytes_down.load(Ordering::Relaxed),
            limit_hits = self.limit_hits.load(Ordering::Relaxed),
            "WEB runtime stopped"
        );
    }

    /// Expires credentials and closes idle sessions without holding locks across callbacks.
    pub(super) fn cleanup(&self) {
        self.cleanup_websockets();
        let now = Instant::now();
        let generation = self.active_generation();
        let config = &generation.config().web;
        let learning_enabled = config.carrier_negotiation_enabled() && config.carrier_learning;
        let mut learning = self.learning.lock();
        let _ = learning.apply_policy(
            now,
            learning_enabled,
            config.carrier_negotiation_aggressiveness,
            Duration::from_secs(config.timeouts.carrier_learning_secs),
        );
        learning.prune(now);
        drop(learning);
        let (sessions, expired_chains) = {
            let mut state = self.state.lock();
            let expired = state
                .bootstraps
                .iter()
                .filter_map(|(hash, bootstrap)| {
                    (bootstrap.carrier_phase == super::state::CarrierChainPhase::Provisional
                        && bootstrap
                            .carrier_deadline_at
                            .is_some_and(|deadline| now >= deadline)
                        && bootstrap
                            .session
                            .as_ref()
                            .is_some_and(|session| !session.is_carrier_committed()))
                    .then_some((*hash, bootstrap.session.clone()))
                })
                .collect::<Vec<_>>();
            let expired_chains = expired
                .iter()
                .filter_map(|(_, session)| session.clone())
                .collect::<Vec<_>>();
            for (hash, _) in expired {
                remove_bootstrap_locked(&mut state, hash);
            }
            remove_expired_locked(&mut state, now);
            (
                state.sessions.values().cloned().collect::<Vec<_>>(),
                expired_chains,
            )
        };
        for session in expired_chains {
            session.close();
        }
        for session in sessions {
            session.close_if_due(now);
        }
    }
}
