use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::state::{
    Bootstrap, allow_rate, evict_oldest_unused_bootstrap, matching_profile, new_unique_token,
    remove_expired_locked,
};
use super::{BootstrapResult, ManagerError, TOKEN_BYTES, TokenHash, WebProcessRuntime};
use crate::config::WebRuntimeProfile;
use crate::web::session::WebSession;

impl WebProcessRuntime {
    /// Issues a one-use bootstrap credential for an active compatible profile.
    pub(crate) fn issue_bootstrap(
        &self,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        let generation = self.active_generation();
        let config = generation.config();
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &profile))
            .ok_or(ManagerError::Authentication)?;
        if !config.web.enabled || !generation.proxy_shared.is_user_enabled(&profile.user) {
            return Err(ManagerError::Closed);
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        if state.closed
            || state
                .bootstraps_per_ip
                .get(&client_ip)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_bootstraps_per_ip
            || !allow_rate(
                &mut state.bootstrap_rate,
                now,
                self.limits.new_bootstraps_per_minute,
                self.limits.new_bootstraps_burst,
            )
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        if state.bootstraps.len() >= self.limits.max_bootstraps_global
            && !evict_oldest_unused_bootstrap(&mut state)
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        let Some((token, hash)) = new_unique_token(&generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        };
        let trace_session_id = self.trace.next_session_id();
        state.bootstraps.insert(
            hash,
            Bootstrap {
                expires_at: now + Duration::from_secs(config.web.timeouts.bootstrap_lifetime_secs),
                issued_at: now,
                issuance_ip: client_ip,
                profile,
                trace_session_id,
                body_digest: [0; TOKEN_BYTES],
                session_token: Zeroizing::new(String::new()),
                session: None,
                carrier_request: None,
                carrier_candidates: Arc::from([]),
                carrier_scores: [0; 4],
                carrier_attempt: 0,
                carrier_transitioning: false,
                carrier_committed: false,
                session_client_ip: None,
                used: false,
            },
        );
        *state.bootstraps_per_ip.entry(client_ip).or_insert(0) += 1;
        let profile = state
            .bootstraps
            .get(&hash)
            .map(|entry| Arc::clone(&entry.profile))
            .ok_or(ManagerError::Closed)?;
        drop(state);
        self.trace.record_profile_lifecycle(
            client_ip,
            Some(trace_session_id),
            &profile,
            crate::web::trace::TraceLifecycleEvent::BridgeIssued,
            None,
            None,
        );
        Ok(BootstrapResult {
            token,
            trace_session_id,
        })
    }

    /// Resolves non-secret bootstrap trace identity without exposing its credential.
    pub(crate) fn bootstrap_trace_identity(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> Option<(u64, Arc<WebRuntimeProfile>)> {
        let now = Instant::now();
        self.state
            .lock()
            .bootstraps
            .get(&hash)
            .filter(|entry| entry.profile.host == host && now <= entry.expires_at)
            .map(|entry| (entry.trace_session_id, Arc::clone(&entry.profile)))
    }

    /// Resolves an authenticated session token.
    pub(crate) fn get_session(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<Arc<WebSession>, ManagerError> {
        self.state
            .lock()
            .sessions
            .get(&hash)
            .cloned()
            .filter(|session| session.matches_host(host))
            .ok_or(ManagerError::Authentication)
    }

    /// Closes a live token and accepts bounded tombstone retries.
    pub(crate) fn close_token(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<(), ManagerError> {
        let state = self.state.lock();
        let session = state
            .sessions
            .get(&hash)
            .filter(|session| session.matches_host(host))
            .cloned();
        let closed = state
            .closed_tokens
            .get(&hash)
            .is_some_and(|closed| closed.host == host);
        drop(state);
        if let Some(session) = session {
            session.close();
            return Ok(());
        }
        closed.then_some(()).ok_or(ManagerError::Authentication)
    }
}
