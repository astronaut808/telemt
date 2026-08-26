use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::state::{
    ManagerState, allow_rate, decrement_map, matching_profile, new_unique_token, profile_key,
    remember_closed_token_locked, remove_expired_locked,
};
use super::{
    CarrierLearningContext, CarrierRequest, CreateResult, ManagerError, TokenHash,
    WebProcessRuntime,
};
use crate::config::{WebCarrier, WebRuntimeProfile, WebTimeoutsConfig};
use crate::web::frame;
use crate::web::session::WebSession;
use crate::web::trace::{TraceIdentity, TraceLifecycleEvent};

struct Replacement {
    old_session: Arc<WebSession>,
    profile: Arc<WebRuntimeProfile>,
    profile_key: super::ProfileKey,
    trace_session_id: u64,
    attempt: u8,
    carrier: WebCarrier,
    request: CarrierRequest,
    scores: [i16; 4],
}

impl WebProcessRuntime {
    /// Creates, replays, or atomically supersedes one pre-commit carrier session.
    pub(crate) fn create_session(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        host: &str,
        client_ip: IpAddr,
        body: &[u8],
        carrier_request: CarrierRequest,
    ) -> std::result::Result<CreateResult, ManagerError> {
        if !frame::validate_hello(body, &self.limits) {
            return Err(ManagerError::Protocol);
        }
        let body_digest: TokenHash = Sha256::digest(body).into();
        let generation = self.active_generation();
        let config = generation.config();
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        let Some(entry) = state.bootstraps.get(&bootstrap_hash) else {
            return Err(ManagerError::Authentication);
        };
        if entry.profile.host != host || now > entry.expires_at {
            return Err(ManagerError::Authentication);
        }
        if entry.used {
            let digest_matches = bool::from(entry.body_digest.ct_eq(&body_digest));
            let client_matches = entry.session_client_ip == Some(client_ip);
            let request_matches = entry
                .carrier_request
                .is_some_and(|current| current.matches_client(carrier_request));
            if !digest_matches || !client_matches || !request_matches {
                return Err(ManagerError::Authentication);
            }
            if entry.carrier_transitioning {
                return Err(ManagerError::Concurrent);
            }
            if carrier_request.attempt() == Some(entry.carrier_attempt)
                || (!carrier_request.is_automatic() && entry.carrier_attempt == 1)
            {
                let session = entry.session.as_ref().ok_or(ManagerError::Authentication)?;
                let result = CreateResult {
                    token: entry.session_token.as_str().to_owned(),
                    carrier: session.carrier(),
                    attempt: carrier_request.attempt(),
                };
                let identity = session.trace_identity();
                drop(state);
                self.trace.record_lifecycle(
                    None,
                    Some(client_ip),
                    identity,
                    TraceLifecycleEvent::SessionReplayed,
                    None,
                    None,
                );
                return Ok(result);
            }
            let next_attempt = entry.carrier_attempt.saturating_add(1);
            if !carrier_request.is_automatic()
                || carrier_request.attempt() != Some(next_attempt)
                || entry.carrier_committed
            {
                return Err(ManagerError::Protocol);
            }
            let Some(carrier) = entry
                .carrier_candidates
                .get(usize::from(next_attempt - 1))
                .copied()
            else {
                return Err(ManagerError::Protocol);
            };
            let old_session = entry.session.clone().ok_or(ManagerError::Authentication)?;
            let replacement = Replacement {
                profile: Arc::clone(&entry.profile),
                profile_key: old_session.profile_key(),
                trace_session_id: entry.trace_session_id,
                old_session,
                attempt: next_attempt,
                carrier,
                request: carrier_request,
                scores: entry.carrier_scores,
            };
            state
                .bootstraps
                .get_mut(&bootstrap_hash)
                .ok_or(ManagerError::Authentication)?
                .carrier_transitioning = true;
            drop(state);
            return self.replace_session(
                bootstrap_hash,
                client_ip,
                replacement,
                &config.web.timeouts,
            );
        }

        if (carrier_request.is_automatic() && carrier_request.attempt() != Some(1))
            || (!carrier_request.is_automatic() && carrier_request.attempt().is_some())
        {
            return Err(ManagerError::Protocol);
        }
        let trace_session_id = entry.trace_session_id;
        let issued_profile = Arc::clone(&entry.profile);
        if state.closed || !config.web.enabled {
            return Err(ManagerError::Closed);
        }
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &issued_profile))
            .filter(|profile| generation.proxy_shared.is_user_enabled(&profile.user))
            .ok_or(ManagerError::Authentication)?;
        let profile_key = profile_key(&profile);
        if carrier_request.is_automatic() && !profile.carrier_negotiation_enabled {
            return Err(ManagerError::Protocol);
        }
        let (candidates, scores) = if carrier_request.is_automatic() && profile.carrier_learning {
            self.learning.lock().rank(
                now,
                &profile.carriers,
                carrier_request,
                profile_key,
                client_ip,
            )
        } else if carrier_request.is_automatic() {
            (
                profile
                    .carriers
                    .iter()
                    .copied()
                    .filter(|carrier| carrier_request.supports(*carrier))
                    .collect(),
                [0; 4],
            )
        } else {
            (vec![profile.carrier], [0; 4])
        };
        let Some(carrier) = candidates.first().copied() else {
            return Err(ManagerError::Protocol);
        };
        if !admit_initial(self, &mut state, now, client_ip, profile_key, &profile) {
            return Err(ManagerError::Limit);
        }
        let Some((session_token, session_hash)) = new_unique_token(&generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        };
        let learning_context = (carrier_request.is_automatic() && profile.carrier_learning)
            .then_some(CarrierLearningContext {
                profile_key,
                client_ip,
                class: carrier_request.class(),
                user_agent_hash: carrier_request.user_agent_hash(),
            });
        let session = WebSession::new(
            Arc::downgrade(self),
            session_hash,
            client_ip,
            trace_session_id,
            Arc::clone(&profile),
            profile_key,
            carrier,
            1,
            bootstrap_hash,
            learning_context,
            self.limits.clone(),
            config.web.timeouts.clone(),
        );
        state.sessions.insert(session_hash, Arc::clone(&session));
        *state.sessions_per_ip.entry(client_ip).or_insert(0) += 1;
        *state.sessions_per_profile.entry(profile_key).or_insert(0) += 1;
        let entry = state
            .bootstraps
            .get_mut(&bootstrap_hash)
            .ok_or(ManagerError::Authentication)?;
        entry.used = true;
        entry.body_digest = body_digest;
        entry.session_token = Zeroizing::new(session_token.clone());
        entry.session = Some(Arc::clone(&session));
        entry.carrier_request = Some(carrier_request);
        entry.carrier_candidates = candidates.into();
        entry.carrier_scores = scores;
        entry.carrier_attempt = 1;
        entry.session_client_ip = Some(client_ip);
        let issuance_ip = entry.issuance_ip;
        decrement_map(&mut state.bootstraps_per_ip, &issuance_ip);
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        let identity = session.trace_identity();
        let result = CreateResult {
            token: session_token,
            carrier,
            attempt: carrier_request.attempt(),
        };
        drop(state);
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierClassified,
            carrier_request.class().as_str(),
            carrier,
            1,
            scores,
            None,
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierSelected,
            carrier_request.class().as_str(),
            carrier,
            1,
            scores,
            None,
        );
        self.trace.record_lifecycle(
            None,
            Some(client_ip),
            identity,
            TraceLifecycleEvent::SessionCreated,
            None,
            None,
        );
        Ok(result)
    }

    fn replace_session(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        client_ip: IpAddr,
        replacement: Replacement,
        timeouts: &WebTimeoutsConfig,
    ) -> std::result::Result<CreateResult, ManagerError> {
        if !replacement.old_session.begin_carrier_supersede() {
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(ManagerError::Protocol);
        }
        let generation = self.active_generation();
        let config = generation.config();
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        let valid = state.bootstraps.get(&bootstrap_hash).is_some_and(|entry| {
            entry.carrier_transitioning
                && entry.carrier_attempt.saturating_add(1) == replacement.attempt
                && entry
                    .session
                    .as_ref()
                    .is_some_and(|session| Arc::ptr_eq(session, &replacement.old_session))
        }) && state
            .sessions
            .get(&replacement.old_session.token_hash())
            .is_some_and(|session| Arc::ptr_eq(session, &replacement.old_session));
        if !valid
            || state.closed
            || !config.web.enabled
            || !generation
                .proxy_shared
                .is_user_enabled(&replacement.profile.user)
        {
            drop(state);
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(ManagerError::Closed);
        }
        let Some((session_token, session_hash)) = new_unique_token(&generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            drop(state);
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(ManagerError::Limit);
        };
        let learning_context = replacement.profile.carrier_learning.then_some(
            CarrierLearningContext {
                profile_key: replacement.profile_key,
                client_ip,
                class: replacement.request.class(),
                user_agent_hash: replacement.request.user_agent_hash(),
            },
        );
        let session = WebSession::new(
            Arc::downgrade(self),
            session_hash,
            client_ip,
            replacement.trace_session_id,
            Arc::clone(&replacement.profile),
            replacement.profile_key,
            replacement.carrier,
            replacement.attempt,
            bootstrap_hash,
            learning_context,
            self.limits.clone(),
            timeouts.clone(),
        );
        let old_hash = replacement.old_session.token_hash();
        state.sessions.remove(&old_hash);
        remember_closed_token_locked(
            &mut state,
            old_hash,
            &replacement.profile.host,
            Duration::from_secs(config.web.timeouts.bootstrap_lifetime_secs),
            self.limits.max_sessions_global.saturating_mul(16),
        );
        state.sessions.insert(session_hash, Arc::clone(&session));
        let entry = state
            .bootstraps
            .get_mut(&bootstrap_hash)
            .ok_or(ManagerError::Authentication)?;
        entry.session_token = Zeroizing::new(session_token.clone());
        entry.session = Some(Arc::clone(&session));
        entry.carrier_request = Some(replacement.request);
        entry.carrier_attempt = replacement.attempt;
        entry.carrier_transitioning = false;
        entry.carrier_committed = false;
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
        let result = CreateResult {
            token: session_token,
            carrier: replacement.carrier,
            attempt: Some(replacement.attempt),
        };
        let identity = session.trace_identity();
        let old_identity = replacement.old_session.trace_identity();
        drop(state);
        replacement.old_session.finish_carrier_supersede();
        if let Some(context) = learning_context {
            self.record_carrier_outcome(context, replacement.old_session.carrier(), false);
        }
        self.trace.record_carrier_lifecycle(
            client_ip,
            old_identity.clone(),
            TraceLifecycleEvent::CarrierFailed,
            replacement.request.class().as_str(),
            replacement.old_session.carrier(),
            replacement.attempt - 1,
            replacement.scores,
            replacement.request.failure().map(|failure| failure.as_str()),
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            old_identity,
            TraceLifecycleEvent::CarrierSuperseded,
            replacement.request.class().as_str(),
            replacement.old_session.carrier(),
            replacement.attempt - 1,
            replacement.scores,
            replacement.request.failure().map(|failure| failure.as_str()),
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierSelected,
            replacement.request.class().as_str(),
            replacement.carrier,
            replacement.attempt,
            replacement.scores,
            None,
        );
        self.trace.record_lifecycle(
            None,
            Some(client_ip),
            identity,
            TraceLifecycleEvent::SessionCreated,
            None,
            replacement.request.failure().map(|failure| failure.as_str()),
        );
        Ok(result)
    }

    fn cancel_replacement(&self, bootstrap_hash: TokenHash, old_session: &Arc<WebSession>) {
        old_session.cancel_carrier_supersede();
        let mut state = self.state.lock();
        if let Some(entry) = state.bootstraps.get_mut(&bootstrap_hash)
            && entry
                .session
                .as_ref()
                .is_some_and(|session| Arc::ptr_eq(session, old_session))
        {
            entry.carrier_transitioning = false;
        }
    }

    /// Commits learning only after one accepted OPEN or DATA batch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn carrier_committed(
        &self,
        bootstrap_hash: TokenHash,
        session_hash: TokenHash,
        attempt: u8,
        carrier: WebCarrier,
        learning_context: Option<CarrierLearningContext>,
        client_ip: IpAddr,
        identity: TraceIdentity,
    ) {
        let mut state = self.state.lock();
        let scores = state.bootstraps.get_mut(&bootstrap_hash).and_then(|entry| {
            if entry.carrier_attempt == attempt
                && entry
                    .session
                    .as_ref()
                    .is_some_and(|session| session.token_hash() == session_hash)
            {
                entry.carrier_committed = true;
                Some(entry.carrier_scores)
            } else {
                None
            }
        });
        drop(state);
        let Some(scores) = scores else { return };
        if let Some(context) = learning_context {
            self.record_carrier_outcome(context, carrier, true);
        }
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity,
            TraceLifecycleEvent::CarrierCommitted,
            learning_context
                .map_or("legacy", |context| context.class.as_str()),
            carrier,
            attempt,
            scores,
            None,
        );
    }

    fn record_carrier_outcome(
        &self,
        context: CarrierLearningContext,
        carrier: WebCarrier,
        success: bool,
    ) {
        let generation = self.active_generation();
        if !generation.config().web.carrier_learning {
            return;
        }
        let lifetime = Duration::from_secs(
            generation.config().web.timeouts.carrier_learning_secs,
        );
        self.learning
            .lock()
            .record(Instant::now(), lifetime, context, carrier, success);
    }
}

fn admit_initial(
    runtime: &WebProcessRuntime,
    state: &mut ManagerState,
    now: Instant,
    client_ip: IpAddr,
    profile_key: super::ProfileKey,
    profile: &WebRuntimeProfile,
) -> bool {
    let admitted = state.sessions.len() < runtime.limits.max_sessions_global
        && state.sessions_per_ip.get(&client_ip).copied().unwrap_or(0)
            < runtime.limits.max_sessions_per_ip
        && state
            .sessions_per_profile
            .get(&profile_key)
            .copied()
            .unwrap_or(0)
            < profile.max_sessions
        && allow_rate(
            &mut state.session_rate,
            now,
            runtime.limits.new_sessions_per_minute,
            runtime.limits.new_sessions_burst,
        );
    if !admitted {
        runtime.limit_hits.fetch_add(1, Ordering::Relaxed);
    }
    admitted
}
