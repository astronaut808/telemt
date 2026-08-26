/// Telemt Carrier Selection and Failure Dampening - Copyright 2077 
/// anhand des Kundenverhaltens Rückschlüsse gegen DSGVO ziehen...?!
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::negotiation::{CarrierClientClass, CarrierLearningContext};
use super::ProfileKey;
use crate::config::WebCarrier;

const PROFILE_WEIGHT: i16 = 4;
const USER_AGENT_WEIGHT: i16 = 4;
const IP_WEIGHT: i16 = 1;
const SCORE_MIN: i8 = -8;
const SCORE_MAX: i8 = 8;
const PROFILE_MIN_OUTCOMES: u8 = 8;
const PROFILE_MIN_COHORTS: usize = 4;
const COHORT_CONTEXT: &[u8] = b"telemt-web-carrier-cohort-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EvidenceKey {
    Profile(ProfileKey),
    UserAgent(ProfileKey, CarrierClientClass, [u8; 32]),
    Ip(ProfileKey, IpAddr),
}

struct Evidence {
    created_at: Instant,
    lifetime: Duration,
    scores: [i8; 4],
    outcomes: u8,
    cohorts: [Option<[u8; 32]>; PROFILE_MIN_COHORTS],
}

impl Evidence {
    fn new(created_at: Instant, lifetime: Duration) -> Self {
        Self {
            created_at,
            lifetime,
            scores: [0; 4],
            outcomes: 0,
            cohorts: [None; PROFILE_MIN_COHORTS],
        }
    }

    fn update(&mut self, carrier: WebCarrier, delta: i8, cohort: Option<[u8; 32]>) {
        let score = &mut self.scores[carrier.index()];
        *score = score.saturating_add(delta).clamp(SCORE_MIN, SCORE_MAX);
        self.outcomes = self.outcomes.saturating_add(1).min(PROFILE_MIN_OUTCOMES);
        if let Some(cohort) = cohort
            && !self.cohorts.contains(&Some(cohort))
            && let Some(slot) = self.cohorts.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(cohort);
        }
    }
}

/// Process-local bounded fixed-window carrier evidence store.
pub(super) struct CarrierLearning {
    entries: HashMap<EvidenceKey, Evidence>,
    capacity: usize,
}

impl CarrierLearning {
    /// Creates an empty store under the restart-owned capacity ceiling.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Ranks supported configured candidates using only unexpired evidence.
    pub(super) fn rank(
        &mut self,
        now: Instant,
        configured: &[WebCarrier],
        request: super::CarrierRequest,
        profile_key: ProfileKey,
        client_ip: IpAddr,
    ) -> (Vec<WebCarrier>, [i16; 4]) {
        self.prune(now);
        let mut scores = [0i16; 4];
        let profile = self.entries.get(&EvidenceKey::Profile(profile_key));
        let profile_ready = profile.is_some_and(|entry| {
            entry.outcomes >= PROFILE_MIN_OUTCOMES
                && entry.cohorts.iter().flatten().count() >= PROFILE_MIN_COHORTS
        });
        let user_agent = self.entries.get(&EvidenceKey::UserAgent(
            profile_key,
            request.class(),
            request.user_agent_hash(),
        ));
        let ip = self.entries.get(&EvidenceKey::Ip(profile_key, client_ip));
        for carrier in WebCarrier::ALL {
            let index = carrier.index();
            if profile_ready {
                scores[index] += i16::from(profile.map_or(0, |entry| entry.scores[index]))
                    * PROFILE_WEIGHT;
            }
            scores[index] += i16::from(user_agent.map_or(0, |entry| entry.scores[index]))
                * USER_AGENT_WEIGHT;
            scores[index] +=
                i16::from(ip.map_or(0, |entry| entry.scores[index])) * IP_WEIGHT;
        }
        let mut ranked = configured
            .iter()
            .copied()
            .filter(|carrier| request.supports(*carrier))
            .collect::<Vec<_>>();
        ranked.sort_by_key(|carrier| std::cmp::Reverse(scores[carrier.index()]));
        (ranked, scores)
    }

    /// Records one committed success or one server-accepted supersession failure.
    pub(super) fn record(
        &mut self,
        now: Instant,
        lifetime: Duration,
        context: CarrierLearningContext,
        carrier: WebCarrier,
        success: bool,
    ) {
        self.prune(now);
        let delta = if success { 1 } else { -1 };
        let cohort = cohort_hash(context);
        self.update(
            EvidenceKey::Profile(context.profile_key),
            now,
            lifetime,
            carrier,
            delta,
            Some(cohort),
        );
        self.update(
            EvidenceKey::UserAgent(
                context.profile_key,
                context.class,
                context.user_agent_hash,
            ),
            now,
            lifetime,
            carrier,
            delta,
            None,
        );
        self.update(
            EvidenceKey::Ip(context.profile_key, context.client_ip),
            now,
            lifetime,
            carrier,
            delta,
            None,
        );
    }

    /// Removes fixed-window entries after their creation-time expiry.
    pub(super) fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.created_at) <= entry.lifetime
        });
    }

    fn update(
        &mut self,
        key: EvidenceKey,
        now: Instant,
        lifetime: Duration,
        carrier: WebCarrier,
        delta: i8,
        cohort: Option<[u8; 32]>,
    ) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries
            .entry(key)
            .or_insert_with(|| Evidence::new(now, lifetime))
            .update(carrier, delta, cohort);
    }
}

fn cohort_hash(context: CarrierLearningContext) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COHORT_CONTEXT);
    digest.update(context.profile_key);
    digest.update([match context.class {
        CarrierClientClass::Legacy => 0,
        CarrierClientClass::Bridge => 1,
        CarrierClientClass::BrowserHint => 2,
    }]);
    digest.update(context.user_agent_hash);
    match context.client_ip {
        IpAddr::V4(address) => {
            digest.update([4]);
            digest.update(address.octets());
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            digest.update(address.octets());
        }
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::manager::{CarrierCapabilities, CarrierRequest};

    fn request(hash: u8) -> CarrierRequest {
        CarrierRequest::automatic(
            CarrierClientClass::Bridge,
            CarrierCapabilities::all(),
            1,
            None,
            [hash; 32],
        )
    }

    #[test]
    fn evidence_is_bounded_and_expires_without_sliding() {
        let start = Instant::now();
        let mut learning = CarrierLearning::new(3);
        let context = CarrierLearningContext {
            profile_key: [1; 32],
            client_ip: "192.0.2.1".parse().unwrap(),
            class: CarrierClientClass::Bridge,
            user_agent_hash: [2; 32],
        };
        learning.record(
            start,
            Duration::from_secs(10),
            context,
            WebCarrier::Websocket,
            true,
        );
        assert_eq!(learning.entries.len(), 3);
        learning.record(
            start + Duration::from_secs(5),
            Duration::from_secs(10),
            context,
            WebCarrier::Websocket,
            true,
        );
        learning.prune(start + Duration::from_secs(11));
        assert!(learning.entries.is_empty());
    }

    #[test]
    fn user_agent_and_ip_evidence_rank_stably() {
        let now = Instant::now();
        let mut learning = CarrierLearning::new(16);
        let context = CarrierLearningContext {
            profile_key: [1; 32],
            client_ip: "192.0.2.1".parse().unwrap(),
            class: CarrierClientClass::Bridge,
            user_agent_hash: [2; 32],
        };
        learning.record(
            now,
            Duration::from_secs(10),
            context,
            WebCarrier::Websocket,
            true,
        );
        let (ranked, scores) = learning.rank(
            now,
            &[WebCarrier::Https, WebCarrier::Websocket],
            request(2),
            context.profile_key,
            context.client_ip,
        );
        assert_eq!(ranked, [WebCarrier::Websocket, WebCarrier::Https]);
        assert_eq!(scores[WebCarrier::Websocket.index()], 5);
    }

    #[test]
    fn profile_evidence_requires_outcome_and_cohort_thresholds() {
        let now = Instant::now();
        let profile_key = [1; 32];
        let configured = [WebCarrier::Https, WebCarrier::Websocket];
        let unrelated_ip = "198.51.100.10".parse().unwrap();
        let mut learning = CarrierLearning::new(64);
        for cohort in 1..=3u8 {
            let context = CarrierLearningContext {
                profile_key,
                client_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, cohort)),
                class: CarrierClientClass::Bridge,
                user_agent_hash: [cohort; 32],
            };
            for _ in 0..2 {
                learning.record(
                    now,
                    Duration::from_secs(10),
                    context,
                    WebCarrier::Websocket,
                    true,
                );
            }
        }
        let (ranked, _) = learning.rank(
            now,
            &configured,
            request(99),
            profile_key,
            unrelated_ip,
        );
        assert_eq!(ranked, configured);

        let fourth = CarrierLearningContext {
            profile_key,
            client_ip: "192.0.2.4".parse().unwrap(),
            class: CarrierClientClass::Bridge,
            user_agent_hash: [4; 32],
        };
        for _ in 0..2 {
            learning.record(
                now,
                Duration::from_secs(10),
                fourth,
                WebCarrier::Websocket,
                true,
            );
        }
        let (ranked, scores) = learning.rank(
            now,
            &configured,
            request(99),
            profile_key,
            unrelated_ip,
        );
        assert_eq!(ranked, [WebCarrier::Websocket, WebCarrier::Https]);
        assert_eq!(scores[WebCarrier::Websocket.index()], 32);
    }
}
