use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::ProfileKey;
use super::negotiation::{CarrierClientClass, CarrierLearningContext};
use crate::config::{WebCarrier, WebCarrierNegotiationAggressiveness};

const PROFILE_WEIGHT: i16 = 32;
const USER_AGENT_WEIGHT: i16 = 32;
const IP_WEIGHT: i16 = 1;
const SCORE_MIN: i8 = -8;
const SCORE_MAX: i8 = 8;
const MAX_COHORTS: usize = 4;
const PRUNE_ENTRIES_PER_TICK: usize = 64;
const COHORT_CONTEXT: &[u8] = b"telemt-web-carrier-cohort-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EvidenceKey {
    Profile(ProfileKey),
    UserAgent(ProfileKey, CarrierClientClass, [u8; 32]),
    Ip(ProfileKey, IpAddr),
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    slot: u64,
    valid: bool,
    scores: [i8; 4],
    outcomes: u8,
    cohorts: [Option<[u8; 32]>; MAX_COHORTS],
}

impl Bucket {
    fn reset(&mut self, slot: u64) {
        *self = Self {
            slot,
            valid: true,
            ..Self::default()
        };
    }

    fn update(&mut self, deltas: [i8; 4], cohort: Option<[u8; 32]>) {
        for (score, delta) in self.scores.iter_mut().zip(deltas) {
            *score = score.saturating_add(delta).clamp(SCORE_MIN, SCORE_MAX);
        }
        self.outcomes = self.outcomes.saturating_add(1);
        if let Some(cohort) = cohort
            && !self.cohorts.contains(&Some(cohort))
            && let Some(slot) = self.cohorts.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(cohort);
        }
    }
}

struct Evidence {
    insertion_sequence: u64,
    buckets: [Bucket; 2],
}

impl Evidence {
    fn new(insertion_sequence: u64) -> Self {
        Self {
            insertion_sequence,
            buckets: [Bucket::default(), Bucket::default()],
        }
    }

    fn update(&mut self, slot: u64, deltas: [i8; 4], cohort: Option<[u8; 32]>) {
        let index = slot as usize % self.buckets.len();
        if !self.buckets[index].valid || self.buckets[index].slot != slot {
            self.buckets[index].reset(slot);
        }
        self.buckets[index].update(deltas, cohort);
    }

    fn aggregate(&self, slot: u64) -> Aggregate {
        let mut aggregate = Aggregate::default();
        for bucket in &self.buckets {
            if !bucket.valid || (bucket.slot != slot && bucket.slot.saturating_add(1) != slot) {
                continue;
            }
            aggregate.outcomes = aggregate.outcomes.saturating_add(bucket.outcomes);
            for (score, value) in aggregate.scores.iter_mut().zip(bucket.scores) {
                *score = score.saturating_add(value).clamp(SCORE_MIN, SCORE_MAX);
            }
            for cohort in bucket.cohorts.iter().flatten() {
                if !aggregate.cohorts.contains(&Some(*cohort))
                    && let Some(target) = aggregate.cohorts.iter_mut().find(|slot| slot.is_none())
                {
                    *target = Some(*cohort);
                }
            }
        }
        aggregate
    }

    fn is_live(&self, slot: u64) -> bool {
        self.buckets.iter().any(|bucket| {
            bucket.valid && (bucket.slot == slot || bucket.slot.saturating_add(1) == slot)
        })
    }
}

#[derive(Default)]
struct Aggregate {
    scores: [i8; 4],
    outcomes: u8,
    cohorts: [Option<[u8; 32]>; MAX_COHORTS],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LearningPolicy {
    enabled: bool,
    aggressiveness: WebCarrierNegotiationAggressiveness,
    lifetime: Duration,
}

#[derive(Clone, Copy)]
struct Thresholds {
    user_agent: u8,
    ip: Option<u8>,
    profile_outcomes: u8,
    profile_cohorts: usize,
}

impl Thresholds {
    fn for_aggressiveness(value: WebCarrierNegotiationAggressiveness) -> Self {
        match value {
            WebCarrierNegotiationAggressiveness::Conservative => Self {
                user_agent: 3,
                ip: None,
                profile_outcomes: 8,
                profile_cohorts: 4,
            },
            WebCarrierNegotiationAggressiveness::Balanced => Self {
                user_agent: 2,
                ip: Some(3),
                profile_outcomes: 6,
                profile_cohorts: 3,
            },
            WebCarrierNegotiationAggressiveness::Aggressive => Self {
                user_agent: 1,
                ip: Some(1),
                profile_outcomes: 4,
                profile_cohorts: 2,
            },
        }
    }
}

/// Process-local bounded two-bucket carrier evidence store.
pub(super) struct CarrierLearning {
    entries: HashMap<EvidenceKey, Evidence>,
    insertion_order: VecDeque<(EvidenceKey, u64)>,
    capacity: usize,
    insertion_sequence: u64,
    epoch: Option<u64>,
    policy: Option<LearningPolicy>,
    policy_started_at: Instant,
}

/// Bounded control-plane summary of carrier-learning state.
#[derive(Clone, Copy)]
pub(crate) struct CarrierLearningStatus {
    /// Whether outcome learning is active in the effective policy.
    pub(crate) enabled: bool,
    /// Effective evidence thresholds.
    pub(crate) aggressiveness: WebCarrierNegotiationAggressiveness,
    /// Current evidence epoch, or none after counter exhaustion.
    pub(crate) epoch: Option<u64>,
    /// Retained evidence entries.
    pub(crate) entries: usize,
    /// Restart-owned evidence ceiling.
    pub(crate) capacity: usize,
    /// Effective evidence lifetime.
    pub(crate) lifetime_secs: u64,
    /// Monotonic age of the current policy epoch.
    pub(crate) age_ms: u64,
}

/// Result of one epoch-fenced learning reset.
#[derive(Clone, Copy)]
pub(crate) struct CarrierLearningResetOutcome {
    /// Evidence entries detached by the reset.
    pub(crate) entries_cleared: usize,
    /// New epoch fencing pre-reset outcomes.
    pub(crate) epoch: u64,
}

impl CarrierLearning {
    /// Creates an empty store under the restart-owned capacity ceiling.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            capacity,
            insertion_sequence: 1,
            epoch: Some(0),
            policy: None,
            policy_started_at: Instant::now(),
        }
    }

    fn status(&self, now: Instant) -> CarrierLearningStatus {
        let policy = self.policy.unwrap_or(LearningPolicy {
            enabled: false,
            aggressiveness: WebCarrierNegotiationAggressiveness::Conservative,
            lifetime: Duration::ZERO,
        });
        CarrierLearningStatus {
            enabled: policy.enabled,
            aggressiveness: policy.aggressiveness,
            epoch: self.epoch,
            entries: self.entries.len(),
            capacity: self.capacity,
            lifetime_secs: policy.lifetime.as_secs(),
            age_ms: millis(now.saturating_duration_since(self.policy_started_at)),
        }
    }

    /// Applies hot-reloaded learning policy and returns its outcome epoch.
    pub(super) fn apply_policy(
        &mut self,
        now: Instant,
        enabled: bool,
        aggressiveness: WebCarrierNegotiationAggressiveness,
        lifetime: Duration,
    ) -> Option<u64> {
        let policy = LearningPolicy {
            enabled,
            aggressiveness,
            lifetime,
        };
        if self.policy != Some(policy) {
            self.entries.clear();
            self.insertion_order.clear();
            if !enabled {
                self.entries.shrink_to_fit();
                self.insertion_order.shrink_to_fit();
            }
            self.insertion_sequence = 1;
            self.epoch = self.epoch.and_then(|epoch| epoch.checked_add(1));
            self.policy = Some(policy);
            self.policy_started_at = now;
        }
        self.epoch
    }

    /// Returns the current epoch only when the request snapshot matches owner policy.
    pub(super) fn epoch_for_policy(
        &self,
        enabled: bool,
        aggressiveness: WebCarrierNegotiationAggressiveness,
        lifetime: Duration,
    ) -> Option<u64> {
        (self.policy
            == Some(LearningPolicy {
                enabled,
                aggressiveness,
                lifetime,
            }))
        .then_some(self.epoch)
        .flatten()
    }

    /// Ranks supported configured candidates without scanning the evidence store.
    pub(super) fn rank(
        &self,
        now: Instant,
        configured: &[WebCarrier],
        request: super::CarrierRequest,
        profile_key: ProfileKey,
        client_ip: IpAddr,
        ip_learning_eligible: bool,
    ) -> (Vec<WebCarrier>, [i16; 4]) {
        let Some(policy) = self.policy.filter(|policy| policy.enabled) else {
            return (supported(configured, request), [0; 4]);
        };
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let thresholds = Thresholds::for_aggressiveness(policy.aggressiveness);
        let profile = self
            .entries
            .get(&EvidenceKey::Profile(profile_key))
            .map(|entry| entry.aggregate(slot));
        let user_agent = self
            .entries
            .get(&EvidenceKey::UserAgent(
                profile_key,
                request.class(),
                request.user_agent_hash(),
            ))
            .map(|entry| entry.aggregate(slot));
        let ip = (ip_learning_eligible && thresholds.ip.is_some())
            .then(|| self.entries.get(&EvidenceKey::Ip(profile_key, client_ip)))
            .flatten()
            .map(|entry| entry.aggregate(slot));
        let profile_ready = profile.as_ref().is_some_and(|entry| {
            entry.outcomes >= thresholds.profile_outcomes
                && entry.cohorts.iter().flatten().count() >= thresholds.profile_cohorts
        });
        let user_agent_ready = user_agent
            .as_ref()
            .is_some_and(|entry| entry.outcomes >= thresholds.user_agent);
        let ip_ready = thresholds
            .ip
            .is_some_and(|minimum| ip.as_ref().is_some_and(|entry| entry.outcomes >= minimum));
        let mut scores = [0i16; 4];
        for carrier in WebCarrier::ALL {
            let index = carrier.index();
            if profile_ready {
                scores[index] += i16::from(profile.as_ref().map_or(0, |value| value.scores[index]))
                    * PROFILE_WEIGHT;
            }
            if user_agent_ready {
                scores[index] +=
                    i16::from(user_agent.as_ref().map_or(0, |value| value.scores[index]))
                        * USER_AGENT_WEIGHT;
            }
            if ip_ready {
                scores[index] +=
                    i16::from(ip.as_ref().map_or(0, |value| value.scores[index])) * IP_WEIGHT;
            }
        }
        let mut ranked = supported(configured, request);
        let fallback = configured
            .last()
            .copied()
            .filter(|carrier| request.supports(*carrier));
        if let Some(fallback) = fallback {
            ranked.retain(|carrier| *carrier != fallback);
        }
        ranked.sort_by_key(|carrier| std::cmp::Reverse(scores[carrier.index()]));
        if let Some(fallback) = fallback {
            ranked.push(fallback);
        }
        (ranked, scores)
    }

    /// Applies one complete attempt chain as one atomic evidence sample.
    pub(super) fn record_chain(
        &mut self,
        now: Instant,
        epoch: u64,
        context: CarrierLearningContext,
        failures: &[WebCarrier],
        winner: WebCarrier,
    ) {
        let Some(policy) = self.policy.filter(|policy| policy.enabled) else {
            return;
        };
        if Some(epoch) != self.epoch {
            return;
        }
        let mut deltas = [0i8; 4];
        let _ = failures;
        deltas[winner.index()] = deltas[winner.index()].saturating_add(1);
        let thresholds = Thresholds::for_aggressiveness(policy.aggressiveness);
        let keys = [
            Some(EvidenceKey::Profile(context.profile_key)),
            Some(EvidenceKey::UserAgent(
                context.profile_key,
                context.class,
                context.user_agent_hash,
            )),
            (context.ip_learning_eligible && thresholds.ip.is_some())
                .then_some(EvidenceKey::Ip(context.profile_key, context.client_ip)),
        ];
        self.make_room(&keys);
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !self.entries.contains_key(key))
            .count();
        if self.entries.len().saturating_add(missing) > self.capacity {
            return;
        }
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let cohort = cohort_hash(context);
        for (index, key) in keys.into_iter().enumerate() {
            let Some(key) = key else { continue };
            self.update_key(key, slot, deltas, (index == 0).then_some(cohort));
        }
    }

    /// Reclaims a fixed number of entries outside both half-window buckets.
    pub(super) fn prune(&mut self, now: Instant) {
        let Some(policy) = self.policy else { return };
        let slot = bucket_slot(self.policy_started_at, now, policy.lifetime);
        let budget = self.insertion_order.len().min(PRUNE_ENTRIES_PER_TICK);
        for _ in 0..budget {
            let Some((key, sequence)) = self.insertion_order.pop_front() else {
                break;
            };
            let current = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.insertion_sequence == sequence);
            if !current {
                continue;
            }
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.is_live(slot))
            {
                self.insertion_order.push_back((key, sequence));
            } else {
                self.entries.remove(&key);
            }
        }
    }

    fn make_room(&mut self, keys: &[Option<EvidenceKey>; 3]) {
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !self.entries.contains_key(key))
            .count();
        let mut remaining = self.insertion_order.len();
        while self.entries.len().saturating_add(missing) > self.capacity && remaining > 0 {
            remaining -= 1;
            let Some((oldest, sequence)) = self.insertion_order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&oldest)
                .is_none_or(|entry| entry.insertion_sequence != sequence)
            {
                continue;
            }
            if keys.contains(&Some(oldest)) {
                self.insertion_order.push_back((oldest, sequence));
                continue;
            }
            self.entries.remove(&oldest);
        }
    }

    fn update_key(
        &mut self,
        key: EvidenceKey,
        slot: u64,
        deltas: [i8; 4],
        cohort: Option<[u8; 32]>,
    ) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.update(slot, deltas, cohort);
            return;
        }
        let Some(insertion_sequence) = self.next_insertion_sequence() else {
            return;
        };
        self.entries.insert(key, Evidence::new(insertion_sequence));
        self.insertion_order.push_back((key, insertion_sequence));
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.update(slot, deltas, cohort);
        }
    }

    fn next_insertion_sequence(&mut self) -> Option<u64> {
        let sequence = self.insertion_sequence;
        self.insertion_sequence = sequence.checked_add(1)?;
        Some(sequence)
    }
}

impl super::WebProcessRuntime {
    /// Captures learning state without waiting for a contended evidence lock.
    pub(crate) fn try_carrier_learning_status(&self) -> Option<CarrierLearningStatus> {
        self.learning
            .try_lock()
            .map(|learning| learning.status(Instant::now()))
    }

    /// Clears all evidence under a new epoch without changing the active policy.
    pub(crate) fn reset_carrier_learning(
        &self,
    ) -> Result<CarrierLearningResetOutcome, super::ManagerError> {
        let control = self
            .control_mutation_guard()
            .map_err(|_| super::ManagerError::Closed)?;
        let (outcome, retired_entries, retired_order) = {
            let mut learning = self.learning.lock();
            let epoch = learning
                .epoch
                .and_then(|epoch| epoch.checked_add(1))
                .ok_or(super::ManagerError::Closed)?;
            learning.epoch = Some(epoch);
            learning.insertion_sequence = 1;
            learning.policy_started_at = Instant::now();
            let retired_entries = std::mem::take(&mut learning.entries);
            let retired_order = std::mem::take(&mut learning.insertion_order);
            (
                CarrierLearningResetOutcome {
                    entries_cleared: retired_entries.len(),
                    epoch,
                },
                retired_entries,
                retired_order,
            )
        };
        drop(control);
        drop((retired_entries, retired_order));
        Ok(outcome)
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn supported(configured: &[WebCarrier], request: super::CarrierRequest) -> Vec<WebCarrier> {
    configured
        .iter()
        .copied()
        .filter(|carrier| request.supports(*carrier))
        .collect()
}

fn bucket_slot(start: Instant, now: Instant, lifetime: Duration) -> u64 {
    let half = (lifetime / 2).max(Duration::from_nanos(1));
    let quotient = now.saturating_duration_since(start).as_nanos() / half.as_nanos();
    quotient.min(u128::from(u64::MAX)) as u64
}

fn cohort_hash(context: CarrierLearningContext) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COHORT_CONTEXT);
    digest.update(context.profile_key);
    digest.update([match context.class {
        CarrierClientClass::Legacy => 0,
        CarrierClientClass::Bridge => 1,
        CarrierClientClass::BrowserHint => 2,
        CarrierClientClass::Ios => 3,
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
#[path = "carrier_learning/tests.rs"]
mod tests;
