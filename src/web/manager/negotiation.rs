use std::net::IpAddr;

use crate::config::WebCarrier;

/// Stable client classification used only for carrier negotiation and learning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CarrierClientClass {
    /// A client that did not present server-bridge negotiation metadata.
    Legacy,
    /// The generated bridge presented the explicit capability marker.
    Bridge,
    /// Strict same-origin browser metadata survived while the marker did not.
    BrowserHint,
}

impl CarrierClientClass {
    /// Returns the non-sensitive token exposed by WEB debug lifecycle records.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Bridge => "bridge",
            Self::BrowserHint => "browser-hint",
        }
    }
}

/// Canonical carrier failure category reported by the generated bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierFailure {
    /// The cumulative attempt deadline elapsed.
    Timeout,
    /// The browser observed a network failure.
    Network,
    /// A WebSocket upgrade or post-upgrade acknowledgement failed.
    Upgrade,
    /// The carrier returned an unexpected HTTP result.
    Http,
    /// The carrier violated its response or framing contract.
    Protocol,
}

impl CarrierFailure {
    /// Parses one canonical bridge failure token.
    pub(crate) const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"timeout" => Some(Self::Timeout),
            b"network" => Some(Self::Network),
            b"upgrade" => Some(Self::Upgrade),
            b"http" => Some(Self::Http),
            b"protocol" => Some(Self::Protocol),
            _ => None,
        }
    }

    /// Returns the canonical non-sensitive failure token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Network => "network",
            Self::Upgrade => "upgrade",
            Self::Http => "http",
            Self::Protocol => "protocol",
        }
    }
}

/// Fixed carrier capability set sent by the generated bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierCapabilities(u8);

impl CarrierCapabilities {
    /// Returns a set containing every carrier implemented by the generated bridge.
    pub(crate) const fn all() -> Self {
        Self(0b1111)
    }

    /// Builds a set from a validated bit representation.
    pub(crate) const fn from_bits(bits: u8) -> Option<Self> {
        if bits != 0 && bits & !0b1111 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns whether the bridge can run one carrier.
    pub(crate) const fn contains(self, carrier: WebCarrier) -> bool {
        self.0 & (1 << carrier.index()) != 0
    }
}

/// Immutable metadata attached to one session-creation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierRequest {
    class: CarrierClientClass,
    capabilities: Option<CarrierCapabilities>,
    attempt: Option<u8>,
    failure: Option<CarrierFailure>,
    user_agent_hash: [u8; 32],
}

impl CarrierRequest {
    /// Constructs legacy metadata without enabling negotiation or learning.
    pub(crate) const fn legacy(user_agent_hash: [u8; 32]) -> Self {
        Self {
            class: CarrierClientClass::Legacy,
            capabilities: None,
            attempt: None,
            failure: None,
            user_agent_hash,
        }
    }

    /// Constructs validated automatic-negotiation metadata.
    pub(crate) const fn automatic(
        class: CarrierClientClass,
        capabilities: CarrierCapabilities,
        attempt: u8,
        failure: Option<CarrierFailure>,
        user_agent_hash: [u8; 32],
    ) -> Self {
        Self {
            class,
            capabilities: Some(capabilities),
            attempt: Some(attempt),
            failure,
            user_agent_hash,
        }
    }

    /// Returns whether this request participates in server-side negotiation.
    pub(crate) const fn is_automatic(self) -> bool {
        self.capabilities.is_some()
    }

    /// Returns the canonical attempt number when negotiation is active.
    pub(crate) const fn attempt(self) -> Option<u8> {
        self.attempt
    }

    /// Returns the reported reason for advancing from the previous candidate.
    pub(crate) const fn failure(self) -> Option<CarrierFailure> {
        self.failure
    }

    /// Returns whether a carrier is supported by this request.
    pub(crate) const fn supports(self, carrier: WebCarrier) -> bool {
        match self.capabilities {
            Some(capabilities) => capabilities.contains(carrier),
            None => false,
        }
    }

    /// Returns the stable non-sensitive client class.
    pub(crate) const fn class(self) -> CarrierClientClass {
        self.class
    }

    /// Returns the normalized User-Agent digest.
    pub(crate) const fn user_agent_hash(self) -> [u8; 32] {
        self.user_agent_hash
    }

    /// Checks the capability identity frozen across sequential attempts.
    pub(crate) fn matches_client(self, other: Self) -> bool {
        self.class == other.class
            && self.capabilities_bits() == other.capabilities_bits()
            && self.user_agent_hash == other.user_agent_hash
    }

    fn capabilities_bits(self) -> Option<u8> {
        self.capabilities.map(|capabilities| capabilities.0)
    }
}

/// Secret-independent evidence owner frozen into an automatic session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierLearningContext {
    /// Stable profile namespace.
    pub(crate) profile_key: super::ProfileKey,
    /// Effective client address from the trusted L7 boundary.
    pub(crate) client_ip: IpAddr,
    /// Client-class namespace for normalized User-Agent evidence.
    pub(crate) class: CarrierClientClass,
    /// Domain-separated normalized User-Agent digest.
    pub(crate) user_agent_hash: [u8; 32],
}
