use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use zeroize::Zeroizing;

use super::sanitize::{
    bounded_text, capture_limit, frame_error_name, frame_type_name, request_dynamic_bytes,
    response_dynamic_bytes, sanitized_headers, scrub_body, sensitive_values,
};
use super::store::{WebTraceStore, epoch_millis};
use super::types::{
    TraceBodySnapshot, TraceBodyState, TraceDirection, TraceFrame, TraceHeader, TraceHttpRecord,
    TraceIdentity, TraceRecord, TraceRecordKind, TraceRoute, TraceTimings,
};
use crate::config::{WebDebugBodyCapture, WebDebugConfig, WebLimitsConfig, WebRuntimeProfile};
use crate::web::frame::{self, FrameType};

const USER_AGENT_MAX_BYTES: usize = 512;

#[derive(Default)]
struct BodyCapture {
    observed_bytes: u64,
    captured: Vec<u8>,
    truncated: bool,
    state: Option<TraceBodyState>,
}

struct ExchangeState {
    method: String,
    path: String,
    route: TraceRoute,
    peer_ip: IpAddr,
    effective_ip: Option<IpAddr>,
    user_agent: Option<String>,
    identity: TraceIdentity,
    request_headers: Vec<TraceHeader>,
    response_headers: Vec<TraceHeader>,
    request_body: BodyCapture,
    response_body: BodyCapture,
    status: Option<u16>,
    frames: Vec<TraceFrame>,
    timings: TraceTimings,
    redactions: Vec<Zeroizing<Vec<u8>>>,
    body_capture_blocked: bool,
}

/// One in-flight request-to-response capture with process-wide byte leases.
pub(crate) struct HttpTraceExchange {
    store: Arc<WebTraceStore>,
    epoch: u64,
    policy: Arc<WebDebugConfig>,
    started: Instant,
    started_epoch_millis: u64,
    state: Mutex<ExchangeState>,
    reserved: AtomicUsize,
    committed: AtomicBool,
}

impl HttpTraceExchange {
    /// Creates one enabled exchange after the store reserved its base record lease.
    pub(super) fn new<B>(
        store: Arc<WebTraceStore>,
        epoch: u64,
        policy: Arc<WebDebugConfig>,
        request: &hyper::Request<B>,
        peer_ip: IpAddr,
        base_reservation: usize,
    ) -> Arc<Self> {
        let started = Instant::now();
        let started_epoch_millis = epoch_millis();
        let dynamic = request_dynamic_bytes(request, &policy);
        let dynamic_reserved = store.try_reserve(dynamic);
        let (method, path, user_agent, request_headers, redactions) = if dynamic_reserved {
            (
                request.method().as_str().to_string(),
                request.uri().path().to_string(),
                request
                    .headers()
                    .get(hyper::header::USER_AGENT)
                    .map(|value| bounded_text(value.as_bytes(), USER_AGENT_MAX_BYTES)),
                if policy.capture_headers {
                    sanitized_headers(request.headers())
                } else {
                    Vec::new()
                },
                sensitive_values(request.headers(), request.uri().query()),
            )
        } else {
            (
                bounded_text(request.method().as_str().as_bytes(), 32),
                bounded_text(request.uri().path().as_bytes(), 512),
                None,
                Vec::new(),
                Vec::new(),
            )
        };
        Arc::new(Self {
            store,
            epoch,
            policy,
            started,
            started_epoch_millis,
            state: Mutex::new(ExchangeState {
                method,
                path,
                route: TraceRoute::Unknown,
                peer_ip,
                effective_ip: None,
                user_agent,
                identity: TraceIdentity::default(),
                request_headers,
                response_headers: Vec::new(),
                request_body: BodyCapture::default(),
                response_body: BodyCapture::default(),
                status: None,
                frames: Vec::new(),
                timings: TraceTimings::default(),
                redactions,
                body_capture_blocked: !dynamic_reserved,
            }),
            reserved: AtomicUsize::new(
                base_reservation + if dynamic_reserved { dynamic } else { 0 },
            ),
            committed: AtomicBool::new(false),
        })
    }

    /// Sets the final request route before body polling or decoy forwarding.
    pub(crate) fn set_route(&self, route: TraceRoute) {
        self.state.lock().route = route;
    }

    /// Sets the trusted effective client address after proxy-header validation.
    pub(crate) fn set_effective_ip(&self, client_ip: IpAddr) {
        self.state.lock().effective_ip = Some(client_ip);
    }

    /// Binds non-secret profile and process session identity.
    pub(crate) fn bind_profile(&self, profile: &WebRuntimeProfile, session_id: u64) {
        let dynamic = profile
            .user
            .len()
            .saturating_add(profile.key_fingerprint.len());
        let mut state = self.state.lock();
        state.identity.session_id = Some(session_id);
        if self.reserve(dynamic) {
            state.identity.user = Some(profile.user.clone());
            state.identity.key_fingerprint = Some(profile.key_fingerprint.clone());
        }
    }

    /// Binds an already resolved non-secret session identity.
    pub(crate) fn bind_identity(&self, identity: TraceIdentity) {
        let dynamic = identity
            .user
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(identity.key_fingerprint.as_ref().map_or(0, String::len));
        let mut state = self.state.lock();
        state.identity.session_id = identity.session_id;
        if self.reserve(dynamic) {
            state.identity.user = identity.user;
            state.identity.key_fingerprint = identity.key_fingerprint;
        }
    }

    /// Registers an ephemeral credential for body scrubbing before commit.
    pub(crate) fn register_redaction(&self, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        if !self.reserve(value.len()) {
            self.block_body_capture();
            return;
        }
        self.state
            .lock()
            .redactions
            .push(Zeroizing::new(value.to_vec()));
    }

    /// Captures response status and sanitized headers at handler completion.
    pub(crate) fn response_ready<B>(&self, response: &hyper::Response<B>) {
        let dynamic = response_dynamic_bytes(response, &self.policy);
        let reserved = self.reserve(dynamic);
        let mut state = self.state.lock();
        state.status = Some(response.status().as_u16());
        if self.policy.capture_headers && reserved {
            state.response_headers = sanitized_headers(response.headers());
        }
        if reserved {
            state
                .redactions
                .extend(sensitive_values(response.headers(), None));
        } else if dynamic != 0 {
            state.body_capture_blocked = true;
            state.request_body.captured.clear();
            state.response_body.captured.clear();
            state.request_body.truncated = true;
            state.response_body.truncated = true;
        }
        if self.policy.capture_timings {
            state.timings.response_ready_us = Some(self.elapsed_us());
        }
    }

    /// Appends one body data frame without changing the proxied bytes.
    pub(crate) fn body_data(&self, direction: TraceDirection, data: &[u8]) {
        let mut state = self.state.lock();
        let route = state.route;
        let body_capture_blocked = state.body_capture_blocked;
        let body = match direction {
            TraceDirection::Request => &mut state.request_body,
            TraceDirection::Response => &mut state.response_body,
        };
        body.observed_bytes = body
            .observed_bytes
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if data.is_empty() {
            return;
        }
        if body_capture_blocked {
            body.truncated |= !data.is_empty();
            return;
        }
        let Some(limit) = capture_limit(&self.policy, route, self.store.max_carrier_body_bytes())
        else {
            return;
        };
        if body.captured.len() >= limit {
            if !data.is_empty() && !body.truncated {
                self.store.record_truncation();
            }
            body.truncated |= !data.is_empty();
            return;
        }
        if body.captured.capacity() == 0 {
            if !self.reserve(limit) {
                body.truncated = true;
                return;
            }
            body.captured = Vec::with_capacity(limit);
        }
        let take = data.len().min(limit - body.captured.len());
        body.captured.extend_from_slice(&data[..take]);
        if take < data.len() {
            if !body.truncated {
                self.store.record_truncation();
            }
            body.truncated = true;
        }
    }

    /// Marks one request or response body terminal state.
    pub(crate) fn body_finished(&self, direction: TraceDirection, terminal: TraceBodyState) {
        let mut state = self.state.lock();
        let body = match direction {
            TraceDirection::Request => &mut state.request_body,
            TraceDirection::Response => &mut state.response_body,
        };
        if body.state.is_none() {
            body.state = Some(terminal);
        }
        if self.policy.capture_timings {
            match direction {
                TraceDirection::Request => state.timings.request_body_us = Some(self.elapsed_us()),
                TraceDirection::Response => {
                    state.timings.response_body_us = Some(self.elapsed_us())
                }
            }
        }
        drop(state);
        if direction == TraceDirection::Response {
            self.commit();
        }
    }

    /// Attaches parsed carrier frame metadata from one complete bounded body.
    pub(crate) fn record_frames(
        &self,
        direction: TraceDirection,
        body: &[u8],
        limits: &WebLimitsConfig,
    ) {
        if !self.policy.capture_frames {
            return;
        }
        let estimated_frames = body
            .len()
            .div_ceil(frame::HEADER_BYTES)
            .clamp(1, limits.max_frames_per_body);
        let reservation = estimated_frames.saturating_mul(std::mem::size_of::<TraceFrame>());
        if !self.reserve(reservation) {
            return;
        }
        let frames = match frame::parse_all(body, limits) {
            Ok(frames) => frames
                .into_iter()
                .map(|frame| TraceFrame {
                    direction,
                    frame_type: Some(frame_type_name(frame.frame_type)),
                    stream_id: Some(frame.stream_id),
                    payload_len: Some(frame.payload.len()),
                    window_delta: (frame.frame_type == FrameType::Window)
                        .then(|| frame::window_amount(frame.payload).ok())
                        .flatten(),
                    parse_error: None,
                })
                .collect::<Vec<_>>(),
            Err(error) => vec![TraceFrame {
                direction,
                frame_type: None,
                stream_id: None,
                payload_len: None,
                window_delta: None,
                parse_error: Some(frame_error_name(error)),
            }],
        };
        self.state.lock().frames.extend(frames);
    }

    /// Commits once after response body consumption or drop.
    pub(crate) fn commit(&self) {
        if self.committed.swap(true, Ordering::AcqRel) {
            return;
        }
        let reserved = self.reserved.load(Ordering::Acquire);
        let record = self.build_record();
        if !self.store.try_commit(record, reserved, self.epoch) {
            self.store.release(reserved);
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        if self.store.try_reserve(bytes) {
            self.reserved.fetch_add(bytes, Ordering::AcqRel);
            true
        } else {
            false
        }
    }

    fn block_body_capture(&self) {
        let mut state = self.state.lock();
        state.body_capture_blocked = true;
        state.request_body.captured.clear();
        state.response_body.captured.clear();
        state.request_body.truncated = true;
        state.response_body.truncated = true;
    }

    fn build_record(&self) -> TraceRecord {
        let mut state = self.state.lock();
        let redactions = std::mem::take(&mut state.redactions);
        scrub_body(&mut state.request_body.captured, &redactions);
        scrub_body(&mut state.response_body.captured, &redactions);
        let request_body = body_snapshot(&self.policy, &mut state.request_body);
        let response_body = body_snapshot(&self.policy, &mut state.response_body);
        TraceRecord {
            seq: self.store.next_record_seq(),
            epoch_millis: self.started_epoch_millis,
            peer_ip: Some(state.peer_ip),
            effective_ip: state.effective_ip,
            user_agent: state.user_agent.take(),
            identity: std::mem::take(&mut state.identity),
            kind: TraceRecordKind::Http(TraceHttpRecord {
                method: std::mem::take(&mut state.method),
                path: std::mem::take(&mut state.path),
                route: state.route,
                request_headers: std::mem::take(&mut state.request_headers),
                response_headers: std::mem::take(&mut state.response_headers),
                request_body,
                status: state.status,
                response_body,
                frames: std::mem::take(&mut state.frames),
                timings: self
                    .policy
                    .capture_timings
                    .then(|| std::mem::take(&mut state.timings)),
            }),
        }
    }

    fn elapsed_us(&self) -> u64 {
        self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }
}

impl Drop for HttpTraceExchange {
    fn drop(&mut self) {
        if !self.committed.load(Ordering::Acquire) {
            self.body_finished(TraceDirection::Request, TraceBodyState::Aborted);
            self.body_finished(TraceDirection::Response, TraceBodyState::Aborted);
        }
    }
}

fn body_snapshot(policy: &WebDebugConfig, body: &mut BodyCapture) -> Option<TraceBodySnapshot> {
    (policy.body_capture != WebDebugBodyCapture::Off).then(|| TraceBodySnapshot {
        observed_bytes: body.observed_bytes,
        captured: std::mem::take(&mut body.captured),
        truncated: body.truncated,
        state: body.state.unwrap_or(TraceBodyState::Aborted),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_capture_redacts_credentials_and_omits_query() {
        let request_token = "request-token-0123456789";
        let capability = "capability-0123456789";
        let response_token = "response-token-0123456789";
        let request = hyper::Request::builder()
            .uri(format!("/?bridge={capability}"))
            .header("authorization", format!("Bearer {request_token}"))
            .body(())
            .unwrap();
        let policy = WebDebugConfig {
            enabled: true,
            body_capture: WebDebugBodyCapture::Prefix,
            body_prefix_bytes: 256,
            ..Default::default()
        };
        let limits = WebLimitsConfig {
            debug_records_capacity: 4,
            debug_bytes_global: 16 * 1024,
            ..Default::default()
        };
        let store = WebTraceStore::new(policy, &limits);
        let exchange = store
            .begin_http(&request, "192.0.2.30".parse().unwrap())
            .unwrap();
        exchange.set_route(TraceRoute::Bridge);
        exchange.body_data(
            TraceDirection::Request,
            format!("{request_token}:{capability}").as_bytes(),
        );
        exchange.body_finished(TraceDirection::Request, TraceBodyState::Complete);

        let response = hyper::Response::builder()
            .status(hyper::StatusCode::OK)
            .header("x-session-token", response_token)
            .body(())
            .unwrap();
        exchange.response_ready(&response);
        exchange.body_data(TraceDirection::Response, response_token.as_bytes());
        exchange.body_finished(TraceDirection::Response, TraceBodyState::Complete);

        let records = store.snapshot_matching(|_| true);
        assert_eq!(records.len(), 1);
        let TraceRecordKind::Http(http) = &records[0].record.kind else {
            panic!("expected HTTP debug record");
        };
        assert_eq!(http.path, "/");
        assert_eq!(http.route, TraceRoute::Bridge);
        assert!(
            http.request_headers
                .iter()
                .any(|header| header.name == "authorization" && header.value.is_none())
        );
        assert!(
            http.response_headers
                .iter()
                .any(|header| header.name == "x-session-token" && header.value.is_none())
        );
        let request_body = http.request_body.as_ref().unwrap();
        let response_body = http.response_body.as_ref().unwrap();
        for secret in [request_token.as_bytes(), capability.as_bytes()] {
            assert!(
                !request_body
                    .captured
                    .windows(secret.len())
                    .any(|value| value == secret)
            );
        }
        assert!(
            !response_body
                .captured
                .windows(response_token.len())
                .any(|value| value == response_token.as_bytes())
        );
    }
}
