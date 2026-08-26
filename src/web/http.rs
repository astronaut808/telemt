use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::config::{WebClientIpSource, WebRuntimeVhost};
use crate::web::bridge;
use crate::web::frame::{self, FrameType};
use crate::web::manager::{ManagerError, WebProcessRuntime};

// Response-body activity keeps connection idle accounting lifecycle-correct.
mod activity;
// Body collection retains allocation permits through request processing.
mod body;
// Decoy routing and upstream proxying are isolated from carrier authentication.
mod decoy;
// Downlink long-poll handling remains isolated from request routing.
mod down;
// Canonical request parsing rejects ambiguous credentials before routing.
mod request;
// Carrier response construction and lane-header helpers are shared by handlers.
mod response;
// RFC 6455 upgrade validation and carrier drivers remain isolated from HTTP routing.
#[cfg(test)]
mod tests;
mod websocket;
// Enabled-debug integration coverage remains separate from carrier behavior tests.
#[cfg(test)]
#[path = "http/trace_tests.rs"]
mod trace_tests;

use crate::web::trace::{HttpTraceExchange, TraceDirection, TraceLifecycleEvent, TraceRoute};
use activity::{ActivityBody, RequestActivity};
use body::{CollectBodyError, CollectedBody, RequestBody, collect_body};
use decoy::serve_decoy;
use down::handle_down;
use request::{
    bearer_token_hash, binary_content_type, bridge_candidate, canonical_request_host,
    canonical_u64_header, carrier_request, client_ip, compatible_cookie_header, match_profile,
};
use response::{
    bad_gateway, carrier_empty, carrier_headers, carrier_lane, full_response, generic_not_found,
    insert_header, service_unavailable,
};

type BoxError = Box<dyn Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpResponse = Response<HttpBody>;

const CREATE_BODY_LIMIT: usize = 64;
const TRANSPORT_PATHS: [&str; 3] = ["/api/v1/session", "/api/v1/up", "/api/v1/down"];
const WEBSOCKET_PATH: &str = "/api/v1/ws";

/// Serves one bounded HTTP/1.1 connection accepted from an external TLS terminator.
pub(crate) async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: Arc<[IpNetwork]>,
    runtime: Arc<WebProcessRuntime>,
    cancellation: CancellationToken,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
) {
    let config = runtime.active_generation().config();
    let max_header_bytes = config.web.limits.max_header_bytes;
    let header_timeout = Duration::from_secs(config.web.timeouts.header_secs);
    let idle_timeout = Duration::from_secs(config.web.timeouts.http_idle_secs);
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let service_last_activity = Arc::clone(&last_activity);
    let service = service_fn(move |mut request| {
        let runtime = Arc::clone(&runtime);
        let trusted_proxy_cidrs = Arc::clone(&trusted_proxy_cidrs);
        let last_activity = Arc::clone(&service_last_activity);
        let client_ip_source = client_ip_source;
        async move {
            let activity = RequestActivity::begin(last_activity);
            let trace = runtime.trace().begin_http(&request, peer.ip());
            if let Some(trace) = &trace {
                request.extensions_mut().insert(Arc::clone(trace));
            }
            let request = request.map(|body| RequestBody::new(body, trace.clone()));
            let response = if let Some(_handler_permit) = runtime.try_http_handler() {
                handle_request(
                    request,
                    peer,
                    client_ip_source,
                    &trusted_proxy_cidrs,
                    runtime,
                )
                .await
            } else {
                service_unavailable()
            };
            if let Some(trace) = &trace {
                trace.response_ready(&response);
            }
            let response =
                response.map(|body| ActivityBody::new(body, activity, trace).boxed_unsync());
            Ok::<_, Infallible>(response)
        }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .max_buf_size(max_header_bytes)
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(websocket::ConnectionIo::new(stream, connection_permit)),
            service,
        )
        .with_upgrades();
    tokio::pin!(connection);
    let mut idle_check = tokio::time::interval((idle_timeout / 2).max(Duration::from_secs(1)));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = &mut connection => break,
            _ = idle_check.tick() => {
                if Instant::now().saturating_duration_since(*last_activity.lock())
                    >= idle_timeout
                {
                    break;
                }
            }
        }
    }
}

async fn handle_request(
    request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
) -> HttpResponse {
    set_trace_route(&request, TraceRoute::Decoy);
    if let Some(trace) = request_trace(&request)
        && let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs)
    {
        trace.set_effective_ip(client_ip);
    }
    let generation = runtime.active_generation();
    let config = generation.config();
    let Some(web_runtime) = config.web.runtime.as_ref() else {
        return generic_not_found();
    };
    let Some(host) = canonical_request_host(&request) else {
        return generic_not_found();
    };
    let Some(vhost) = web_runtime.vhosts.get(host).cloned() else {
        return generic_not_found();
    };
    let path = request.uri().path();
    if path == WEBSOCKET_PATH {
        return websocket::handle(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            vhost,
        )
        .await;
    }
    if TRANSPORT_PATHS.contains(&path) {
        return handle_api(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            vhost,
        )
        .await;
    }
    if path == "/" && matches!(*request.method(), Method::GET | Method::HEAD) {
        return handle_root(
            request,
            peer,
            client_ip_source,
            trusted_proxy_cidrs,
            runtime,
            vhost,
        )
        .await;
    }
    serve_decoy(request, vhost, false, &runtime).await
}

async fn handle_root(
    mut request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
) -> HttpResponse {
    let (candidate, canonical) = bridge_candidate(request.uri().query());
    let profile = match_profile(&vhost, &candidate);
    let Some(profile) = profile.filter(|_| canonical && request.method() == Method::GET) else {
        return serve_decoy(request, vhost, false, &runtime).await;
    };
    let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs) else {
        strip_query(&mut request);
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Bridge);
        trace.set_effective_ip(client_ip);
    }
    let bootstrap = match runtime.issue_bootstrap(Arc::clone(&profile), client_ip) {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                None,
                &profile,
                TraceLifecycleEvent::BootstrapRejected,
                None,
                Some(error.as_str()),
            );
            strip_query(&mut request);
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if let Some(trace) = request_trace(&request) {
        trace.bind_profile(&profile, bootstrap.trace_session_id);
        trace.register_redaction(bootstrap.token.as_bytes());
    }
    let generation = runtime.active_generation();
    let page = bridge::render(
        &vhost.host,
        &bootstrap.token,
        generation.config().web.limits.carrier_batch_bytes,
        generation.config().web.limits.pending_bytes_per_session,
        generation.config().web.limits.pending_items_per_session,
        profile.carrier_negotiation_enabled,
        profile.carriers.len(),
        profile.carrier_negotiation_deadlines_secs,
        &generation.rng,
    );
    let mut response = full_response(StatusCode::OK, Bytes::from(page.body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    insert_header(
        &mut response,
        header::CONTENT_SECURITY_POLICY,
        &page.content_security_policy,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-dns-prefetch-control"),
        HeaderValue::from_static("off"),
    );
    insert_header(
        &mut response,
        HeaderName::from_static("permissions-policy"),
        bridge::PERMISSIONS_POLICY,
    );
    response
}

async fn handle_api(
    request: Request<RequestBody>,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
) -> HttpResponse {
    if request.uri().query().is_some() || !compatible_cookie_header(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(client_ip) = client_ip(&request, peer, client_ip_source, trusted_proxy_cidrs) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_effective_ip(client_ip);
    }
    let Some(token_hash) = bearer_token_hash(&request) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    match request.uri().path() {
        "/api/v1/session" => handle_session(request, runtime, vhost, token_hash, client_ip).await,
        "/api/v1/up" => handle_up(request, runtime, vhost, token_hash).await,
        "/api/v1/down" => handle_down(request, runtime, vhost, token_hash).await,
        _ => serve_decoy(request, vhost, true, &runtime).await,
    }
}

async fn handle_session(
    request: Request<RequestBody>,
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    token_hash: crate::web::manager::TokenHash,
    client_ip: IpAddr,
) -> HttpResponse {
    if request.headers().contains_key("x-lane-id") {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    if request.method() == Method::DELETE {
        if request.headers().contains_key(header::CONTENT_TYPE) {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
        if let Some(trace) = request_trace(&request)
            && let Ok(session) = runtime.get_session(token_hash, &vhost.host)
        {
            trace.set_route(TraceRoute::Session);
            trace.bind_identity(session.trace_identity());
        }
        let CollectedBody {
            request,
            body,
            _body_budget,
        } = match collect_body(request, &runtime, 1, true).await {
            Ok(result) => result,
            Err(CollectBodyError::Limit) => return service_unavailable(),
            Err(CollectBodyError::Invalid(request)) => {
                return serve_decoy(request, vhost, true, &runtime).await;
            }
        };
        if !body.is_empty() || runtime.close_token(token_hash, &vhost.host).is_err() {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
        return carrier_empty(StatusCode::NO_CONTENT);
    }
    if request.method() != Method::POST || !binary_content_type(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(carrier_request) = carrier_request(&request, &vhost.host) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let Some((trace_session_id, profile)) =
        runtime.bootstrap_trace_identity(token_hash, &vhost.host)
    else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Session);
        trace.bind_profile(&profile, trace_session_id);
    }
    let CollectedBody {
        request,
        body,
        _body_budget,
    } = match collect_body(request, &runtime, CREATE_BODY_LIMIT, false).await {
        Ok(result) => result,
        Err(CollectBodyError::Limit) => return service_unavailable(),
        Err(CollectBodyError::Invalid(request)) => {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if let Some(trace) = request_trace(&request) {
        trace.record_frames(
            TraceDirection::Request,
            &body,
            &runtime.active_generation().config().web.limits,
        );
    }
    match runtime.create_session(
        token_hash,
        &vhost.host,
        client_ip,
        &body,
        carrier_request,
    ) {
        Ok(result) => {
            let welcome = frame::encode(FrameType::Welcome, 0, &[]);
            if let Some(trace) = request_trace(&request) {
                trace.register_redaction(result.token.as_bytes());
                trace.record_frames(
                    TraceDirection::Response,
                    &welcome,
                    &runtime.active_generation().config().web.limits,
                );
            }
            let mut response = full_response(StatusCode::OK, welcome);
            carrier_headers(&mut response);
            insert_header(
                &mut response,
                HeaderName::from_static("x-session-token"),
                &result.token,
            );
            response.headers_mut().insert(
                HeaderName::from_static("x-carrier-mode"),
                HeaderValue::from_static(result.carrier.as_str()),
            );
            response.headers_mut().insert(
                HeaderName::from_static("x-down-cursor"),
                HeaderValue::from_static("0"),
            );
            if let Some(attempt) = result.attempt {
                insert_header(
                    &mut response,
                    HeaderName::from_static("x-carrier-attempt"),
                    &attempt.to_string(),
                );
            }
            response
        }
        Err(
            error @ (ManagerError::Limit | ManagerError::Backpressure | ManagerError::Concurrent),
        ) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                Some(trace_session_id),
                &profile,
                TraceLifecycleEvent::SessionRejected,
                None,
                Some(error.as_str()),
            );
            service_unavailable()
        }
        Err(error) => {
            runtime.trace().record_profile_lifecycle(
                client_ip,
                Some(trace_session_id),
                &profile,
                TraceLifecycleEvent::SessionRejected,
                None,
                Some(error.as_str()),
            );
            serve_decoy(request, vhost, true, &runtime).await
        }
    }
}

async fn handle_up(
    request: Request<RequestBody>,
    runtime: Arc<WebProcessRuntime>,
    vhost: Arc<WebRuntimeVhost>,
    token_hash: crate::web::manager::TokenHash,
) -> HttpResponse {
    if request.method() != Method::POST || !binary_content_type(&request) {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    let Some(sequence) = canonical_u64_header(&request, "x-up-seq").filter(|value| *value != 0)
    else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let Ok(session) = runtime.get_session(token_hash, &vhost.host) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    if session.carrier().uses_websocket() {
        return serve_decoy(request, vhost, true, &runtime).await;
    }
    if let Some(trace) = request_trace(&request) {
        trace.set_route(TraceRoute::Uplink);
        trace.bind_identity(session.trace_identity());
    }
    let Some(lane_id) = carrier_lane(&request, session.carrier()) else {
        return serve_decoy(request, vhost, true, &runtime).await;
    };
    let limit = runtime
        .active_generation()
        .config()
        .web
        .limits
        .max_body_bytes;
    let CollectedBody {
        request,
        body,
        _body_budget,
    } = match collect_body(request, &runtime, limit, false).await {
        Ok(result) => result,
        Err(CollectBodyError::Limit) => return service_unavailable(),
        Err(CollectBodyError::Invalid(request)) => {
            return serve_decoy(request, vhost, true, &runtime).await;
        }
    };
    if let Some(trace) = request_trace(&request) {
        trace.record_frames(
            TraceDirection::Request,
            &body,
            &runtime.active_generation().config().web.limits,
        );
    }
    let result = match lane_id {
        Some(lane_id) => session.process_up_lane(lane_id, sequence, &body),
        None => session.process_up(sequence, &body),
    };
    match result {
        Ok(ack) => {
            let mut response = carrier_empty(StatusCode::NO_CONTENT);
            insert_header(
                &mut response,
                HeaderName::from_static("x-up-ack"),
                &ack.to_string(),
            );
            response
        }
        Err(ManagerError::Backpressure | ManagerError::Concurrent | ManagerError::Limit) => {
            service_unavailable()
        }
        Err(_) => serve_decoy(request, vhost, true, &runtime).await,
    }
}

fn strip_query<B>(request: &mut Request<B>) {
    if request.uri().query().is_some()
        && let Ok(uri) = request.uri().path().parse()
    {
        *request.uri_mut() = uri;
    }
}

fn request_trace<B>(request: &Request<B>) -> Option<&Arc<HttpTraceExchange>> {
    request.extensions().get::<Arc<HttpTraceExchange>>()
}

fn set_trace_route<B>(request: &Request<B>, route: TraceRoute) {
    if let Some(trace) = request_trace(request) {
        trace.set_route(route);
    }
}
