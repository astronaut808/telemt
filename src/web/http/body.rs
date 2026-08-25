use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use hyper::body::{Body as _, Incoming};

use crate::web::manager::WebProcessRuntime;

/// Collected carrier request retaining its process-wide body reservation.
pub(super) struct CollectedBody {
    /// Request head reconstructed without the consumed network body.
    pub(super) request: Request<Empty<Bytes>>,
    /// Fully collected bounded carrier payload.
    pub(super) body: Bytes,
    /// Byte-budget reservation held through request processing.
    pub(super) _body_budget: tokio::sync::OwnedSemaphorePermit,
}

// Keep rejected requests inline to avoid attacker-controlled allocations on invalid bodies.
#[allow(clippy::large_enum_variant)]
/// Body collection failure with sanitized request context when decoy routing is safe.
pub(super) enum CollectBodyError {
    /// The body shape, size, or deadline failed after retaining the request head.
    Invalid(Request<Empty<Bytes>>),
    /// Process-wide body reader or byte capacity is temporarily exhausted.
    Limit,
}

/// Collects one bounded carrier body under reader, byte, and deadline ownership.
pub(super) async fn collect_body(
    request: Request<Incoming>,
    runtime: &WebProcessRuntime,
    limit: usize,
    allow_empty: bool,
) -> Result<CollectedBody, CollectBodyError> {
    let exceeds_limit = request.body().size_hint().lower() > limit as u64
        || request
            .body()
            .size_hint()
            .upper()
            .is_some_and(|upper| upper > limit as u64);
    let (parts, body) = request.into_parts();
    if exceeds_limit {
        return Err(CollectBodyError::Invalid(Request::from_parts(
            parts,
            Empty::new(),
        )));
    }
    let Some((reader_budget, body_budget)) = runtime.try_body_budget(limit) else {
        return Err(CollectBodyError::Limit);
    };
    let body_timeout =
        Duration::from_secs(runtime.active_generation().config().web.timeouts.body_secs);
    let body = match tokio::time::timeout(body_timeout, Limited::new(body, limit).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            return Err(CollectBodyError::Invalid(Request::from_parts(
                parts,
                Empty::new(),
            )));
        }
    };
    drop(reader_budget);
    let request = Request::from_parts(parts, Empty::new());
    if !allow_empty && body.is_empty() {
        return Err(CollectBodyError::Invalid(request));
    }
    Ok(CollectedBody {
        request,
        body,
        _body_budget: body_budget,
    })
}
