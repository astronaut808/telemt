use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use parking_lot::Mutex;

use super::{BoxError, HttpBody};

/// Request lifecycle guard that refreshes HTTP connection activity on completion.
pub(super) struct RequestActivity {
    last_activity: Arc<Mutex<Instant>>,
}

impl RequestActivity {
    /// Starts activity accounting for one HTTP request.
    pub(super) fn begin(last_activity: Arc<Mutex<Instant>>) -> Self {
        *last_activity.lock() = Instant::now();
        Self { last_activity }
    }
}

impl Drop for RequestActivity {
    fn drop(&mut self) {
        *self.last_activity.lock() = Instant::now();
    }
}

/// Response body wrapper that refreshes activity while downstream data progresses.
pub(super) struct ActivityBody {
    inner: HttpBody,
    activity: RequestActivity,
}

impl ActivityBody {
    /// Binds one response body to its request activity guard.
    pub(super) fn new(inner: HttpBody, activity: RequestActivity) -> Self {
        Self { inner, activity }
    }
}

impl Body for ActivityBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(context);
        if result.is_ready() {
            *self.activity.last_activity.lock() = Instant::now();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
