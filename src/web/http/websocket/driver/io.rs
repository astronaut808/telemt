use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_util::sync::CancellationToken;

use super::CarrierSocket;
use crate::web::manager::{ManagerError, WebProcessRuntime, WebSocketBudgetLease};
use crate::web::session::{WebSession, WebSocketLaneReservation};
use crate::web::trace::{TraceDirection, TraceWebSocketContext};

pub(super) async fn read_message(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    owner: crate::web::manager::ProfileKey,
    cancellation: &CancellationToken,
    retained_budget: &mut Option<WebSocketBudgetLease>,
) -> Result<(Message, Option<WebSocketBudgetLease>), ()> {
    tokio::select! {
        _ = cancellation.cancelled() => return Err(()),
        ready = socket.get_ref().readable() => ready.map_err(|_| ())?,
    }
    if retained_budget.is_none() {
        let maximum = runtime
            .active_generation()
            .config()
            .web
            .limits
            .carrier_batch_bytes;
        *retained_budget = Some(reserve_data(runtime, owner, maximum, cancellation).await?);
    }
    let message = tokio::select! {
        _ = cancellation.cancelled() => return Err(()),
        message = socket.next() => message.ok_or(())?.map_err(|_| ())?,
    };
    if socket.get_ref().websocket_fragmented_message() {
        return Ok((message, None));
    }
    let mut budget = retained_budget.take().ok_or(())?;
    budget.shrink_to(message.len());
    Ok((message, Some(budget)))
}

pub(super) async fn reserve_data(
    runtime: &Arc<WebProcessRuntime>,
    owner: crate::web::manager::ProfileKey,
    bytes: usize,
    cancellation: &CancellationToken,
) -> Result<WebSocketBudgetLease, ()> {
    let timeout = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_backpressure_secs,
    );
    tokio::time::timeout(timeout, async {
        loop {
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            if let Some(budget) = runtime.try_websocket_data_budget(owner, bytes.max(1)) {
                return Ok(budget);
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    .map_err(|_| ())?
}

pub(super) async fn process_multiplex(
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    sequence: u64,
    body: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), ()> {
    retry_backpressure(runtime, cancellation, || {
        session.process_up(sequence, body).map(|_| ())
    })
    .await
}

pub(super) async fn process_lane(
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    reservation: &mut WebSocketLaneReservation,
    sequence: u64,
    body: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), ()> {
    let timeout = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_backpressure_secs,
    );
    tokio::time::timeout(timeout, async {
        loop {
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            match session.process_websocket_lane(reservation, sequence, body) {
                Ok(()) => return Ok(()),
                Err(ManagerError::Backpressure) => {}
                Err(_) => return Err(()),
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    .map_err(|_| ())?
}

async fn retry_backpressure<F>(
    runtime: &Arc<WebProcessRuntime>,
    cancellation: &CancellationToken,
    mut operation: F,
) -> Result<(), ()>
where
    F: FnMut() -> Result<(), ManagerError>,
{
    let timeout = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_backpressure_secs,
    );
    tokio::time::timeout(timeout, async {
        loop {
            let notify = runtime.budget_notify();
            let notified = notify.notified();
            match operation() {
                Ok(()) => return Ok(()),
                Err(ManagerError::Backpressure) => {}
                Err(_) => return Err(()),
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Err(()),
                _ = notified => {}
            }
        }
    })
    .await
    .map_err(|_| ())?
}

pub(super) async fn send(
    socket: &mut CarrierSocket,
    runtime: &WebProcessRuntime,
    message: Message,
) -> Result<(), ()> {
    let timeout = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_write_secs,
    );
    tokio::time::timeout(timeout, socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

pub(super) async fn flush(
    socket: &mut CarrierSocket,
    runtime: &WebProcessRuntime,
) -> Result<(), ()> {
    let timeout = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_write_secs,
    );
    tokio::time::timeout(timeout, socket.flush())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

pub(super) fn record_message(
    runtime: &WebProcessRuntime,
    trace: Option<&TraceWebSocketContext>,
    direction: TraceDirection,
    message_type: &'static str,
    payload: &[u8],
    started: Instant,
) {
    let Some(trace) = trace else {
        return;
    };
    runtime.trace().record_websocket_message(
        trace,
        direction,
        message_type,
        payload,
        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
    );
}
