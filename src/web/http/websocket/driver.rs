use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_util::sync::CancellationToken;

use super::ConnectionIo;
use crate::web::manager::{
    ManagerError, WebProcessRuntime, WebSocketBudgetLease, WebSocketConnection,
};
use crate::web::session::{WebSession, WebSocketLaneReservation};
use crate::web::trace::{TraceDirection, TraceWebSocketContext};

const READ_BUFFER_BYTES: usize = 64 * 1024;
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

pub(super) async fn run_upgraded(
    on_upgrade: hyper::upgrade::OnUpgrade,
    runtime: Arc<WebProcessRuntime>,
    session: Arc<WebSession>,
    connection: WebSocketConnection,
    mut lane_reservation: Option<WebSocketLaneReservation>,
    trace: Option<TraceWebSocketContext>,
) {
    let Ok(upgraded) = on_upgrade.await else {
        return;
    };
    let Ok(parts) = upgraded.downcast::<TokioIo<ConnectionIo>>() else {
        return;
    };
    let mut io = parts.io.into_inner();
    io.enable_websocket(parts.read_buf);
    let limits = runtime.active_generation().config().web.limits.clone();
    let config = WebSocketConfig::default()
        .read_buffer_size(READ_BUFFER_BYTES)
        .write_buffer_size(WRITE_BUFFER_BYTES)
        .max_write_buffer_size(
            WRITE_BUFFER_BYTES
                .saturating_add(limits.carrier_batch_bytes)
                .saturating_add(1024),
        )
        .max_message_size(Some(limits.carrier_batch_bytes))
        .max_frame_size(Some(limits.carrier_batch_bytes));
    let mut socket = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
    connection.mark_opened();
    let cancellation = connection.cancellation();
    if let Some(reservation) = lane_reservation.as_mut() {
        let _ = run_lane(
            &mut socket,
            &runtime,
            &session,
            &connection,
            reservation,
            cancellation.clone(),
            trace.as_ref(),
        )
        .await;
    } else {
        let _ = run_multiplex(
            &mut socket,
            &runtime,
            &session,
            &connection,
            cancellation.clone(),
            trace.as_ref(),
        )
        .await;
    }
    let eviction = Duration::from_secs(
        runtime
            .active_generation()
            .config()
            .web
            .timeouts
            .websocket_eviction_secs,
    );
    let _ = tokio::time::timeout(eviction, socket.close(None)).await;
    if let Some(reservation) = lane_reservation {
        session.close_websocket_lane(reservation.lane_id());
        drop(reservation);
    } else {
        session.close();
    }
}

type CarrierSocket = WebSocketStream<ConnectionIo>;

async fn run_multiplex(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    connection: &WebSocketConnection,
    cancellation: CancellationToken,
    trace: Option<&TraceWebSocketContext>,
) -> Result<(), ()> {
    let mut sequence = 1u64;
    let mut cursor = 0u64;
    // The lease survives cancelled select branches and control frames interleaved
    // inside one fragmented data message.
    let mut read_budget = None;
    let liveness_interval = connection.liveness_interval();
    let mut next_ping = Instant::now() + liveness_interval;
    loop {
        let down = session.poll_down(cursor);
        tokio::pin!(down);
        let event = tokio::select! {
            _ = cancellation.cancelled() => return Err(()),
            _ = tokio::time::sleep_until(next_ping.into()) => DriverEvent::Liveness,
            incoming = read_message(
                socket,
                runtime,
                session.profile_key(),
                &cancellation,
                &mut read_budget,
            ) => {
                DriverEvent::Incoming(incoming?)
            }
            down = &mut down => DriverEvent::Down(down.map_err(|_| ())?),
        };
        match event {
            DriverEvent::Incoming((message, _budget)) => match message {
                Message::Binary(body) => {
                    let started = Instant::now();
                    let result =
                        process_multiplex(runtime, session, sequence, &body, &cancellation).await;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "binary",
                        &body,
                        started,
                    );
                    result?;
                    sequence = sequence.checked_add(1).ok_or(())?;
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Pong(payload) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "pong",
                        &payload,
                        Instant::now(),
                    );
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Ping(payload) => {
                    let started = Instant::now();
                    flush(socket, runtime).await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "ping",
                        &payload,
                        started,
                    );
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "pong",
                        &payload,
                        started,
                    );
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Close(_) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "close",
                        &[],
                        Instant::now(),
                    );
                    return Ok(());
                }
                Message::Text(text) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "text",
                        text.as_bytes(),
                        Instant::now(),
                    );
                    return Err(());
                }
                Message::Frame(_) => return Err(()),
            },
            DriverEvent::Down(result) => {
                if result.body.is_empty() {
                    let started = Instant::now();
                    send(socket, runtime, Message::Ping(Bytes::new())).await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "ping",
                        &[],
                        started,
                    );
                    next_ping = Instant::now() + liveness_interval;
                } else {
                    let _budget = reserve_data(
                        runtime,
                        session.profile_key(),
                        result.body.len(),
                        &cancellation,
                    )
                    .await?;
                    let body = result.body;
                    let started = Instant::now();
                    if trace.is_some() {
                        send(socket, runtime, Message::Binary(body.clone())).await?;
                        record_message(
                            runtime,
                            trace,
                            TraceDirection::Response,
                            "binary",
                            &body,
                            started,
                        );
                    } else {
                        send(socket, runtime, Message::Binary(body)).await?;
                    }
                    connection.mark_progress();
                }
                cursor = result.next_cursor;
            }
            DriverEvent::Liveness => {
                let started = Instant::now();
                send(socket, runtime, Message::Ping(Bytes::new())).await?;
                record_message(
                    runtime,
                    trace,
                    TraceDirection::Response,
                    "ping",
                    &[],
                    started,
                );
                next_ping = Instant::now() + liveness_interval;
            }
        }
    }
}

async fn run_lane(
    socket: &mut CarrierSocket,
    runtime: &Arc<WebProcessRuntime>,
    session: &Arc<WebSession>,
    connection: &WebSocketConnection,
    reservation: &mut WebSocketLaneReservation,
    cancellation: CancellationToken,
    trace: Option<&TraceWebSocketContext>,
) -> Result<(), ()> {
    let mut sequence = 1u64;
    let mut cursor = 0u64;
    // Lane reads use the same cancellation-safe fragmented-message ownership.
    let mut read_budget = None;
    let liveness_interval = connection.liveness_interval();
    let mut next_ping = Instant::now() + liveness_interval;
    loop {
        let down = session.poll_down_lane(reservation.lane_id(), cursor);
        tokio::pin!(down);
        let event = tokio::select! {
            _ = cancellation.cancelled() => return Err(()),
            _ = tokio::time::sleep_until(next_ping.into()) => DriverEvent::Liveness,
            incoming = read_message(
                socket,
                runtime,
                session.profile_key(),
                &cancellation,
                &mut read_budget,
            ) => {
                DriverEvent::Incoming(incoming?)
            }
            down = &mut down => DriverEvent::Down(down.map_err(|_| ())?),
        };
        match event {
            DriverEvent::Incoming((message, _budget)) => match message {
                Message::Binary(body) => {
                    let started = Instant::now();
                    let result = process_lane(
                        runtime,
                        session,
                        reservation,
                        sequence,
                        &body,
                        &cancellation,
                    )
                    .await;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "binary",
                        &body,
                        started,
                    );
                    result?;
                    sequence = sequence.checked_add(1).ok_or(())?;
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Pong(payload) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "pong",
                        &payload,
                        Instant::now(),
                    );
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Ping(payload) => {
                    let started = Instant::now();
                    flush(socket, runtime).await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "ping",
                        &payload,
                        started,
                    );
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "pong",
                        &payload,
                        started,
                    );
                    connection.mark_peer_activity();
                    next_ping = Instant::now() + liveness_interval;
                }
                Message::Close(_) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "close",
                        &[],
                        Instant::now(),
                    );
                    return Ok(());
                }
                Message::Text(text) => {
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Request,
                        "text",
                        text.as_bytes(),
                        Instant::now(),
                    );
                    return Err(());
                }
                Message::Frame(_) => return Err(()),
            },
            DriverEvent::Down(result) => {
                if result.lane_closed {
                    return Ok(());
                }
                if result.body.is_empty() {
                    let started = Instant::now();
                    send(socket, runtime, Message::Ping(Bytes::new())).await?;
                    record_message(
                        runtime,
                        trace,
                        TraceDirection::Response,
                        "ping",
                        &[],
                        started,
                    );
                    next_ping = Instant::now() + liveness_interval;
                } else {
                    let _budget = reserve_data(
                        runtime,
                        session.profile_key(),
                        result.body.len(),
                        &cancellation,
                    )
                    .await?;
                    let body = result.body;
                    let started = Instant::now();
                    if trace.is_some() {
                        send(socket, runtime, Message::Binary(body.clone())).await?;
                        record_message(
                            runtime,
                            trace,
                            TraceDirection::Response,
                            "binary",
                            &body,
                            started,
                        );
                    } else {
                        send(socket, runtime, Message::Binary(body)).await?;
                    }
                    connection.mark_progress();
                }
                cursor = result.next_cursor;
            }
            DriverEvent::Liveness => {
                let started = Instant::now();
                send(socket, runtime, Message::Ping(Bytes::new())).await?;
                record_message(
                    runtime,
                    trace,
                    TraceDirection::Response,
                    "ping",
                    &[],
                    started,
                );
                next_ping = Instant::now() + liveness_interval;
            }
        }
    }
}

enum DriverEvent {
    Incoming((Message, Option<WebSocketBudgetLease>)),
    Down(crate::web::session::PollResult),
    Liveness,
}

async fn read_message(
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

async fn reserve_data(
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

async fn process_multiplex(
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

async fn process_lane(
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

async fn send(
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

async fn flush(socket: &mut CarrierSocket, runtime: &WebProcessRuntime) -> Result<(), ()> {
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

fn record_message(
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
