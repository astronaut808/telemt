use super::*;

/// Validates WEB request, learning, and lifecycle timeouts.
pub(super) fn validate(timeouts: &WebTimeoutsConfig) -> Result<()> {
    let values = [
        ("header_secs", timeouts.header_secs),
        ("body_secs", timeouts.body_secs),
        ("stream_handshake_secs", timeouts.stream_handshake_secs),
        ("long_poll_secs", timeouts.long_poll_secs),
        ("websocket_write_secs", timeouts.websocket_write_secs),
        (
            "websocket_backpressure_secs",
            timeouts.websocket_backpressure_secs,
        ),
        ("websocket_eviction_secs", timeouts.websocket_eviction_secs),
        ("bootstrap_lifetime_secs", timeouts.bootstrap_lifetime_secs),
        ("reconnect_grace_secs", timeouts.reconnect_grace_secs),
        ("http_idle_secs", timeouts.http_idle_secs),
        ("shutdown_secs", timeouts.shutdown_secs),
        ("decoy_header_secs", timeouts.decoy_header_secs),
    ];
    if let Some((field, _)) = values
        .into_iter()
        .find(|(_, value)| !(1..=3600).contains(value))
    {
        return config_error(&format!("web.timeouts.{field} must be within [1, 3600]"));
    }
    if timeouts.carrier_learning_secs == 0 {
        return config_error("web.timeouts.carrier_learning_secs must be > 0");
    }
    let request_deadline = timeouts
        .header_secs
        .max(timeouts.body_secs)
        .max(timeouts.long_poll_secs)
        .max(timeouts.decoy_header_secs);
    if request_deadline >= timeouts.http_idle_secs {
        return config_error("web.timeouts request deadlines must be lower than http_idle_secs");
    }
    Ok(())
}
