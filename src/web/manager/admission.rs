use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::state::{allocate_stream_port, allow_rate, decrement_map, release_stream_port};
use super::{ProfileKey, WebProcessRuntime};

impl WebProcessRuntime {
    /// Reserves one process-wide and per-profile live logical-stream slot.
    pub(crate) fn try_acquire_stream(
        &self,
        profile_key: ProfileKey,
        max_streams: usize,
        client_ip: IpAddr,
        public_addr: SocketAddr,
    ) -> Option<u16> {
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.closed
            || state.streams_live >= self.limits.max_streams_global
            || state
                .streams_per_profile
                .get(&profile_key)
                .copied()
                .unwrap_or(0)
                >= max_streams
            || !allow_rate(
                &mut state.stream_rate,
                now,
                self.limits.new_streams_per_minute,
                self.limits.new_streams_burst,
            )
        {
            self.streams_rejected.fetch_add(1, Ordering::Relaxed);
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let Some(peer_port) = allocate_stream_port(&mut state, client_ip, public_addr) else {
            self.streams_rejected.fetch_add(1, Ordering::Relaxed);
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        state.streams_live += 1;
        *state.streams_per_profile.entry(profile_key).or_insert(0) += 1;
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        Some(peer_port)
    }

    /// Releases one live logical-stream slot after its relay task exits.
    pub(crate) fn release_stream(
        &self,
        profile_key: ProfileKey,
        client_ip: IpAddr,
        public_addr: SocketAddr,
        peer_port: u16,
    ) {
        let mut state = self.state.lock();
        if !release_stream_port(&mut state, client_ip, public_addr, peer_port) {
            return;
        }
        state.streams_live = state.streams_live.saturating_sub(1);
        decrement_map(&mut state.streams_per_profile, &profile_key);
    }

    /// Records a logical stream rejected outside manager quota acquisition.
    pub(crate) fn record_stream_rejected(&self) {
        self.streams_rejected.fetch_add(1, Ordering::Relaxed);
        self.record_limit_hit();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use super::*;
    use crate::config::ProxyConfig;
    use crate::maestro::generation::test_runtime_generation;
    use crate::web::session::QUEUE_ITEM_COST;

    #[tokio::test]
    async fn global_downlink_budget_preserves_one_maximum_uplink_batch() {
        let generation = test_runtime_generation(1, ProxyConfig::default());
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation)));
        let control_items = super::super::state::control_item_reserve(&runtime.limits);
        let data_bytes = runtime
            .limits
            .pending_bytes_global
            .saturating_sub(runtime.limits.control_bytes_global);
        let data_items = runtime
            .limits
            .pending_items_global
            .saturating_sub(control_items);
        let uplink_bytes = runtime
            .limits
            .max_body_bytes
            .saturating_add(runtime.limits.max_frames_per_body * QUEUE_ITEM_COST);
        let downlink_bytes = data_bytes - uplink_bytes;
        let downlink_items = data_items - runtime.limits.max_frames_per_body;

        assert!(runtime.try_reserve_pending(downlink_bytes, downlink_items, false, true,));
        assert!(runtime.try_reserve_pending(
            uplink_bytes,
            runtime.limits.max_frames_per_body,
            false,
            false,
        ));
        assert!(!runtime.try_reserve_pending(1, 1, false, true));

        runtime.release_pending(downlink_bytes, downlink_items, false);
        runtime.release_pending(uplink_bytes, runtime.limits.max_frames_per_body, false);
        runtime.shutdown().await;
    }
}
