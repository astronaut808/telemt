use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::ip_tracker::UserIpTracker;
use crate::proxy::direct_relay::handle_via_direct_with_shared_and_conntrack;
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::middle_relay::{handle_via_middle_proxy, handle_via_middle_proxy_with_conntrack};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::{ConntrackClosePolicy, ProxySharedState};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

/// Immutable dependency snapshot pinned by one authenticated client stream.
#[derive(Clone)]
pub(crate) struct ClientRuntimeDeps {
    /// Immutable effective configuration pinned for this stream.
    pub(crate) config: Arc<ProxyConfig>,
    /// Process statistics registry.
    pub(crate) stats: Arc<Stats>,
    /// Direct Telegram upstream connector.
    pub(crate) upstream_manager: Arc<UpstreamManager>,
    /// Shared relay buffer pool.
    pub(crate) buffer_pool: Arc<BufferPool>,
    /// Process cryptographic random source.
    pub(crate) rng: Arc<SecureRandom>,
    /// Startup Middle-End pool, when immediately available.
    pub(crate) me_pool: Option<Arc<MePool>>,
    /// Hot-swappable Middle-End pool holder.
    pub(crate) me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
    /// Route-mode controller shared by active generations.
    pub(crate) route_runtime: Arc<RouteRuntimeController>,
    /// Per-user source-IP admission tracker.
    pub(crate) ip_tracker: Arc<UserIpTracker>,
    /// Process-shared admission and relay coordination state.
    pub(crate) shared: Arc<ProxySharedState>,
}

/// Runs admission and relay after a successful MTProxy handshake.
pub(crate) async fn run_authenticated<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    deps: ClientRuntimeDeps,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conntrack_close_policy: ConntrackClosePolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    if !deps.shared.is_user_enabled(&user) {
        warn!(user = %user, "Disabled user rejected");
        return Err(ProxyError::UserDisabled { user });
    }

    let user_reservation = acquire_user_connection_reservation(
        &user,
        &deps.config,
        Arc::clone(&deps.stats),
        peer_addr,
        Arc::clone(&deps.ip_tracker),
    )
    .await
    .map_err(|error| {
        warn!(user = %user, error = %error, "User admission check failed");
        error
    })?;

    let route_snapshot = deps.route_runtime.snapshot();
    let session_id = deps.rng.u64();
    let user_session = deps.shared.register_user_session(&user, session_id);
    let session_cancel = user_session.token();
    let selected_me_pool = if deps.config.general.use_middle_proxy
        && matches!(route_snapshot.mode, RelayRouteMode::Middle)
    {
        if let Some(pool) = &deps.me_pool {
            Some(Arc::clone(pool))
        } else if let Some(pool_runtime) = &deps.me_pool_runtime {
            pool_runtime.read().await.clone()
        } else {
            None
        }
    } else {
        None
    };

    let relay_result = if deps.config.general.use_middle_proxy
        && matches!(route_snapshot.mode, RelayRouteMode::Middle)
    {
        if let Some(pool) = selected_me_pool {
            if conntrack_close_policy == ConntrackClosePolicy::Publish {
                handle_via_middle_proxy(
                    client_reader,
                    client_writer,
                    success,
                    pool,
                    Arc::clone(&deps.stats),
                    Arc::clone(&deps.config),
                    Arc::clone(&deps.buffer_pool),
                    local_addr,
                    Arc::clone(&deps.rng),
                    deps.route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                    session_cancel.clone(),
                    Arc::clone(&deps.shared),
                )
                .await
            } else {
                handle_via_middle_proxy_with_conntrack(
                    client_reader,
                    client_writer,
                    success,
                    pool,
                    Arc::clone(&deps.stats),
                    Arc::clone(&deps.config),
                    Arc::clone(&deps.buffer_pool),
                    local_addr,
                    Arc::clone(&deps.rng),
                    deps.route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                    session_cancel.clone(),
                    Arc::clone(&deps.shared),
                    ConntrackClosePolicy::Suppress,
                )
                .await
            }
        } else {
            warn!("use_middle_proxy=true but MePool not initialized, falling back to direct");
            run_direct(
                client_reader,
                client_writer,
                success,
                &deps,
                route_snapshot,
                session_id,
                local_addr,
                session_cancel.clone(),
                conntrack_close_policy,
            )
            .await
        }
    } else {
        run_direct(
            client_reader,
            client_writer,
            success,
            &deps,
            route_snapshot,
            session_id,
            local_addr,
            session_cancel,
            conntrack_close_policy,
        )
        .await
    };
    user_reservation.release().await;
    relay_result
}

async fn run_direct<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    deps: &ClientRuntimeDeps,
    route_snapshot: crate::proxy::route_mode::RouteCutoverState,
    session_id: u64,
    local_addr: SocketAddr,
    session_cancel: tokio_util::sync::CancellationToken,
    conntrack_close_policy: ConntrackClosePolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_via_direct_with_shared_and_conntrack(
        client_reader,
        client_writer,
        success,
        Arc::clone(&deps.upstream_manager),
        Arc::clone(&deps.stats),
        Arc::clone(&deps.config),
        Arc::clone(&deps.buffer_pool),
        Arc::clone(&deps.rng),
        deps.route_runtime.subscribe(),
        route_snapshot,
        session_id,
        local_addr,
        session_cancel,
        Arc::clone(&deps.shared),
        conntrack_close_policy,
    )
    .await
}

#[must_use = "the reservation owns user and IP admission until release or drop"]
/// Owns one authenticated user's connection and source-IP admission slots.
pub(crate) struct UserConnectionReservation {
    stats: Arc<Stats>,
    ip_tracker: Arc<UserIpTracker>,
    user: String,
    ip: IpAddr,
    tracks_ip: bool,
    active: bool,
}

impl UserConnectionReservation {
    /// Creates an active reservation after both admission counters were acquired.
    pub(crate) fn new(
        stats: Arc<Stats>,
        ip_tracker: Arc<UserIpTracker>,
        user: String,
        ip: IpAddr,
        tracks_ip: bool,
    ) -> Self {
        Self {
            stats,
            ip_tracker,
            user,
            ip,
            tracks_ip,
            active: true,
        }
    }

    /// Releases both admission counters through the asynchronous cleanup path.
    pub(crate) async fn release(mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        if self.tracks_ip {
            self.ip_tracker.remove_ip(&self.user, self.ip).await;
        }
        self.stats.decrement_user_curr_connects(&self.user);
    }
}

impl Drop for UserConnectionReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.stats.increment_session_drop_fallback_total();
        self.stats.decrement_user_curr_connects(&self.user);
        if self.tracks_ip {
            self.ip_tracker.enqueue_cleanup(self.user.clone(), self.ip);
        }
    }
}

/// Applies user quota, connection, and source-IP admission atomically.
pub(crate) async fn acquire_user_connection_reservation(
    user: &str,
    config: &ProxyConfig,
    stats: Arc<Stats>,
    peer_addr: SocketAddr,
    ip_tracker: Arc<UserIpTracker>,
) -> Result<UserConnectionReservation> {
    if let Some(expiration) = config.access.user_expirations.get(user)
        && chrono::Utc::now() > *expiration
    {
        return Err(ProxyError::UserExpired {
            user: user.to_string(),
        });
    }
    if let Some(quota) = config.access.user_data_quota.get(user)
        && stats.get_user_quota_used(user) >= *quota
    {
        return Err(ProxyError::DataQuotaExceeded {
            user: user.to_string(),
        });
    }

    let limit = config
        .access
        .user_max_tcp_conns
        .get(user)
        .copied()
        .filter(|limit| *limit > 0)
        .or((config.access.user_max_tcp_conns_global_each > 0)
            .then_some(config.access.user_max_tcp_conns_global_each))
        .map(|value| value as u64);
    if !stats.try_acquire_user_curr_connects(user, limit) {
        return Err(ProxyError::ConnectionLimitExceeded {
            user: user.to_string(),
        });
    }

    if let Err(reason) = ip_tracker.check_and_add(user, peer_addr.ip()).await {
        stats.decrement_user_curr_connects(user);
        warn!(
            user = %user,
            ip = %peer_addr.ip(),
            reason = %reason,
            "IP limit exceeded"
        );
        return Err(ProxyError::ConnectionLimitExceeded {
            user: user.to_string(),
        });
    }

    Ok(UserConnectionReservation::new(
        stats,
        ip_tracker,
        user.to_string(),
        peer_addr.ip(),
        true,
    ))
}
