use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use socket2::Socket;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use crate::config::{ListenerTransport, ProxyConfig};
use crate::startup::{COMPONENT_LISTENERS_BIND, StartupTracker};
use crate::transport::find_listener_processes;
use crate::transport::socket::{activate_listener_socket, bind_listener_socket};

use super::plan::{ListenerBindSpec, listener_bind_plan};
use crate::maestro::helpers::{print_proxy_links, print_web_proxy_links};

/// Owns sockets bound before process accept loops start.
pub(crate) struct BoundListeners {
    pub(super) listeners: Vec<BoundTcpListener>,
    #[cfg(unix)]
    pub(super) unix_listener: Option<UnixListener>,
}

impl BoundListeners {
    pub(crate) fn is_empty(&self) -> bool {
        let tcp_empty = self.listeners.is_empty();
        #[cfg(unix)]
        {
            tcp_empty && self.unix_listener.is_none()
        }
        #[cfg(not(unix))]
        {
            tcp_empty
        }
    }
}

/// Active socket and immutable connection policy for one endpoint.
pub(super) struct BoundTcpListener {
    pub(super) listener: Arc<TcpListener>,
    pub(super) spec: ListenerBindSpec,
}

/// Socket bound for a candidate transition but not yet listening.
pub(super) struct PreparedTcpListener {
    socket: Socket,
    spec: ListenerBindSpec,
}

fn mss_segment_multiplier(client_mss: u16) -> u16 {
    1460u16.div_ceil(client_mss)
}

fn default_link_port(config: &ProxyConfig) -> u16 {
    config
        .server
        .listeners
        .iter()
        .find(|listener| listener.transport == ListenerTransport::Mtproxy)
        .and_then(|listener| listener.port)
        .unwrap_or(config.server.port)
}

fn log_bind_error(addr: SocketAddr, reuse_allow: bool, error_value: &std::io::Error) {
    if error_value.kind() == std::io::ErrorKind::AddrInUse {
        let owners = find_listener_processes(addr);
        if owners.is_empty() {
            error!(%addr, "Failed to bind: address already in use (owner process unresolved)");
        } else {
            for owner in owners {
                error!(
                    %addr,
                    pid = owner.pid,
                    process = %owner.process,
                    "Failed to bind: address already in use"
                );
            }
        }
        if !reuse_allow {
            error!(
                %addr,
                "reuse_allow=false; set [[server.listeners]].reuse_allow=true to allow multi-instance listening"
            );
        }
    } else {
        error!(%addr, error = %error_value, "Failed to bind listener");
    }
}

pub(super) fn prepare_listener(spec: ListenerBindSpec) -> std::io::Result<PreparedTcpListener> {
    match bind_listener_socket(spec.addr, &spec.options) {
        Ok(socket) => Ok(PreparedTcpListener { socket, spec }),
        Err(error_value) => {
            log_bind_error(spec.addr, spec.options.reuse_port, &error_value);
            Err(error_value)
        }
    }
}

impl PreparedTcpListener {
    pub(super) fn activate(self) -> std::io::Result<BoundTcpListener> {
        activate_listener_socket(&self.socket, self.spec.options.backlog)?;
        let listener = TcpListener::from_std(self.socket.into())?;
        Ok(BoundTcpListener {
            listener: Arc::new(listener),
            spec: self.spec,
        })
    }
}

fn log_listener_profile(spec: &ListenerBindSpec) {
    info!(addr = %spec.addr, transport = ?spec.transport, "Listening on TCP endpoint");
    if let Some(client_mss) = spec.options.client_mss {
        info!(
            addr = %spec.addr,
            client_mss,
            segment_multiplier = mss_segment_multiplier(client_mss),
            "Client-facing TCP MSS configured"
        );
    }
    if let Some(fragment_size) = spec.tls_response_fragment_size {
        info!(
            addr = %spec.addr,
            fragment_size,
            bulk_mss = spec.options.client_mss,
            "Initial FakeTLS response best-effort chunking configured"
        );
    }
}

fn print_configured_links(
    config: &ProxyConfig,
    plan: &std::collections::BTreeMap<SocketAddr, ListenerBindSpec>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) {
    print_web_proxy_links(config);
    for listener in &config.server.listeners {
        if listener.transport != ListenerTransport::Mtproxy {
            continue;
        }
        let port = listener.port.unwrap_or(config.server.port);
        let addr = SocketAddr::new(listener.ip, port);
        if !plan.contains_key(&addr) || config.general.links.public_host.is_some() {
            continue;
        }
        let public_host = if let Some(announce) = &listener.announce {
            announce.clone()
        } else if listener.ip.is_unspecified() {
            if listener.ip.is_ipv4() {
                detected_ip_v4
            } else {
                detected_ip_v6
            }
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| listener.ip.to_string())
        } else {
            listener.ip.to_string()
        };
        if !config.general.links.show.is_empty() {
            let link_port = config.general.links.public_port.unwrap_or(port);
            print_proxy_links(&public_host, link_port, config);
        }
    }

    if config.general.links.show.is_empty()
        || config.general.links.public_host.is_none()
        || !plan
            .values()
            .any(|spec| spec.transport == ListenerTransport::Mtproxy)
    {
        return;
    }
    let host = config
        .general
        .links
        .public_host
        .as_deref()
        .unwrap_or_default();
    let port = config
        .general
        .links
        .public_port
        .unwrap_or_else(|| default_link_port(config));
    print_proxy_links(host, port, config);
}

/// Binds every eligible configured listener or fails without a partial inventory.
pub(crate) async fn bind_listeners(
    config: &Arc<ProxyConfig>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    startup_tracker: &Arc<StartupTracker>,
) -> Result<BoundListeners, Box<dyn Error>> {
    startup_tracker
        .start_component(
            COMPONENT_LISTENERS_BIND,
            Some("bind TCP/Unix listeners".to_string()),
        )
        .await;
    let plan = listener_bind_plan(config).map_err(std::io::Error::other)?;
    let mut prepared = Vec::with_capacity(plan.len());
    for spec in plan.values().cloned() {
        prepared.push(prepare_listener(spec)?);
    }
    let mut listeners = Vec::with_capacity(prepared.len());
    for candidate in prepared {
        let bound = candidate.activate()?;
        log_listener_profile(&bound.spec);
        listeners.push(bound);
    }
    print_configured_links(config, &plan, detected_ip_v4, detected_ip_v6);

    #[cfg(unix)]
    let mut unix_listener_out = None;
    #[cfg(unix)]
    if let Some(unix_path) = &config.server.listen_unix_sock {
        let _ = tokio::fs::remove_file(unix_path).await;
        let unix_listener = UnixListener::bind(unix_path)?;
        if let Some(perm_str) = &config.server.listen_unix_sock_perm {
            match u32::from_str_radix(perm_str.trim_start_matches('0'), 8) {
                Ok(mode) => {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = std::fs::Permissions::from_mode(mode);
                    if let Err(error_value) = std::fs::set_permissions(unix_path, permissions) {
                        error!(
                            path = %unix_path,
                            permissions = %perm_str,
                            error = %error_value,
                            "Failed to set Unix socket permissions"
                        );
                    } else {
                        info!(path = %unix_path, permissions = %perm_str, "Listening on Unix socket");
                    }
                }
                Err(error_value) => {
                    warn!(
                        path = %unix_path,
                        permissions = %perm_str,
                        error = %error_value,
                        "Invalid Unix socket permissions; keeping umask-derived mode"
                    );
                }
            }
        } else {
            info!(path = %unix_path, "Listening on Unix socket");
        }
        unix_listener_out = Some(unix_listener);
    }

    #[cfg(unix)]
    let has_unix_listener = unix_listener_out.is_some();
    #[cfg(not(unix))]
    let has_unix_listener = false;
    startup_tracker
        .complete_component(
            COMPONENT_LISTENERS_BIND,
            Some(format!(
                "listeners configured tcp={} unix={}",
                listeners.len(),
                has_unix_listener
            )),
        )
        .await;

    Ok(BoundListeners {
        listeners,
        #[cfg(unix)]
        unix_listener: unix_listener_out,
    })
}
