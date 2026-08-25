use super::*;

const WEB_CONFIG: &str = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
carrier = "https-lanes"

[[web.vhosts]]
host = "Proxy.Example.COM"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
max_sessions = 4
max_streams = 64
max_streams_per_session = 16
"#;

#[test]
fn web_config_builds_canonical_runtime_snapshot() {
    let config = load_config_from_temp_toml(WEB_CONFIG);
    let runtime = config.web.runtime.expect("WEB runtime snapshot");
    let vhost = runtime
        .vhosts
        .get("proxy.example.com")
        .expect("canonical WEB vhost");
    assert_eq!(vhost.profiles.len(), 1);
    assert_eq!(vhost.profiles[0].user, "alice");
    assert_eq!(vhost.profiles[0].secret_mode, WebSecretMode::Dd);
    assert_eq!(vhost.profiles[0].carrier, WebCarrier::HttpsLanes);
    assert_eq!(vhost.profiles[0].max_sessions, 4);
    assert_eq!(vhost.profiles[0].max_streams, 64);
    assert_eq!(vhost.profiles[0].max_streams_per_session, 16);
    assert_eq!(vhost.profiles[0].key_fingerprint.len(), 16);
    assert_ne!(vhost.profiles[0].key_fingerprint, "0001020304050607");
}

#[test]
fn web_debug_table_uses_debug_name_and_bounded_defaults() {
    let configured = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\nbody_capture = \"prefix\"\nbody_prefix_bytes = 2048\ndefault_window_secs = 180\nmax_window_secs = 900\n\n[[web.vhosts]]",
    );
    let config = load_config_from_temp_toml(&configured);
    assert!(config.web.debug.enabled);
    assert_eq!(config.web.debug.body_capture, WebDebugBodyCapture::Prefix);
    assert_eq!(config.web.debug.body_prefix_bytes, 2048);
    assert_eq!(config.web.debug.default_window_secs, 180);
    assert_eq!(config.web.debug.max_window_secs, 900);

    let old_name = format!("[general]\nconfig_strict = true\n{}", WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.trace]\nenabled = true\n\n[[web.vhosts]]",
    ));
    let error = load_config_error_from_temp_toml(&old_name);
    assert!(error.contains("web.trace"));
}

#[test]
fn web_debug_prefix_and_window_validation_fail_closed() {
    let oversized_prefix = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\nbody_prefix_bytes = 2097153\n\n[[web.vhosts]]",
    );
    let error = load_config_error_from_temp_toml(&oversized_prefix);
    assert!(error.contains("web.debug.body_prefix_bytes"));

    let reversed_window = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\ndefault_window_secs = 181\nmax_window_secs = 180\n\n[[web.vhosts]]",
    );
    let error = load_config_error_from_temp_toml(&reversed_window);
    assert!(error.contains("web.debug windows"));

    let undersized_store = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\ndebug_bytes_global = 4095",
    );
    let error = load_config_error_from_temp_toml(&undersized_store);
    assert!(error.contains("debug_bytes_global must be at least 4096"));
}

#[test]
fn https_lanes_requires_separate_poll_and_control_handler_capacity() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\nmax_http_handlers = 1\nmax_body_readers = 1",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("web.carrier=https-lanes requires"));
}

#[test]
fn web_listener_requires_an_explicit_trusted_proxy() {
    let invalid = WEB_CONFIG.replace(
        "web_trusted_proxy_cidrs = [\"127.0.0.1/32\"]",
        "web_trusted_proxy_cidrs = []",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("web_trusted_proxy_cidrs must be non-empty"));
}

#[test]
fn web_queue_limits_preserve_control_and_uplink_progress() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\ncontrol_bytes_per_session = 1",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("control reserves must cover bounded control frames"));
}

#[test]
fn web_semaphore_limits_are_rejected_before_runtime_construction() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        &format!(
            "carrier = \"https-lanes\"\n\n[web.limits]\nmax_http_connections = {}",
            tokio::sync::Semaphore::MAX_PERMITS + 1,
        ),
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("exceeds Tokio semaphore capacity"));
}

#[test]
fn web_ipv6_decoy_uses_a_valid_http_authority() {
    let ipv6 = WEB_CONFIG.replace("http://127.0.0.1:18081", "http://[::1]:18081");
    let config = load_config_from_temp_toml(&ipv6);
    let runtime = config.web.runtime.expect("WEB runtime snapshot");
    let vhost = runtime.vhosts.get("proxy.example.com").unwrap();
    let WebRuntimeDecoy::HttpUpstream { authority, .. } = &vhost.decoy else {
        panic!("expected HTTP decoy");
    };
    assert_eq!(authority, "[::1]:18081");
}
