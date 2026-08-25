use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::*;

const WEB_CAPABILITY_CONTEXT: &[u8] = b"tdesktop-web-proxy-bridge-v1\n";
const MAX_WEB_STATIC_DEPTH: usize = 64;

/// Builds the immutable WEB routing and decoy snapshot for one generation.
pub(super) fn rebuild(config: &mut ProxyConfig) -> Result<()> {
    let auth = config.runtime_user_auth().ok_or_else(|| {
        ProxyError::Config("WEB runtime requires the user authentication snapshot".to_string())
    })?;
    let mut runtime_vhosts = BTreeMap::new();
    let mut runtime_profiles = Vec::new();
    let mut static_files = 0usize;
    let mut static_bytes = 0usize;

    for vhost in &config.web.vhosts {
        let decoy = build_decoy(
            vhost,
            &config.web.limits,
            &mut static_files,
            &mut static_bytes,
        )?;
        let mut profiles = Vec::with_capacity(vhost.profiles.len());
        let mut capabilities = HashSet::with_capacity(vhost.profiles.len());
        for profile in &vhost.profiles {
            let user_id = auth.user_id_by_name(&profile.user).ok_or_else(|| {
                ProxyError::Config(format!(
                    "WEB profile references unknown access user `{}`",
                    profile.user
                ))
            })?;
            let auth_entry = auth.entry_by_id(user_id).ok_or_else(|| {
                ProxyError::Config("WEB profile user snapshot is inconsistent".to_string())
            })?;
            let (client_secret, client_secret_len) =
                client_secret(auth_entry.secret, profile.secret_mode);
            let capability =
                derive_web_capability(&client_secret[..client_secret_len], vhost.host.as_bytes())?;
            if !capabilities.insert(capability) {
                return Err(ProxyError::Config(format!(
                    "WEB vhost `{}` contains profiles with the same client capability",
                    vhost.host
                )));
            }
            let runtime_profile = Arc::new(WebRuntimeProfile {
                host: vhost.host.clone(),
                public_addr: vhost.public_addr,
                user: profile.user.clone(),
                secret_mode: profile.secret_mode,
                carrier: config.web.carrier,
                capability,
                max_sessions: profile
                    .max_sessions
                    .unwrap_or(config.web.limits.max_sessions_global),
                max_streams: profile
                    .max_streams
                    .unwrap_or(config.web.limits.max_streams_global),
                max_streams_per_session: profile
                    .max_streams_per_session
                    .unwrap_or(config.web.limits.max_streams_per_session),
            });
            profiles.push(Arc::clone(&runtime_profile));
            runtime_profiles.push(runtime_profile);
        }
        runtime_vhosts.insert(
            vhost.host.clone(),
            Arc::new(WebRuntimeVhost {
                host: vhost.host.clone(),
                decoy,
                decoy_header_secs: config.web.timeouts.decoy_header_secs,
                profiles,
            }),
        );
    }

    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts: runtime_vhosts,
        profiles: runtime_profiles,
    }));
    Ok(())
}

/// Derives the Telegram Desktop WEB capability for one exact secret and host.
pub(crate) fn derive_web_capability(secret: &[u8], host: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| ProxyError::Config("WEB capability secret must not be empty".to_string()))?;
    mac.update(WEB_CAPABILITY_CONTEXT);
    mac.update(host);
    Ok(mac.finalize().into_bytes().into())
}

fn client_secret(secret: [u8; 16], mode: WebSecretMode) -> ([u8; 17], usize) {
    let mut client_secret = [0u8; 17];
    match mode {
        WebSecretMode::Plain => {
            client_secret[..16].copy_from_slice(&secret);
            (client_secret, 16)
        }
        WebSecretMode::Dd => {
            client_secret[0] = 0xdd;
            client_secret[1..].copy_from_slice(&secret);
            (client_secret, 17)
        }
    }
}

fn build_decoy(
    vhost: &WebVhostConfig,
    limits: &WebLimitsConfig,
    static_files: &mut usize,
    static_bytes: &mut usize,
) -> Result<WebRuntimeDecoy> {
    match &vhost.decoy {
        WebDecoyConfig::HttpUpstream { upstream } => {
            let parsed = url::Url::parse(upstream).map_err(|error| {
                ProxyError::Config(format!(
                    "WEB decoy upstream for `{}` is invalid: {error}",
                    vhost.host
                ))
            })?;
            let ip = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => std::net::IpAddr::V4(ip),
                Some(url::Host::Ipv6(ip)) => std::net::IpAddr::V6(ip),
                _ => {
                    return Err(ProxyError::Config(
                        "WEB decoy host must be an IP literal".to_string(),
                    ));
                }
            };
            let host = ip.to_string();
            let port = parsed.port_or_known_default().ok_or_else(|| {
                ProxyError::Config("WEB decoy port cannot be resolved".to_string())
            })?;
            let authority = match (ip, parsed.port()) {
                (std::net::IpAddr::V6(_), Some(_)) => format!("[{host}]:{port}"),
                (std::net::IpAddr::V6(_), None) => format!("[{host}]"),
                (std::net::IpAddr::V4(_), Some(_)) => format!("{host}:{port}"),
                (std::net::IpAddr::V4(_), None) => host.clone(),
            };
            Ok(WebRuntimeDecoy::HttpUpstream {
                addr: SocketAddr::new(ip, port),
                authority,
            })
        }
        WebDecoyConfig::StaticDirectory { directory, index } => {
            let site = load_static_site(directory, index, limits, static_files, static_bytes)?;
            Ok(WebRuntimeDecoy::StaticDirectory(Arc::new(site)))
        }
    }
}

fn load_static_site(
    root: &Path,
    index: &str,
    limits: &WebLimitsConfig,
    total_files: &mut usize,
    total_bytes: &mut usize,
) -> Result<WebStaticSite> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        ProxyError::Config(format!(
            "failed to inspect WEB static directory `{}`: {error}",
            root.display()
        ))
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ProxyError::Config(format!(
            "WEB static directory `{}` must be a real directory, not a symlink",
            root.display()
        )));
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        ProxyError::Config(format!(
            "failed to canonicalize WEB static directory `{}`: {error}",
            root.display()
        ))
    })?;
    let mut assets = BTreeMap::new();
    load_static_directory(
        &canonical_root,
        &canonical_root,
        &mut assets,
        total_files,
        total_bytes,
        limits,
        0,
    )?;
    if !assets.contains_key(&format!("/{index}")) {
        return Err(ProxyError::Config(format!(
            "WEB static directory `{}` does not contain index `{index}`",
            root.display()
        )));
    }
    Ok(WebStaticSite {
        assets,
        index: index.to_string(),
    })
}

fn load_static_directory(
    root: &Path,
    directory: &Path,
    assets: &mut BTreeMap<String, WebStaticAsset>,
    total_files: &mut usize,
    total_bytes: &mut usize,
    limits: &WebLimitsConfig,
    depth: usize,
) -> Result<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ProxyError::Config(format!(
            "failed to read WEB static directory `{}`: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ProxyError::Config(format!("failed to read WEB static entry: {error}"))
        })?;
        if *total_files >= limits.max_static_files {
            return Err(ProxyError::Config(
                "WEB static entries exceed process-wide web.limits.max_static_files".to_string(),
            ));
        }
        *total_files += 1;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ProxyError::Config(format!(
                "failed to inspect WEB static entry `{}`: {error}",
                path.display()
            ))
        })?;
        if file_type.is_symlink() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` must not be a symlink",
                path.display()
            )));
        }
        if file_type.is_dir() {
            if depth >= MAX_WEB_STATIC_DEPTH {
                return Err(ProxyError::Config(format!(
                    "WEB static directory `{}` exceeds the maximum nesting depth",
                    path.display()
                )));
            }
            load_static_directory(
                root,
                &path,
                assets,
                total_files,
                total_bytes,
                limits,
                depth + 1,
            )?;
            continue;
        }
        if !file_type.is_file() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` must be a regular file",
                path.display()
            )));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options.open(&path).map_err(|error| {
            ProxyError::Config(format!(
                "failed to open WEB static file `{}`: {error}",
                path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            ProxyError::Config(format!(
                "failed to inspect WEB static file `{}`: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` changed before it was opened",
                path.display()
            )));
        }
        let file_len = usize::try_from(metadata.len()).map_err(|_| {
            ProxyError::Config(format!("WEB static file `{}` is too large", path.display()))
        })?;
        if file_len > limits.max_static_file_bytes {
            return Err(ProxyError::Config(format!(
                "WEB static file `{}` exceeds web.limits.max_static_file_bytes",
                path.display()
            )));
        }
        *total_bytes = total_bytes.checked_add(file_len).ok_or_else(|| {
            ProxyError::Config("WEB static snapshot byte count overflowed usize".to_string())
        })?;
        if *total_bytes > limits.max_static_bytes {
            return Err(ProxyError::Config(
                "WEB static snapshots exceed process-wide web.limits.max_static_bytes".to_string(),
            ));
        }
        let relative = path.strip_prefix(root).map_err(|_| {
            ProxyError::Config("WEB static path escaped its configured root".to_string())
        })?;
        let route = static_route(relative)?;
        let mut body = Vec::with_capacity(file_len);
        file.take(limits.max_static_file_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| {
                ProxyError::Config(format!(
                    "failed to read WEB static file `{}`: {error}",
                    path.display()
                ))
            })?;
        if body.len() != file_len {
            return Err(ProxyError::Config(format!(
                "WEB static file `{}` changed while its snapshot was built",
                path.display()
            )));
        }
        let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body)));
        assets.insert(
            route,
            WebStaticAsset {
                body: Bytes::from(body),
                content_type: static_content_type(&path),
                etag,
            },
        );
    }
    Ok(())
}

fn static_route(relative: &Path) -> Result<String> {
    let mut route = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ProxyError::Config(
                "WEB static path contains an unsafe component".to_string(),
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            ProxyError::Config("WEB static file names must be valid UTF-8".to_string())
        })?;
        route.push('/');
        route.push_str(component);
    }
    Ok(route)
}

fn static_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn capability_matches_reference_vectors() {
        let secret = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = derive_web_capability(&secret, b"proxy.example.com").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain),
            "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
        );
        let mut dd_secret = vec![0xdd];
        dd_secret.extend_from_slice(&secret);
        let dd = derive_web_capability(&dd_secret, b"proxy.example.com").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dd),
            "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"
        );
    }
}
