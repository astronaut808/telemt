use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine as _;
use hyper::Request;
use hyper::header;
use ipnetwork::IpNetwork;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{WebClientIpSource, WebRuntimeProfile, WebRuntimeVhost};
use crate::web::manager::TokenHash;

/// Parses one lowercase canonical Host value restricted to the public HTTPS port.
pub(super) fn canonical_request_host<B>(request: &Request<B>) -> Option<&str> {
    let values = request.headers().get_all(header::HOST);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let authority = value.parse::<hyper::http::uri::Authority>().ok()?;
    if authority.port_u16().is_some_and(|port| port != 443) {
        return None;
    }
    let host = value.strip_suffix(":443").unwrap_or(value);
    if authority.host() != host || host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    Some(host)
}

/// Accepts one forwarded client address or the direct address of a trusted peer.
pub(super) fn client_ip<B>(
    request: &Request<B>,
    peer: SocketAddr,
    source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
) -> Option<IpAddr> {
    if !trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(peer.ip()))
    {
        return None;
    }
    let header_name = match source {
        WebClientIpSource::XForwardedFor => "x-forwarded-for",
    };
    let values = request.headers().get_all(header_name);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Some(peer.ip());
    };
    let value = value.to_str().ok()?;
    if values.next().is_some() || value.trim() != value || value.contains(',') {
        return None;
    }
    if value.is_empty() {
        return Some(peer.ip());
    }
    value.parse::<IpAddr>().ok()
}

/// Decodes an exact canonical bridge query without allocating credential strings.
pub(super) fn bridge_candidate(query: Option<&str>) -> ([u8; 32], bool) {
    let mut candidate = [0u8; 32];
    let Some(value) = query.and_then(|query| query.strip_prefix("bridge=")) else {
        return (candidate, false);
    };
    if value.len() != 43 {
        return (candidate, false);
    }
    let mut decoded = [0u8; 32];
    let Ok(decoded_len) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode_slice(value, &mut decoded)
    else {
        return (candidate, false);
    };
    let mut canonical = [0u8; 43];
    let Ok(encoded_len) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_slice(decoded, &mut canonical)
    else {
        return (candidate, false);
    };
    if decoded_len != decoded.len()
        || encoded_len != canonical.len()
        || !bool::from(canonical.ct_eq(value.as_bytes()))
    {
        return (candidate, false);
    }
    candidate = decoded;
    (candidate, true)
}

/// Matches a capability in constant time across every profile of one virtual host.
pub(super) fn match_profile(
    vhost: &WebRuntimeVhost,
    candidate: &[u8; 32],
) -> Option<Arc<WebRuntimeProfile>> {
    let mut matched = None;
    for profile in &vhost.profiles {
        if bool::from(profile.capability.ct_eq(candidate)) {
            matched = Some(Arc::clone(profile));
        }
    }
    matched
}

/// Validates and hashes one canonical bearer credential for map lookup.
pub(super) fn bearer_token_hash<B>(request: &Request<B>) -> Option<TokenHash> {
    let values = request.headers().get_all(header::AUTHORIZATION);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || !value.starts_with("Bearer ") || value.matches(' ').count() != 1 {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?;
    if token.len() != 43 {
        return None;
    }
    let mut decoded = [0u8; 32];
    let decoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(token, &mut decoded)
        .ok()?;
    let mut canonical = [0u8; 43];
    let encoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(decoded, &mut canonical)
        .ok()?;
    (decoded_len == decoded.len()
        && encoded_len == canonical.len()
        && bool::from(canonical.ct_eq(token.as_bytes())))
    .then(|| Sha256::digest(decoded).into())
}

/// Checks the exact carrier media type without accepting duplicate headers.
pub(super) fn binary_content_type<B>(request: &Request<B>) -> bool {
    let values = request.headers().get_all(header::CONTENT_TYPE);
    let mut values = values.iter();
    let value = values.next().and_then(|value| value.to_str().ok());
    values.next().is_none()
        && value.is_some_and(|value| value.eq_ignore_ascii_case("application/octet-stream"))
}

/// Accepts no Cookie or the one empty value emitted by restricted Windows WebView2.
pub(super) fn compatible_cookie_header<B>(request: &Request<B>) -> bool {
    let values = request.headers().get_all(header::COOKIE);
    let mut values = values.iter();
    match values.next() {
        None => true,
        Some(value) => value.as_bytes().is_empty() && values.next().is_none(),
    }
}

/// Parses one canonical unsigned decimal carrier sequence header.
pub(super) fn canonical_u64_header<B>(request: &Request<B>, name: &'static str) -> Option<u64> {
    let values = request.headers().get_all(name);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || value.is_empty()
        || value.starts_with('+')
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bridge_query_rejects_aliases() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(bridge_candidate(Some(&format!("bridge={token}"))).1);
        assert!(!bridge_candidate(Some(&format!("x=1&bridge={token}"))).1);
        assert!(!bridge_candidate(Some(&format!("bridge={token}="))).1);
    }

    #[test]
    fn host_is_canonical_and_forwarded_identity_is_single_parseable_ip() {
        let request = Request::builder()
            .header(header::HOST, "proxy.example.com:443")
            .header("x-forwarded-for", "192.0.2.10")
            .body(())
            .unwrap();
        assert_eq!(canonical_request_host(&request), Some("proxy.example.com"));
        let trusted: [IpNetwork; 1] = ["127.0.0.1/32".parse().unwrap()];
        assert_eq!(
            client_ip(
                &request,
                "127.0.0.1:40000".parse().unwrap(),
                WebClientIpSource::XForwardedFor,
                &trusted,
            ),
            Some("192.0.2.10".parse().unwrap())
        );

        let expanded_ipv6 = Request::builder()
            .header("x-forwarded-for", "2001:0db8:0:0:0:0:0:10")
            .body(())
            .unwrap();
        assert_eq!(
            client_ip(
                &expanded_ipv6,
                "127.0.0.1:40000".parse().unwrap(),
                WebClientIpSource::XForwardedFor,
                &trusted,
            ),
            Some("2001:db8::10".parse().unwrap())
        );

        let without_forwarded_address = Request::builder().body(()).unwrap();
        assert_eq!(
            client_ip(
                &without_forwarded_address,
                "127.0.0.1:40000".parse().unwrap(),
                WebClientIpSource::XForwardedFor,
                &trusted,
            ),
            Some("127.0.0.1".parse().unwrap())
        );

        let empty_forwarded_address = Request::builder()
            .header("x-forwarded-for", "")
            .body(())
            .unwrap();
        assert_eq!(
            client_ip(
                &empty_forwarded_address,
                "127.0.0.1:40000".parse().unwrap(),
                WebClientIpSource::XForwardedFor,
                &trusted,
            ),
            Some("127.0.0.1".parse().unwrap())
        );

        let uppercase = Request::builder()
            .header(header::HOST, "Proxy.Example.com")
            .body(())
            .unwrap();
        assert!(canonical_request_host(&uppercase).is_none());
        let appended = Request::builder()
            .header("x-forwarded-for", "192.0.2.10, 198.51.100.4")
            .body(())
            .unwrap();
        assert!(
            client_ip(
                &appended,
                "127.0.0.1:40000".parse().unwrap(),
                WebClientIpSource::XForwardedFor,
                &trusted,
            )
            .is_none()
        );
    }

    #[test]
    fn bearer_and_sequence_headers_reject_noncanonical_aliases() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let request = Request::builder()
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-up-seq", "17")
            .body(())
            .unwrap();
        assert_eq!(
            bearer_token_hash(&request),
            Some(Sha256::digest([1u8; 32]).into())
        );
        assert_eq!(canonical_u64_header(&request, "x-up-seq"), Some(17));

        let leading_zero = Request::builder()
            .header("x-up-seq", "017")
            .body(())
            .unwrap();
        assert!(canonical_u64_header(&leading_zero, "x-up-seq").is_none());
    }

    #[test]
    fn cookie_header_accepts_only_absent_or_one_empty_value() {
        let absent = Request::new(());
        assert!(compatible_cookie_header(&absent));

        let empty = Request::builder()
            .header(header::COOKIE, "")
            .body(())
            .unwrap();
        assert!(compatible_cookie_header(&empty));

        let nonempty = Request::builder()
            .header(header::COOKIE, "state=unexpected")
            .body(())
            .unwrap();
        assert!(!compatible_cookie_header(&nonempty));

        let whitespace = Request::builder()
            .header(header::COOKIE, " ")
            .body(())
            .unwrap();
        assert!(!compatible_cookie_header(&whitespace));

        let mut duplicate_empty = Request::new(());
        duplicate_empty
            .headers_mut()
            .append(header::COOKIE, "".parse().unwrap());
        duplicate_empty
            .headers_mut()
            .append(header::COOKIE, "".parse().unwrap());
        assert!(!compatible_cookie_header(&duplicate_empty));

        let mut duplicate_mixed = Request::new(());
        duplicate_mixed
            .headers_mut()
            .append(header::COOKIE, "".parse().unwrap());
        duplicate_mixed
            .headers_mut()
            .append(header::COOKIE, "state=unexpected".parse().unwrap());
        assert!(!compatible_cookie_header(&duplicate_mixed));
    }
}
