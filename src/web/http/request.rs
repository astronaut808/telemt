use std::sync::Arc;

use base64::Engine as _;
use hyper::Request;
use hyper::header;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{WebRuntimeProfile, WebRuntimeVhost};
use crate::web::manager::{
    CarrierCapabilities, CarrierClientClass, CarrierFailure, CarrierRequest, TokenHash,
};

const USER_AGENT_CONTEXT: &[u8] = b"telemt-web-carrier-user-agent-v1\0";

// Canonical host and forwarded-address provenance remain isolated from credentials.
mod identity;
pub(super) use identity::{
    canonical_request_host, carrier_ip_learning_eligible, client_ip,
};

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

/// Parses strict bridge negotiation metadata without trusting it for authentication.
pub(super) fn carrier_request<B>(request: &Request<B>, host: &str) -> Option<CarrierRequest> {
    let user_agent_hash = normalized_user_agent_hash(request)?;
    let capabilities = single_header(request, "x-carrier-capabilities");
    let attempt = optional_canonical_u8_header(request, "x-carrier-attempt")?;
    let failure = optional_failure_header(request)?;
    let native_ios = native_ios_user_agent(request);
    match (capabilities, attempt) {
        (None, None) if failure.is_none() => {
            if native_ios {
                Some(CarrierRequest::ios(user_agent_hash))
            } else {
                Some(CarrierRequest::legacy(user_agent_hash))
            }
        }
        (Some(capabilities), Some(attempt)) => {
            let capabilities = parse_capabilities(capabilities)?;
            if (attempt == 1) != failure.is_none() {
                return None;
            }
            Some(CarrierRequest::automatic(
                if native_ios {
                    CarrierClientClass::Ios
                } else {
                    CarrierClientClass::Bridge
                },
                capabilities,
                attempt,
                failure,
                user_agent_hash,
            ))
        }
        (None, Some(attempt)) if strict_browser_hint(request, host) => {
            if (attempt == 1) != failure.is_none() {
                return None;
            }
            Some(CarrierRequest::automatic(
                if native_ios {
                    CarrierClientClass::Ios
                } else {
                    CarrierClientClass::BrowserHint
                },
                CarrierCapabilities::all(),
                attempt,
                failure,
                user_agent_hash,
            ))
        }
        _ => None,
    }
}

fn native_ios_user_agent<B>(request: &Request<B>) -> bool {
    single_header(request, header::USER_AGENT).is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("cfnetwork/") && value.contains("darwin/")
    })
}

fn parse_capabilities(value: &str) -> Option<CarrierCapabilities> {
    let mut bits = 0u8;
    let mut previous = None;
    for token in value.split(',') {
        let index = match token {
            "https" => 0,
            "https-lanes" => 1,
            "websocket" => 2,
            "websocket-lanes" => 3,
            _ => return None,
        };
        if previous.is_some_and(|previous| index <= previous) {
            return None;
        }
        previous = Some(index);
        bits |= 1 << index;
    }
    CarrierCapabilities::from_bits(bits)
}

fn strict_browser_hint<B>(request: &Request<B>, host: &str) -> bool {
    single_header(request, header::ORIGIN)
        .is_some_and(|value| value == format!("https://{host}"))
        && single_header(request, "sec-fetch-site") == Some("same-origin")
        && single_header(request, "sec-fetch-mode") == Some("cors")
        && single_header(request, "sec-fetch-dest") == Some("empty")
}

fn optional_canonical_u8_header<B>(
    request: &Request<B>,
    name: &'static str,
) -> Option<Option<u8>> {
    if !request.headers().contains_key(name) {
        return Some(None);
    }
    canonical_u64_header(request, name)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=4).contains(value))
        .map(Some)
}

fn optional_failure_header<B>(request: &Request<B>) -> Option<Option<CarrierFailure>> {
    if !request.headers().contains_key("x-carrier-failure") {
        return Some(None);
    }
    single_header(request, "x-carrier-failure")
        .and_then(CarrierFailure::parse)
        .map(Some)
}

fn normalized_user_agent_hash<B>(request: &Request<B>) -> Option<[u8; 32]> {
    let user_agent = match single_header(request, header::USER_AGENT) {
        Some(value) => value.as_bytes(),
        None if !request.headers().contains_key(header::USER_AGENT) => &[],
        None => return None,
    };
    let mut digest = Sha256::new();
    digest.update(USER_AGENT_CONTEXT);
    let mut emitted = false;
    let mut pending_whitespace = false;
    for &byte in user_agent {
        if byte.is_ascii_whitespace() {
            pending_whitespace = emitted;
        } else {
            if pending_whitespace {
                digest.update([b' ']);
            }
            digest.update([byte.to_ascii_lowercase()]);
            emitted = true;
            pending_whitespace = false;
        }
    }
    Some(digest.finalize().into())
}

fn single_header<B>(request: &Request<B>, name: impl header::AsHeaderName) -> Option<&str> {
    let mut values = request.headers().get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::IpNetwork;

    use crate::config::{WebCarrier, WebClientIpSource};

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

    #[test]
    fn carrier_metadata_is_canonical_and_legacy_safe() {
        let automatic = Request::builder()
            .header(
                "x-carrier-capabilities",
                "https,https-lanes,websocket,websocket-lanes",
            )
            .header("x-carrier-attempt", "2")
            .header("x-carrier-failure", "timeout")
            .header(header::USER_AGENT, "Example  Browser")
            .body(())
            .unwrap();
        let parsed = carrier_request(&automatic, "proxy.example.com").unwrap();
        assert!(parsed.is_automatic());
        assert_eq!(parsed.attempt(), Some(2));
        assert_eq!(parsed.failure(), Some(CarrierFailure::Timeout));

        let missing_failure = Request::builder()
            .header(
                "x-carrier-capabilities",
                "https,https-lanes,websocket,websocket-lanes",
            )
            .header("x-carrier-attempt", "2")
            .body(())
            .unwrap();
        assert!(carrier_request(&missing_failure, "proxy.example.com").is_none());

        let legacy = Request::builder()
            .header(header::USER_AGENT, "Native")
            .body(())
            .unwrap();
        assert!(!carrier_request(&legacy, "proxy.example.com")
            .unwrap()
            .is_automatic());

        let reordered = Request::builder()
            .header("x-carrier-capabilities", "websocket,https")
            .header("x-carrier-attempt", "1")
            .body(())
            .unwrap();
        assert!(carrier_request(&reordered, "proxy.example.com").is_none());
    }

    #[test]
    fn native_ios_user_agent_classifies_without_overriding_capabilities() {
        let metadata_free = Request::builder()
            .header(
                header::USER_AGENT,
                "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
            )
            .body(())
            .unwrap();
        let parsed = carrier_request(&metadata_free, "proxy.example.com").unwrap();
        assert_eq!(parsed.class(), CarrierClientClass::Ios);
        assert!(!parsed.is_automatic());
        assert!(!parsed.uses_capabilities());

        let automatic = Request::builder()
            .header(
                "x-carrier-capabilities",
                "https,https-lanes",
            )
            .header("x-carrier-attempt", "1")
            .header(
                header::USER_AGENT,
                "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
            )
            .body(())
            .unwrap();
        let parsed = carrier_request(&automatic, "proxy.example.com").unwrap();
        assert_eq!(parsed.class(), CarrierClientClass::Ios);
        assert!(parsed.is_automatic());
        assert!(parsed.supports(WebCarrier::Https));
        assert!(parsed.supports(WebCarrier::HttpsLanes));
        assert!(!parsed.supports(WebCarrier::Websocket));
        assert!(!parsed.supports(WebCarrier::WebsocketLanes));
    }

    #[test]
    fn mapped_private_addresses_are_not_learning_evidence() {
        for address in ["::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            let effective_ip = address.parse().unwrap();
            let request = Request::builder()
                .header("x-forwarded-for", address)
                .body(())
                .unwrap();
            assert!(!carrier_ip_learning_eligible(&request, effective_ip));
        }
        let effective_ip = "::ffff:8.8.8.8".parse().unwrap();
        let request = Request::builder()
            .header("x-forwarded-for", "::ffff:8.8.8.8")
            .body(())
            .unwrap();
        assert!(carrier_ip_learning_eligible(&request, effective_ip));
    }

    #[test]
    fn strict_browser_metadata_recovers_a_stripped_capability_marker() {
        let request = Request::builder()
            .header("x-carrier-attempt", "1")
            .header(header::ORIGIN, "https://proxy.example.com")
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-dest", "empty")
            .body(())
            .unwrap();
        let parsed = carrier_request(&request, "proxy.example.com").unwrap();
        assert_eq!(parsed.class(), CarrierClientClass::BrowserHint);
    }

    #[test]
    fn user_agent_learning_key_is_case_and_whitespace_normalized() {
        let first = Request::builder()
            .header(header::USER_AGENT, "  Example\t Browser  ")
            .body(())
            .unwrap();
        let second = Request::builder()
            .header(header::USER_AGENT, "example browser")
            .body(())
            .unwrap();
        assert_eq!(
            normalized_user_agent_hash(&first),
            normalized_user_agent_hash(&second)
        );
    }
}
