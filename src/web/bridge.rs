use base64::Engine as _;

use crate::crypto::SecureRandom;

/// Browser security policy for the transient Telegram Desktop bridge page.
pub(crate) const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

/// Fully rendered bridge response and its per-response script policy.
pub(crate) struct BridgePage {
    /// Complete transient HTML document.
    pub(crate) body: String,
    /// Nonce-bound policy that authorizes only the embedded bridge script.
    pub(crate) content_security_policy: String,
}

/// Renders the bounded WEB carrier-negotiation bridge with a fresh CSP nonce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render(
    host: &str,
    bootstrap: &str,
    batch_limit: usize,
    queue_limit: usize,
    queue_items: usize,
    negotiation_enabled: bool,
    candidate_count: usize,
    carrier_deadlines: [u64; 4],
    long_poll_secs: u64,
    bridge_request_secs: u64,
    bridge_retry_secs: u64,
    carrier_probe_coalesce_ms: u64,
    rng: &SecureRandom,
) -> BridgePage {
    let mut nonce = [0u8; 18];
    rng.fill(&mut nonce);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let body = DOCUMENT
        .replace("__RUNTIME__", RUNTIME)
        .replace("__NONCE__", &nonce)
        .replace("__HOST__", host)
        .replace("__BOOTSTRAP__", bootstrap)
        .replace("__BATCH_LIMIT__", &batch_limit.to_string())
        .replace("__QUEUE_LIMIT__", &queue_limit.to_string())
        .replace("__QUEUE_ITEMS__", &queue_items.to_string())
        .replace(
            "__NEGOTIATION_ENABLED__",
            if negotiation_enabled { "true" } else { "false" },
        )
        .replace("__CANDIDATE_COUNT__", &candidate_count.to_string())
        .replace("__LONG_POLL_SECS__", &long_poll_secs.to_string())
        .replace("__BRIDGE_REQUEST_SECS__", &bridge_request_secs.to_string())
        .replace("__BRIDGE_RETRY_SECS__", &bridge_retry_secs.to_string())
        .replace(
            "__CARRIER_PROBE_COALESCE_MS__",
            &carrier_probe_coalesce_ms.to_string(),
        )
        .replace(
            "__CARRIER_DEADLINES__",
            &carrier_deadlines
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    BridgePage {
        body,
        content_security_policy: format!(
            "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://{host}; font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; frame-src 'none'; img-src 'none'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts"
        ),
    }
}

const DOCUMENT: &str = include_str!("bridge/document.html");
const RUNTIME: &str = include_str!("bridge/runtime.js");

// Rendered wire-contract tests remain separate from the embedded document.
#[cfg(test)]
mod tests;
