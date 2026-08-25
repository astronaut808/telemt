use super::*;

pub(super) struct MtprotoCandidateValidation {
    pub(super) proto_tag: ProtoTag,
    pub(super) dc_idx: i16,
    pub(super) dec_key: [u8; 32],
    pub(super) dec_iv: u128,
    pub(super) enc_key: [u8; 32],
    pub(super) enc_iv: u128,
    pub(super) decryptor: AesCtr,
    pub(super) encryptor: AesCtr,
}

#[derive(Clone, Copy)]
pub(super) enum MtprotoModePolicy {
    Configured,
    Web(WebSecretMode),
}

pub(super) fn sni_hint_hash(sni: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    for byte in sni.bytes() {
        hasher.write_u8(byte.to_ascii_lowercase());
    }
    hasher.finish()
}

pub(super) fn ip_prefix_hint_key(peer_ip: IpAddr) -> u64 {
    match peer_ip {
        // Keep /24 granularity for IPv4 to avoid over-merging unrelated clients.
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            u64::from_be_bytes([0x04, a, b, c, 0, 0, 0, 0])
        }
        // Keep /56 granularity for IPv6 to retain stability while limiting bucket size.
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            u64::from_be_bytes([
                0x06, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
            ])
        }
    }
}

pub(super) fn sticky_hint_get_by_ip(shared: &ProxySharedState, peer_ip: IpAddr) -> Option<u32> {
    shared
        .handshake
        .sticky_user_by_ip
        .get(&peer_ip)
        .map(|entry| *entry)
}

pub(super) fn sticky_hint_get_by_ip_prefix(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> Option<u32> {
    shared
        .handshake
        .sticky_user_by_ip_prefix
        .get(&ip_prefix_hint_key(peer_ip))
        .map(|entry| *entry)
}

pub(super) fn sticky_hint_get_by_sni(shared: &ProxySharedState, sni: &str) -> Option<u32> {
    let key = sni_hint_hash(sni);
    shared
        .handshake
        .sticky_user_by_sni_hash
        .get(&key)
        .map(|entry| *entry)
}

pub(super) fn sticky_hint_record_success_in(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    user_id: u32,
    sni: Option<&str>,
) {
    if shared.handshake.sticky_user_by_ip.len() > STICKY_HINT_MAX_ENTRIES {
        shared.handshake.sticky_user_by_ip.clear();
    }
    shared.handshake.sticky_user_by_ip.insert(peer_ip, user_id);

    if shared.handshake.sticky_user_by_ip_prefix.len() > STICKY_HINT_MAX_ENTRIES {
        shared.handshake.sticky_user_by_ip_prefix.clear();
    }
    shared
        .handshake
        .sticky_user_by_ip_prefix
        .insert(ip_prefix_hint_key(peer_ip), user_id);

    if let Some(sni) = sni {
        if shared.handshake.sticky_user_by_sni_hash.len() > STICKY_HINT_MAX_ENTRIES {
            shared.handshake.sticky_user_by_sni_hash.clear();
        }
        shared
            .handshake
            .sticky_user_by_sni_hash
            .insert(sni_hint_hash(sni), user_id);
    }
}

pub(super) fn record_recent_user_success_in(shared: &ProxySharedState, user_id: u32) {
    let ring = &shared.handshake.recent_user_ring;
    if ring.is_empty() {
        return;
    }
    let seq = shared
        .handshake
        .recent_user_ring_seq
        .fetch_add(1, Ordering::Relaxed);
    let idx = (seq as usize) % ring.len();
    ring[idx].store(user_id.saturating_add(1), Ordering::Relaxed);
}

pub(super) fn mark_candidate_if_new(
    tried_user_ids: &mut [u32],
    tried_len: &mut usize,
    user_id: u32,
) -> bool {
    if tried_user_ids[..*tried_len].contains(&user_id) {
        return false;
    }
    if *tried_len < tried_user_ids.len() {
        tried_user_ids[*tried_len] = user_id;
        *tried_len += 1;
    }
    true
}

pub(super) fn budget_for_validation(total_users: usize, overload: bool, has_hint: bool) -> usize {
    if total_users == 0 {
        return 0;
    }
    if !overload {
        return total_users;
    }
    let cap = if has_hint {
        OVERLOAD_CANDIDATE_BUDGET_HINTED
    } else {
        OVERLOAD_CANDIDATE_BUDGET_UNHINTED
    };
    total_users.min(cap.max(1))
}

pub(super) fn validate_mtproto_secret_candidate(
    handshake: &[u8; HANDSHAKE_LEN],
    dec_prekey: &[u8; PREKEY_LEN],
    dec_iv: u128,
    enc_prekey: &[u8; PREKEY_LEN],
    enc_iv: u128,
    secret: &[u8; ACCESS_SECRET_BYTES],
    config: &ProxyConfig,
    is_tls: bool,
    mode_policy: MtprotoModePolicy,
) -> Option<MtprotoCandidateValidation> {
    let mut dec_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    dec_key_input.extend_from_slice(dec_prekey);
    dec_key_input.extend_from_slice(secret);
    let dec_key = Zeroizing::new(sha256(&dec_key_input));

    let mut decryptor = AesCtr::new(&dec_key, dec_iv);
    let mut decrypted = *handshake;
    decryptor.apply(&mut decrypted);

    let tag_bytes: [u8; 4] = [
        decrypted[PROTO_TAG_POS],
        decrypted[PROTO_TAG_POS + 1],
        decrypted[PROTO_TAG_POS + 2],
        decrypted[PROTO_TAG_POS + 3],
    ];
    let proto_tag = ProtoTag::from_bytes(tag_bytes)?;
    if !mode_enabled_for_proto_with_policy(config, proto_tag, is_tls, mode_policy) {
        return None;
    }

    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);

    let mut enc_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    enc_key_input.extend_from_slice(enc_prekey);
    enc_key_input.extend_from_slice(secret);
    let enc_key = Zeroizing::new(sha256(&enc_key_input));

    let encryptor = AesCtr::new(&enc_key, enc_iv);

    Some(MtprotoCandidateValidation {
        proto_tag,
        dc_idx,
        dec_key: *dec_key,
        dec_iv,
        enc_key: *enc_key,
        enc_iv,
        decryptor,
        encryptor,
    })
}

pub(super) fn warn_invalid_secret_once_in(
    shared: &ProxySharedState,
    name: &str,
    reason: &str,
    expected: usize,
    got: Option<usize>,
) {
    let key = (name.to_string(), reason.to_string());
    let should_warn = match shared.handshake.invalid_secret_warned.lock() {
        Ok(mut guard) => {
            if !guard.contains(&key) && guard.len() >= WARNED_SECRET_MAX_ENTRIES {
                false
            } else {
                guard.insert(key)
            }
        }
        Err(_) => true,
    };

    if !should_warn {
        return;
    }

    match got {
        Some(actual) => {
            warn!(
                user = %name,
                expected = expected,
                got = actual,
                "Skipping user: access secret has unexpected length"
            );
        }
        None => {
            warn!(
                user = %name,
                "Skipping user: access secret is not valid hex"
            );
        }
    }
}

pub(super) fn decode_user_secret(
    shared: &ProxySharedState,
    name: &str,
    secret_hex: &str,
) -> Option<Vec<u8>> {
    match hex::decode(secret_hex) {
        Ok(bytes) if bytes.len() == ACCESS_SECRET_BYTES => Some(bytes),
        Ok(bytes) => {
            warn_invalid_secret_once_in(
                shared,
                name,
                "invalid_length",
                ACCESS_SECRET_BYTES,
                Some(bytes.len()),
            );
            None
        }
        Err(_) => {
            warn_invalid_secret_once_in(shared, name, "invalid_hex", ACCESS_SECRET_BYTES, None);
            None
        }
    }
}

// Decide whether a client-supplied proto tag is allowed given the configured
// proxy modes and the transport that carried the handshake.
//
// A common mistake is to treat `modes.tls` and `modes.secure` as interchangeable
// even though they correspond to different transport profiles: `modes.tls` is
// for the TLS-fronted (EE-TLS) path, while `modes.secure` is for direct MTProto
// over TCP (DD). Enforcing this separation prevents an attacker from using a
// TLS-capable client to bypass the operator intent for the direct MTProto mode,
// and vice versa.
pub(super) fn mode_enabled_for_proto(
    config: &ProxyConfig,
    proto_tag: ProtoTag,
    is_tls: bool,
) -> bool {
    mode_enabled_for_proto_with_policy(config, proto_tag, is_tls, MtprotoModePolicy::Configured)
}

fn mode_enabled_for_proto_with_policy(
    config: &ProxyConfig,
    proto_tag: ProtoTag,
    is_tls: bool,
    policy: MtprotoModePolicy,
) -> bool {
    if let MtprotoModePolicy::Web(secret_mode) = policy {
        return match secret_mode {
            WebSecretMode::Plain => {
                matches!(proto_tag, ProtoTag::Intermediate | ProtoTag::Abridged)
            }
            WebSecretMode::Dd => matches!(proto_tag, ProtoTag::Secure),
        };
    }
    match proto_tag {
        ProtoTag::Secure => {
            if is_tls {
                config.general.modes.tls
            } else {
                config.general.modes.secure
            }
        }
        ProtoTag::Intermediate | ProtoTag::Abridged => config.general.modes.classic,
    }
}

#[cfg(test)]
mod web_mode_tests {
    use super::*;

    #[test]
    fn web_secret_mode_isolates_inner_protocol_tags() {
        let config = ProxyConfig::default();
        assert!(mode_enabled_for_proto_with_policy(
            &config,
            ProtoTag::Abridged,
            false,
            MtprotoModePolicy::Web(WebSecretMode::Plain),
        ));
        assert!(mode_enabled_for_proto_with_policy(
            &config,
            ProtoTag::Intermediate,
            false,
            MtprotoModePolicy::Web(WebSecretMode::Plain),
        ));
        assert!(!mode_enabled_for_proto_with_policy(
            &config,
            ProtoTag::Secure,
            false,
            MtprotoModePolicy::Web(WebSecretMode::Plain),
        ));
        assert!(mode_enabled_for_proto_with_policy(
            &config,
            ProtoTag::Secure,
            false,
            MtprotoModePolicy::Web(WebSecretMode::Dd),
        ));
        assert!(!mode_enabled_for_proto_with_policy(
            &config,
            ProtoTag::Intermediate,
            false,
            MtprotoModePolicy::Web(WebSecretMode::Dd),
        ));
    }
}

pub(super) fn decode_user_secrets_in(
    shared: &ProxySharedState,
    config: &ProxyConfig,
    preferred_user: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    let mut secrets = Vec::with_capacity(config.access.users.len());

    if let Some(preferred) = preferred_user
        && let Some(secret_hex) = config.access.users.get(preferred)
        && let Some(bytes) = decode_user_secret(shared, preferred, secret_hex)
    {
        secrets.push((preferred.to_string(), bytes));
    }

    for (name, secret_hex) in &config.access.users {
        if preferred_user.is_some_and(|preferred| preferred == name.as_str()) {
            continue;
        }
        if let Some(bytes) = decode_user_secret(shared, name, secret_hex) {
            secrets.push((name.clone(), bytes));
        }
    }

    secrets
}
