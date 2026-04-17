//! TLS mask host suitability assessment command.
//!
//! This command performs live TLS metadata probes using the same fetch path
//! Telemt already uses for TLS-front profile acquisition. The goal is not to
//! prove indistinguishability, but to answer a narrower operational question:
//! whether a candidate host looks suitable for `censorship.tls_domain` and
//! profile fetch in a Telemt deployment.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::TlsFetchProfile;
use crate::tls_front::fetcher::{TlsFetchStrategy, fetch_real_tls_with_strategy};
use crate::tls_front::types::{ParsedCertificateInfo, TlsBehaviorProfile, TlsFetchResult, TlsProfileSource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckMaskHostOptions {
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub attempts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Recommended,
    UsableWithCaution,
    NotRecommended,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Recommended => "recommended",
            Verdict::UsableWithCaution => "usable_with_caution",
            Verdict::NotRecommended => "not_recommended",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Verdict::Recommended => 0,
            Verdict::UsableWithCaution => 10,
            Verdict::NotRecommended => 20,
        }
    }
}

#[derive(Debug, Clone)]
struct ProbeObservation {
    cert_covers_sni: bool,
    cert_valid_now: bool,
    cert_payload_present: bool,
    encrypted_flight_present: bool,
    identity: Option<(Option<String>, Option<String>)>,
    behavior_source: TlsProfileSource,
}

#[derive(Debug, Clone)]
struct Assessment {
    verdict: Verdict,
    score: u8,
    success_count: usize,
    attempts: usize,
    reasons: Vec<&'static str>,
}

pub fn run(opts: &CheckMaskHostOptions) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("[telemt] check-mask-host: failed to create runtime: {err}");
            return 1;
        }
    };

    runtime.block_on(run_async(opts))
}

async fn run_async(opts: &CheckMaskHostOptions) -> i32 {
    let sni = opts.sni.as_deref().unwrap_or(opts.host.as_str());
    let strategy = TlsFetchStrategy {
        profiles: vec![
            TlsFetchProfile::ModernChromeLike,
            TlsFetchProfile::ModernFirefoxLike,
            TlsFetchProfile::CompatTls12,
            TlsFetchProfile::LegacyMinimal,
        ],
        strict_route: false,
        attempt_timeout: Duration::from_millis(1500),
        total_budget: Duration::from_millis(5000),
        grease_enabled: false,
        deterministic: false,
        profile_cache_ttl: Duration::ZERO,
    };

    let mut observations = Vec::new();
    let mut errors = Vec::new();

    for _ in 0..opts.attempts {
        match fetch_real_tls_with_strategy(
            opts.host.as_str(),
            opts.port,
            sni,
            &strategy,
            None,
            None,
            0,
            None,
        )
        .await
        {
            Ok(result) => observations.push(observe_probe(&result, sni)),
            Err(err) => errors.push(err.to_string()),
        }
    }

    let assessment = assess(&observations, opts.attempts);

    print_report(opts, sni, &assessment, &observations, &errors);
    assessment.verdict.exit_code()
}

fn observe_probe(result: &TlsFetchResult, sni: &str) -> ProbeObservation {
    ProbeObservation {
        cert_covers_sni: certificate_covers_sni(result.cert_info.as_ref(), sni),
        cert_valid_now: certificate_is_valid_now(result.cert_info.as_ref()),
        cert_payload_present: result
            .cert_payload
            .as_ref()
            .is_some_and(|payload| !payload.cert_chain_der.is_empty() && !payload.certificate_message.is_empty()),
        encrypted_flight_present: has_encrypted_flight(result),
        identity: result
            .cert_info
            .as_ref()
            .map(|cert| (cert.subject_cn.clone(), cert.issuer_cn.clone())),
        behavior_source: result.behavior_profile.source,
    }
}

fn has_encrypted_flight(result: &TlsFetchResult) -> bool {
    result.total_app_data_len > 0
        || !result.app_data_records_sizes.is_empty()
        || behavior_profile_has_payload(&result.behavior_profile)
}

fn behavior_profile_has_payload(profile: &TlsBehaviorProfile) -> bool {
    !profile.app_data_record_sizes.is_empty() || !profile.ticket_record_sizes.is_empty()
}

fn certificate_covers_sni(cert: Option<&ParsedCertificateInfo>, sni: &str) -> bool {
    let Some(cert) = cert else {
        return false;
    };

    if cert
        .san_names
        .iter()
        .any(|name| dns_name_matches(name.as_str(), sni))
    {
        return true;
    }

    cert.subject_cn
        .as_deref()
        .is_some_and(|name| dns_name_matches(name, sni))
}

fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if pattern == host {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host == suffix {
            return false;
        }
        return host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.'));
    }

    false
}

fn certificate_is_valid_now(cert: Option<&ParsedCertificateInfo>) -> bool {
    let Some(cert) = cert else {
        return false;
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => return false,
    };

    match (cert.not_before_unix, cert.not_after_unix) {
        (Some(not_before), Some(not_after)) => now >= not_before && now <= not_after,
        _ => false,
    }
}

fn assess(observations: &[ProbeObservation], attempts: usize) -> Assessment {
    let success_count = observations.len();
    let all_success = success_count == attempts;
    let majority_success = success_count * 2 >= attempts.max(1);
    let all_cover = !observations.is_empty() && observations.iter().all(|obs| obs.cert_covers_sni);
    let all_valid = !observations.is_empty() && observations.iter().all(|obs| obs.cert_valid_now);
    let all_have_payload = !observations.is_empty()
        && observations.iter().all(|obs| obs.cert_payload_present);
    let all_have_encrypted_flight = !observations.is_empty()
        && observations.iter().all(|obs| obs.encrypted_flight_present);
    let merged_or_raw_majority = observations
        .iter()
        .filter(|obs| matches!(obs.behavior_source, TlsProfileSource::Merged | TlsProfileSource::Raw))
        .count()
        * 2
        >= success_count.max(1);
    let stable_identity = identities_are_stable(observations);

    let mut score = 0i32;
    let mut reasons = Vec::new();

    match success_count {
        count if count == attempts && attempts > 0 => {
            score += 40;
            reasons.push("all live TLS probes completed successfully");
        }
        count if count * 2 >= attempts.max(1) => {
            score += 24;
            reasons.push("most live TLS probes completed successfully");
        }
        count if count > 0 => {
            score += 10;
            reasons.push("only a minority of live TLS probes completed successfully");
        }
        _ => {
            reasons.push("no live TLS probe completed successfully");
        }
    }

    if all_cover {
        score += 20;
        reasons.push("certificate identity covers the requested SNI");
    } else {
        score -= 25;
        reasons.push("certificate identity does not consistently cover the requested SNI");
    }

    if all_valid {
        score += 10;
        reasons.push("certificate validity window is current on successful probes");
    } else {
        score -= 15;
        reasons.push("certificate validity could not be confirmed on all successful probes");
    }

    if all_have_payload {
        score += 15;
        reasons.push("certificate payload is available for FakeTLS profile use");
    } else {
        score -= 15;
        reasons.push("certificate payload was not available on every successful probe");
    }

    if all_have_encrypted_flight {
        score += 15;
        reasons.push("encrypted TLS flight was observed on every successful probe");
    } else {
        score -= 20;
        reasons.push("encrypted TLS flight was missing on at least one successful probe");
    }

    if merged_or_raw_majority {
        score += 10;
        reasons.push("profile acquisition used raw or merged TLS capture on most probes");
    } else {
        reasons.push("profile acquisition relied on weaker metadata fallback");
    }

    if stable_identity && success_count > 1 {
        score += 10;
        reasons.push("certificate identity remained stable across repeated probes");
    }

    score = score.clamp(0, 100);
    let verdict = if all_success && all_cover && all_valid && all_have_payload && all_have_encrypted_flight && score >= 80 {
        Verdict::Recommended
    } else if majority_success && all_cover && all_have_encrypted_flight && score >= 55 {
        Verdict::UsableWithCaution
    } else {
        Verdict::NotRecommended
    };

    Assessment {
        verdict,
        score: score as u8,
        success_count,
        attempts,
        reasons,
    }
}

fn identities_are_stable(observations: &[ProbeObservation]) -> bool {
    let mut identities = observations.iter().filter_map(|obs| obs.identity.as_ref());
    let Some(first) = identities.next() else {
        return false;
    };
    identities.all(|identity| identity == first)
}

fn print_report(
    opts: &CheckMaskHostOptions,
    sni: &str,
    assessment: &Assessment,
    observations: &[ProbeObservation],
    errors: &[String],
) {
    println!("[telemt] Mask host assessment");
    println!("host: {}:{}", opts.host, opts.port);
    println!("sni: {sni}");
    println!("probes: {}/{}", assessment.success_count, assessment.attempts);
    println!(
        "verdict: {} ({}/100)",
        assessment.verdict.as_str(),
        assessment.score
    );

    for reason in &assessment.reasons {
        println!("- {reason}");
    }

    if !observations.is_empty() {
        let raw_or_merged = observations
            .iter()
            .filter(|obs| matches!(obs.behavior_source, TlsProfileSource::Merged | TlsProfileSource::Raw))
            .count();
        println!(
            "successful_probe_profile_quality: {}/{} raw_or_merged",
            raw_or_merged,
            observations.len()
        );
    }

    if !errors.is_empty() {
        println!("failed_probe_errors:");
        for error in errors {
            println!("- {error}");
        }
    }

    println!("note: this command checks host suitability for Telemt TLS profiling");
    println!("note: it does not prove full origin indistinguishability on your deployment path");
}

#[cfg(test)]
mod tests {
    use super::{ProbeObservation, Verdict, assess, dns_name_matches};
    use crate::tls_front::types::TlsProfileSource;

    #[test]
    fn wildcard_dns_name_matches_single_label() {
        assert!(dns_name_matches("*.example.com", "edge.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
    }

    #[test]
    fn recommended_assessment_requires_strong_signals() {
        let observation = ProbeObservation {
            cert_covers_sni: true,
            cert_valid_now: true,
            cert_payload_present: true,
            encrypted_flight_present: true,
            identity: Some((Some("nginx.org".to_string()), Some("Example CA".to_string()))),
            behavior_source: TlsProfileSource::Merged,
        };
        let assessment = assess(&[observation.clone(), observation.clone(), observation], 3);
        assert_eq!(assessment.verdict, Verdict::Recommended);
        assert!(assessment.score >= 80);
    }

    #[test]
    fn failed_probes_drive_not_recommended_verdict() {
        let assessment = assess(&[], 3);
        assert_eq!(assessment.verdict, Verdict::NotRecommended);
        assert_eq!(assessment.score, 0);
    }

    #[test]
    fn caution_verdict_handles_partial_success() {
        let assessment = assess(
            &[
                ProbeObservation {
                    cert_covers_sni: true,
                    cert_valid_now: true,
                    cert_payload_present: true,
                    encrypted_flight_present: true,
                    identity: Some((Some("nginx.org".to_string()), Some("Example CA".to_string()))),
                    behavior_source: TlsProfileSource::Raw,
                },
                ProbeObservation {
                    cert_covers_sni: true,
                    cert_valid_now: true,
                    cert_payload_present: false,
                    encrypted_flight_present: true,
                    identity: Some((Some("nginx.org".to_string()), Some("Example CA".to_string()))),
                    behavior_source: TlsProfileSource::Raw,
                },
            ],
            3,
        );
        assert_eq!(assessment.verdict, Verdict::UsableWithCaution);
    }
}
