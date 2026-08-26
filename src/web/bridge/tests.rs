use super::*;

fn render_page(bootstrap: &str, candidate_count: usize) -> BridgePage {
    render(
        "proxy.example.com",
        bootstrap,
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        true,
        candidate_count,
        [3, 5, 8, 12],
        &SecureRandom::new(),
    )
}

#[test]
fn rendered_page_contains_bounded_negotiation_contract() {
    let page = render_page(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        4,
    );
    assert!(!page.body.contains("__"));
    assert!(!page.body.contains("bridge="));
    assert!(page.body.contains("X-Carrier-Capabilities"));
    assert!(page.body.contains("X-Carrier-Attempt"));
    assert!(page.body.contains("candidateCount=4"));
    assert!(page.body.contains("candidateDeadlines=[3,5,8,12]"));
    assert!(page.body.contains("X-Up-Seq"));
    assert!(page.body.contains("X-Lane-ID"));
    assert!(page.body.contains("tproxy-auto-v1."));
    assert!(page.body.contains("tproxy-auto-lane-v1."));
    assert!(
        page.content_security_policy
            .contains("frame-ancestors http://127.0.0.1:*")
    );
}

#[test]
fn rendered_page_preserves_the_ios_bootstrap_literal() {
    let bootstrap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let page = render_page(bootstrap, 2);
    assert!(page.body.contains(&format!("const bootstrap=\"{bootstrap}\"")));
}

#[test]
fn effective_deadline_formula_uses_the_final_checkpoint() {
    let page = render_page(
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        3,
    );
    assert!(page.body.contains("negotiatedFinalDeadline=candidateDeadlines[3]"));
    assert!(page.body.contains("carrierAttempt>=negotiatedCandidateCount?negotiatedFinalDeadline"));
}

#[test]
fn disabled_negotiation_does_not_arm_a_carrier_deadline() {
    let page = render(
        "proxy.example.com",
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        false,
        1,
        [3, 5, 8, 12],
        &SecureRandom::new(),
    );
    assert!(page.body.contains(
        "if(negotiationEnabled){negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch)}"
    ));
    assert!(page.body.contains(
        "negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.'"
    ));
}

#[test]
fn retry_and_attempt_state_are_frozen_before_fetch() {
    let page = render_page(
        "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        4,
    );
    assert!(page.body.contains("async function request(path,frozenOptions)"));
    assert!(!page.body.contains("makeOptions"));
    assert!(
        page.body
            .contains("if(closed||(external&&external.aborted))throw new Error('request aborted')")
    );
    assert!(page.body.contains(
        "const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(snapshot.attempt,snapshot.failure),controller.signal)"
    ));
}

#[test]
fn ambiguous_commit_is_resolved_before_carrier_advance() {
    let page = render_page(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        4,
    );
    assert!(page.body.contains("resolveAttempt(reason,epoch,snapshot)"));
    assert!(page.body.contains(
        "sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true)"
    ));
    assert!(page.body.contains("if(echo.state!=='provisional'){switching=false;fail();return}"));
    assert!(page.body.contains("const token=cleanupToken||sessionToken"));
}
