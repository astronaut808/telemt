# Mask Host Check Command

## Purpose

`telemt check-mask-host` is a lightweight operational command for evaluating whether a candidate host looks suitable for `censorship.tls_domain`.

It is intentionally narrower than full packet-level validation:

- it performs live TLS metadata probes;
- it reuses Telemt's existing TLS profile acquisition path;
- it reports whether the host looks operationally usable for Telemt profile fetch and FakeTLS masking.

It does **not** prove:

- byte-for-byte equivalence with the origin server;
- full indistinguishability against every DPI implementation;
- end-to-end deployment fidelity on your exact client-to-proxy path.

## Command

```bash
telemt check-mask-host <host> [--port 443] [--sni <domain>] [--attempts 3]
```

Examples:

```bash
telemt check-mask-host nginx.org
telemt check-mask-host example.com --attempts 5
telemt check-mask-host 1.2.3.4 --sni nginx.org
```

## What The Command Checks

For each live probe, Telemt tries to fetch TLS artifacts using the same internal TLS fetch path already used for fronting profile acquisition.

The command evaluates:

- probe success rate across repeated attempts;
- whether the certificate identity covers the requested SNI;
- whether the certificate validity window is current;
- whether certificate payload is available for FakeTLS profile use;
- whether encrypted TLS flight data was observed;
- whether raw or merged TLS capture was obtained instead of weaker metadata fallback;
- whether certificate identity remains stable across repeated probes.

## Verdicts

### `recommended`

Strong result.

Typical meaning:

- all probes succeeded;
- certificate identity matches the requested SNI;
- certificate is currently valid;
- Telemt captured the encrypted flight and certificate payload consistently.

This is the best category for a practical `tls_domain` candidate.

### `usable_with_caution`

Mixed result.

Typical meaning:

- most probes succeeded;
- the certificate still looks plausible for the requested SNI;
- some profile signals were weaker or less consistent.

This host may still be usable, but it deserves extra manual verification before relying on it.

### `not_recommended`

Weak or unstable result.

Typical meaning:

- too many probes failed;
- certificate identity does not reliably cover the requested SNI;
- encrypted flight or certificate payload was missing;
- the host looks operationally weak for Telemt profile fetch.

This host should not be considered a good default masking candidate.

## How To Use The Result

Recommended workflow:

1. Run `telemt check-mask-host <host>` on several candidate domains.
2. Keep only hosts that return `recommended` consistently.
3. Use those hosts for real Telemt deployment tests.
4. If a host is important but only returns `usable_with_caution`, validate it further with deployment-level checks.

## Operational Notes

- The command is useful for **candidate screening**.
- It reduces the need for manual packet capture during the first selection stage.
- Final deployment validation is still a separate step when high-confidence fronting behavior matters.
