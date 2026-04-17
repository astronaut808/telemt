# Partial Degradation for Middle-End Routing

## Problem

Before this change, conditional ME admission behaved as a global binary switch for new sessions:

- if every configured DC had at least one live ME writer, new sessions used Middle-End;
- if even one configured DC lost writer coverage, the whole admission state moved toward global fallback.

This was safe, but too coarse. A single degraded DC could force unrelated healthy DCs onto direct routing.

## What changed

Telemt now separates two questions:

1. Is the ME pool usable at all for at least some DCs?
2. Is the ME pool usable for the specific DC requested by this session?

This introduces partial degradation for new sessions:

- if all covered DCs are ready, Telemt behaves as before and routes new sessions via Middle-End;
- if only part of the covered DC set is ready, Telemt keeps Middle-End globally enabled for new sessions;
- each new session then checks readiness for its own target DC;
- if the target DC has live ME coverage, the session uses Middle-End;
- if the target DC does not have live ME coverage, only that session falls back to Direct-DC.

## Architectural intent

The change is intentionally narrow:

- it does not replace the existing global `RouteRuntimeController`;
- it does not introduce per-session route subscriptions or a new cutover state machine;
- it only improves route selection for new sessions when ME health is asymmetric across DCs.

This keeps the current relay and cutover model intact while removing a major all-or-nothing failure mode.

## Runtime semantics

### Admission layer

The ME admission gate now distinguishes:

- full readiness: every covered configured DC has at least one live writer;
- partial readiness: at least one covered configured DC has at least one live writer;
- no readiness: no covered configured DC has live writer coverage.

When partial readiness is present, the admission gate remains open and the global route mode stays `Middle`.

### Session routing layer

When a new authenticated session is about to use Middle-End, Telemt additionally checks whether ME is ready for the session target DC.

- ready for target DC: session uses ME;
- not ready for target DC: session falls back to Direct-DC;
- all other sessions are unaffected.

## Why this is useful

This improves real operating behavior in hostile networks:

- healthy DCs continue benefiting from ME even while one DC is degraded;
- localized writer loss no longer causes unnecessary global degradation;
- recovery is smoother because Telemt does not have to swing the entire proxy between all-ME and all-direct as often.

## Invariants preserved

This change preserves existing core behavior:

- only new sessions use the refined routing decision;
- active relay sessions still follow the existing global cutover semantics;
- no MTProto or KDF routing contracts were changed;
- no new blocking work was added to the relay path.

## Limits

This is not a full per-family or per-session routing subsystem.

It should be understood as targeted hardening:

- readiness is still built on top of the existing global route runtime;
- session fallback is per target DC, not a full independent route domain;
- existing sessions are not migrated between ME and direct modes.

## Validation ideas

Useful validation scenarios:

1. Configure ME endpoints for multiple DCs.
2. Make one DC lose all live ME writers while another DC remains healthy.
3. Verify that admission stays open instead of forcing immediate global direct routing.
4. Verify that sessions for the healthy DC still use ME.
5. Verify that sessions for the degraded DC fall back to Direct-DC.

This behavior is also covered by targeted pool-status tests for:

- partial readiness with incomplete DC coverage;
- readiness checks scoped to the requested target DC.
