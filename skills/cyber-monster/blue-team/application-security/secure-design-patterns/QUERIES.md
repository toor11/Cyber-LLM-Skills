# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-design-patterns`](SKILL.md) | Family: **Application Security**

Design-conformance checks. These reconcile the written pattern against the running configuration; a design that cannot be reconciled is a claim rather than a control.

## Decision Point

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Single authorisation entry | count of distinct authorisation middlewares/filters per service | One; extra decision points are the ones that drift |
| Server-side enforcement | handlers that re-check inside the body versus handlers relying on layout or client guards | Every mutating handler re-checks server-side |
| Scope derivation | requests where tenant or owner comes from a body field instead of a verified token claim | Zero |

## Failure Mode

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Timeout behaviour | authorisation dependency stop or latency injection | Deny or `503`; never `200` with protected content |
| Policy bundle absence | OPA/Envoy started without its bundle | Startup fails or requests deny; a warning log is not sufficient |
| Credential expiry | expired token with a live session | Re-authenticate, not silently continue with a cached decision |

## Blast Radius

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Credential zone spans | IAM role or service account used by more than one trust zone | Zero; each zone gets its own identity |
| Egress allowlist | services reaching arbitrary hosts | Closed list, per service |

## Telemetry Prerequisites

- The deployment configuration for each control (gateway, mesh, IAM, RLS), not only the design document.
- A way to stop or delay the authorisation dependency in a test environment, which is what makes the failure-mode probe possible.
- The data-classification list, so 'protected content' is a named class.

## Deployment Gates

- A control with no documented failure mode is treated as fail-open until proven otherwise.
- Re-run the failure-mode probes after any dependency upgrade; mesh and gateway defaults change across minor versions.
