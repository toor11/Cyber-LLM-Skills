# Detection Queries and Telemetry Artifacts

> Sub-skill: [`third-party-and-vendor-risk`](SKILL.md) | Family: **Purple Team and Program**

Vendor-register checks. Each row names the field and the state a defensible assessment shows.

## Classification

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Data class | highest data class the vendor processes | Recorded |
| Access paths | identity, network, and data access | Enumerated per vendor |
| Concentration | vendors sharing one provider or subprocessor | Mapped for concentration risk |

## Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Observed scopes | IdP grant versus required scopes | Delta recorded |
| Observed flows | network path from flow logs | Matches the integration's need |
| Attestation dates | report period and issue date | Current for the vendor's cycle |

## Contract

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Notification | breach notification window | Present and tested against the IR process |
| Audit right | right to audit or request evidence | Present for highest-tier vendors |
| Exit | data deletion and transition terms | Present |

## Telemetry Prerequisites

- Identity provider access, since consent grants are the most common over-permission.
- Flow-log visibility for vendor integrations.
- A register that records attestation periods rather than a yes/no certification flag.

## Deployment Gates

- No highest-tier vendor is approved on a questionnaire without observed-access evidence.
- Unused scopes are removed at review, not documented as accepted.
