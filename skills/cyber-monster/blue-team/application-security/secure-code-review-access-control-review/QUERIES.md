# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-code-review-access-control-review`](SKILL.md) | Family: **Application Security**

Authorisation coverage queries. Each row produces a list of actions or a probe result, not a verdict.

## Coverage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Action inventory | controller or view actions versus actions with an authorisation call | Every action has one; custom actions included |
| Scoped lookup | `find(`/`get(pk=` call sites lacking a scope helper | Zero on tenant-scoped models |
| Role source | predicate inputs read from `params` or session-mutable fields | Zero; roles resolve from server-side state |

## Differential

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Same-role substitution | user B calls user A's object id | Same rejection shape as a missing id |
| Cross-tenant substitution | tenant B token with tenant A id | 404 without body leakage |
| Custom action probe | non-owner calls a custom action route | 403/404, no state change recorded |

## Field Level

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Column visibility | serializers exposing fields the role should not see | Closed per role |
| Mass assignment | permitted params containing `role`, `tenant`, `owner` | Excluded |

## Telemetry Prerequisites

- Two accounts in the same role and one in a different tenant, so the substitution probes are meaningful.
- The policy layer's configuration (Pundit policies, DRF permissions, RLS policies), since the control may live there.
- Write access to a staging database to confirm no state changed on the rejected paths.

## Deployment Gates

- No action is signed off without a predicate location and a replayed substitution probe.
- After any refactor that renames a lookup helper, re-run the probes; scaffolding regenerates the unsafe pattern.
