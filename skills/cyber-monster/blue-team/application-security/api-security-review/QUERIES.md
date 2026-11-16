# Detection Queries and Telemetry Artifacts

> Sub-skill: [`api-security-review`](SKILL.md) | Family: **Application Security**

Route-level review queries. Each row produces a list of routes to examine, not a verdict; the verdict needs the predicate location.

## Route Inventory

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Undocumented routes | route table minus OpenAPI paths | Empty, or each difference explained as internal |
| Debug and admin surfaces | paths matching `/debug`, `/actuator`, `/__`, `/internal` | Absent from the public listener |
| Version drift | route prefixes `v1` vs `v2` with different middleware | Same auth predicate on both, or v1 disabled |

## Object Authorisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Bare primary-key lookups | handlers calling `findById`/`get(pk=)` without a tenant or owner argument | Zero on tenant-scoped resources |
| Two-tenant probe | same request as two authenticated tenants | Identical rejection shape for foreign and missing ids |
| Mass assignment | body fields that map to `owner`, `tenant`, `role`, `is_admin` | Rejected by a closed schema |

## Abuse Controls

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Rate limit binding | limit keyed by IP only on an authenticated route | Keyed by principal or token, since IP is shared behind NAT |
| Pagination bound | `limit` parameter with no maximum | Capped server-side |
| Error verbosity | stack traces or SQL text in a `500` body | Absent in production builds |

## Telemetry Prerequisites

- The routing table as deployed, including feature flags, rather than the source tree alone.
- Two test accounts in different tenants, so the object-level differential is replayable.
- The published API document, to diff against the effective route set.

## Deployment Gates

- No route is marked reviewed without a named authorisation predicate and its file:line.
- Re-run the two-tenant probe after any change to middleware ordering or serializer configuration.
