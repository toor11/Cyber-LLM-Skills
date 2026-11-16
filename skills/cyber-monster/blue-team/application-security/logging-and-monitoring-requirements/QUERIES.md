# Detection Queries and Telemetry Artifacts

> Sub-skill: [`logging-and-monitoring-requirements`](SKILL.md) | Family: **Application Security**

Contract-conformance queries. Each row is a check you can run against the log store to prove the requirement is met in production rather than in the logging configuration.

## Event Completeness

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Decision coverage | distinct `event` values for a synthetic actor that signs in, is denied, and exports | One event per decision type, all present |
| Field presence | events where `actor.tenant` or `resource.id` is null | Zero for authorisation and admin events |
| Reason codes | distinct `reason` values on denies | Named codes, not `forbidden`; codes map to a policy rule |

## Integrity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Producer write scope | log sink IAM policy for the application identity | Append-only; no delete, no overwrite, no retention change |
| Clock source | events with `@timestamp` skew greater than 5s from collector time | Zero; skew breaks timeline reconstruction |
| Gap detection | minutes with zero events from a service that emits continuously | No gaps during business hours |

## Retention and Access

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Retention vs obligation | index or bucket lifecycle policy | At least the contractual or regulatory period, with legal hold support |
| Read access | principals with query access to the audit index | Named investigators only; the application identity has write-only |

## Telemetry Prerequisites

- A synthetic transaction that exercises sign-in, deny, and export, so completeness is testable without waiting for a real incident.
- The log store's IAM or role policy, since producer scope is the integrity control.
- The retention obligation in days, agreed with legal, so lifecycle policy can be compared.

## Deployment Gates

- No production launch without a passing synthetic-transaction completeness check in the target environment.
- Any change to log level or sampling requires a re-run of that check, because the common failure is silent suppression.
