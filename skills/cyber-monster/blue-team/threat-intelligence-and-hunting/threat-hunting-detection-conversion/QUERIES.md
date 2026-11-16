# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-hunting-detection-conversion`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Rule-readiness checks. Each row names the metadata field or test and the state a maintainable rule shows.

## Identity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Rule id | `id` field present and stable | UUID, unchanged across tuning |
| Ownership | owner recorded in the rule or its register | Named team |
| Version control | rule file under git with history | Present |

## Analytic

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Description | prose stating the malicious relationship | Present, not a restatement of the query |
| Correlation parameters | `timespan` and `group-by` for sequence rules | Explicit and justified |
| Log source | `logsource` block | Maps to a source the estate actually forwards |

## Testing

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Replay | rule fired against the original hunt events | Fires, with the expected fields |
| Baseline quiet | rule run over the last full window on production | Zero or documented count |
| False positives | list with owners and review dates | Derived from hunt clusters |

## Telemetry Prerequisites

- The dispositioned hunt record, since the analytic and the false positives both come from it.
- A replay capability (test index, or a conversion tool with a test harness) to prove the rule fires.
- The log-source inventory, so the rule's `logsource` maps to something actually collected.

## Deployment Gates

- No rule is enabled without a replay that fires and a baseline run that is quiet.
- Every false-positive entry has an owner; unnamed exceptions are rejected.
