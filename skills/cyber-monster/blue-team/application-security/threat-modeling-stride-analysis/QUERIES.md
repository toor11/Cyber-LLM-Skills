# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-modeling-stride-analysis`](SKILL.md) | Family: **Application Security**

Grid-quality checks over the STRIDE artefact and the config it claims. A complete grid answers every row with a location or a reason.

## Completeness

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Element coverage | diagram elements versus elements present in the grid | Equal counts, including data stores and external entities |
| Category dispositions | cells that are neither a threat nor a reason | Zero |
| Version binding | grid revision versus diagram revision | Same revision recorded in both |

## Control Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Located control | threat rows whose control column names a file or config key | All high-severity rows |
| Verified control | control locations spot-checked against the repository | Present and doing what the row claims |
| Accepted risk | rows with no control | Each has an owner and an expiry |

## Config Reconciliation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Transport identity | mTLS or token verification at each boundary | Matches the spoofing dispositions |
| Audit coverage | events emitted for each action marked 'no repudiation threat' | Present |
| Limits | body, timeout, and rate limits at each DoS disposition | Configured |

## Telemetry Prerequisites

- The current diagram with element ids, so coverage can be measured.
- Repository or config access to spot-check at least one control per category.
- The accepted-risk register, so empty rows can be distinguished from omissions.

## Deployment Gates

- A grid without a matching diagram revision is rejected rather than reviewed.
- Any 'not applicable' cell is justified in the row, not left as a dash.
