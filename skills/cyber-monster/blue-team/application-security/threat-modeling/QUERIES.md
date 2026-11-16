# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-modeling`](SKILL.md) | Family: **Application Security**

Model-quality checks. These are queries against the model artefact and the config it claims to describe; a healthy model answers every row with a located control.

## Coverage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Element without a threat | model elements minus elements referenced by any threat row | Empty, or each gap justified as a passive element |
| Threat without a control | threat rows whose control column is empty or `TBD` | Empty; remaining rows carry an accepted-risk id |
| Control without an owner | control rows with no team or role | Empty; ownership resolves to a real on-call rotation |

## Config Reconciliation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Authentication on internal hops | service mesh `PeerAuthentication` mode or ingress auth annotation | `STRICT`/mTLS where the model claims an authenticated boundary |
| Logging element data class | log pipeline field allowlist vs model data classes | No classified field present in the pipeline without a handling requirement |
| Third-party egress | allowlisted egress hosts vs model third-party elements | One-to-one; every modelled dependency has an egress rule and vice versa |

## Retest Hooks

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Probe per threat | threat rows with a named request shape and expected rejection | Every high-severity threat has a replayable probe |
| Review date | accepted-risk rows with an expiry | No entry older than its review interval |

## Telemetry Prerequisites

- The as-built config for each boundary (ingress rules, mesh policy, IAM roles), not only the design document.
- A data-classification list, so 'sensitive' means a named class rather than a feeling.
- The on-call or team mapping that will own each control.

## Deployment Gates

- A model is only accepted when every high-severity threat has a located control or an accepted-risk id with a date.
- Re-run the config reconciliation after any architecture change; drift between model and config is the failure mode this skill exists to catch.
