# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-intelligence-and-cti-strategic-intelligence`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Strategic product checks. Each row names the field and the state a decision-usable product shows.

## Decision Linkage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Named decision | product record with `decision` and `horizon` | Both present |
| Delta | `delta_from_assumption` field | States what changes, not only what is true |
| Decision record | register or minute citing the product | Present, or an explicit no-decision note |

## Calibration

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Confidence basis | source quality and count | Recorded; volume of low-quality sources does not raise it |
| Sampling bias | bias statement for prevalence claims | Present |
| Inference separation | evidence versus inference lines | Distinct in the product |

## Audience Fit

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Classification | TLP or equivalent marking | Present and respected in distribution |
| Cost framing | effort or licence impact of the recommendation | Present where the decision is investment |

## Telemetry Prerequisites

- The current planning assumption written down, since the delta is meaningless without it.
- Internal exposure data, which is what turns external reporting into a statement about your estate.
- A decision forum with a record, so the loop can close.

## Deployment Gates

- No strategic product ships without a stated delta from the current assumption.
- Prevalence claims carry a sampling-bias note or are removed.
